/*
  libheif memory-accounting regression tests

  MIT License

  Copyright (c) 2026 Dirk Farin <dirk.farin@gmail.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#include "catch_amalgamated.hpp"
#include "box.h"
#include "codecs/hevc_boxes.h"
#include "codecs/vvc_boxes.h"
#include "context.h"
#include "file.h"
#include "image-items/mask_image.h"
#include "security_limits.h"
#include "sequences/seq_boxes.h"
#include "sequences/chunk.h"
#include "sequences/track.h"
#if WITH_UNCOMPRESSED_CODEC
#include "codecs/uncompressed/unc_boxes.h"
#include "color-conversion/bayer_bilinear.h"
#endif

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {

struct AllocationStats;

struct alignas(std::max_align_t) AllocationHeader
{
  size_t size;
  AllocationStats* owner;
  AllocationHeader* previous;
  AllocationHeader* next;
};

struct AllocationStats
{
  size_t live = 0;
  size_t peak = 0;
  size_t largest = 0;
  size_t capture_size = 0;
  void* captured = nullptr;
  AllocationHeader* head = nullptr;
};

thread_local AllocationStats* allocation_stats = nullptr;

// Observe only large C++ allocations during a single-threaded library call.
// Small objects, allocator overhead and calloc-backed pixel planes are excluded.
// Detach surviving buffers at scope exit so none retains a pointer to test state.
class ObserveAllocations
{
public:
  explicit ObserveAllocations(AllocationStats& stats) : m_stats(&stats) { allocation_stats = &stats; }
  ~ObserveAllocations()
  {
    allocation_stats = nullptr;
    while (m_stats->head) {
      auto* header = m_stats->head;
      m_stats->head = header->next;
      header->owner = nullptr;
    }
  }

  ObserveAllocations(const ObserveAllocations&) = delete;
  ObserveAllocations& operator=(const ObserveAllocations&) = delete;

private:
  AllocationStats* m_stats;
};

struct FreeWatch
{
  void* address;
  const heif_security_limits* limits;
  bool visited = false;
  bool reservation_held = false;
};

thread_local FreeWatch* free_watch = nullptr;

} // namespace

// This replacement allocator is isolated in its own test executable. Operations
// outside ObserveAllocations use ordinary malloc/free without being measured.
void* operator new(size_t size)
{
  if (size > SIZE_MAX - sizeof(AllocationHeader)) throw std::bad_alloc();
  auto* header = static_cast<AllocationHeader*>(std::malloc(sizeof(AllocationHeader) + std::max(size, size_t{1})));
  if (!header) throw std::bad_alloc();
  header->size = size;
  header->owner = size >= 512 ? allocation_stats : nullptr;
  header->previous = nullptr;
  header->next = nullptr;
  if (auto* stats = header->owner) {
    header->next = stats->head;
    if (header->next) header->next->previous = header;
    stats->head = header;
    stats->live += size;
    stats->peak = std::max(stats->peak, stats->live);
    stats->largest = std::max(stats->largest, size);
    if (size == stats->capture_size) stats->captured = header + 1;
  }
  return header + 1;
}

void operator delete(void* pointer) noexcept
{
  if (!pointer) return;
  if (free_watch && free_watch->address == pointer) {
    auto* watch = free_watch;
    free_watch = nullptr;
    watch->visited = true;
    MemoryHandle probe;
    watch->reservation_held = probe.alloc(1, watch->limits, "storage destruction probe").sub_error_code == heif_suberror_Security_limit_exceeded;
  }
  auto* header = static_cast<AllocationHeader*>(pointer) - 1;
  if (auto* stats = header->owner) {
    stats->live -= header->size;
    if (header->previous) header->previous->next = header->next;
    else stats->head = header->next;
    if (header->next) header->next->previous = header->previous;
  }
  std::free(header);
}

void* operator new[](size_t size) { return ::operator new(size); }
void operator delete[](void* pointer) noexcept { ::operator delete(pointer); }
void operator delete(void* pointer, size_t) noexcept { ::operator delete(pointer); }
void operator delete[](void* pointer, size_t) noexcept { ::operator delete(pointer); }

namespace {

std::vector<uint8_t> finish_box(StreamWriter& writer)
{
  const auto size = static_cast<uint32_t>(writer.get_data().size());
  writer.set_position(0);
  writer.write32(size);
  return writer.get_data();
}

Error parse_box(const std::vector<uint8_t>& bytes, const heif_security_limits* limits,
                std::shared_ptr<Box>& box)
{
  auto reader = std::make_shared<StreamReader_memory>(bytes.data(), bytes.size(), false);
  BitstreamRange range(reader, bytes.size());
  return Box::read(range, &box, limits);
}

size_t available_total_memory(const heif_security_limits& limits)
{
  auto probe_limits = limits;
  probe_limits.parent = &limits;
  probe_limits.max_memory_block_size = 0;
  size_t bit = 1;
  while (bit <= limits.max_total_memory / 2) bit *= 2;
  MemoryHandle probe;
  size_t available = 0;
  for (; bit; bit /= 2) {
    if (probe.alloc(bit, &probe_limits, "available budget probe") == Error::Ok) available += bit;
  }
  return available;
}

std::vector<uint8_t> make_nal_box(bool vvc, uint16_t count)
{
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc(vvc ? "vvcC" : "hvcC"));
  if (vvc) {
    writer.write32(0);
    writer.write8(7);
    writer.write16(0x10);
    writer.write8(0);
    writer.write8(1);
    writer.write8(2);
    writer.write8(1);
    writer.write8(0);
    writer.write8(0);
    writer.write16(1);
    writer.write16(1);
    writer.write16(0);
    writer.write8(1);
    writer.write8(15);
  }
  else {
    for (int i = 0; i < 22; i++) writer.write8(i == 0 ? 1 : 0);
    writer.write8(1);
    writer.write8(32);
  }
  writer.write16(count);
  for (uint16_t i = 0; i < count; i++) {
    writer.write16(1);
    writer.write8(0);
  }
  return finish_box(writer);
}

std::vector<uint8_t> make_string_images(uint32_t count, size_t string_size, bool auxiliary)
{
  HeifFile file;
  file.set_security_limits(heif_get_global_security_limits());
  file.new_empty_file();
  file.get_ftyp_box()->set_major_brand(fourcc("mif1"));
  file.get_ftyp_box()->add_compatible_brand(fourcc("mif1"));
  auto gimi = std::make_shared<Box_gimi_content_id>();
  gimi->set_content_id(std::string(string_size, 'x'));
  auto aux = std::make_shared<Box_auxC>();
  aux->set_aux_type(std::string(string_size, 'x'));
  auto mask = std::make_shared<Box_mskC>();
  mask->set_bits_per_pixel(8);
  heif_item_id primary = 0;
  for (uint32_t i = 0; i < count; i++) {
    auto id = file.add_new_image(fourcc("mski"));
    REQUIRE(id);
    if (i == 0) {
      primary = *id;
      file.set_primary_item_id(primary);
    }
    file.append_iloc_data(*id, {0}, 0);
    REQUIRE(file.add_ispe_property(*id, 1, 1, true) == Error::Ok);
    file.add_property(*id, mask, true);
    if (!auxiliary) file.add_property(*id, gimi, false);
    else if (i > 0) {
      file.add_property(*id, aux, false);
      file.add_iref_reference(*id, fourcc("auxl"), {primary});
    }
  }
  StreamWriter writer;
  file.derive_box_versions();
  file.write(writer);
  return writer.get_data();
}

} // namespace

TEST_CASE("codec configuration bookkeeping obeys allocation budgets")
{
  const bool vvc = GENERATE(false, true);
  const std::string mode = GENERATE("block", "total", "accounted", "disabled");
  const auto bytes = make_nal_box(vvc, 1024);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 8192 : 0;
  limits.max_total_memory = mode == "total" ? 8192 : mode == "accounted" ? 128 * 1024 : 0;
  TotalMemoryTracker tracker(&limits);
  AllocationStats stats;
  std::shared_ptr<Box> box;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parse_box(bytes, &limits, box);
  }
  if (mode == "block") CHECK(stats.largest <= limits.max_memory_block_size);
  if (mode == "total") CHECK(stats.peak <= limits.max_total_memory);
  if (error != Error::Ok) {
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    if (mode == "accounted") CHECK(tracker.get_max_total_memory_used() >= stats.largest);
    std::vector<uint8_t> headers;
    if (vvc) REQUIRE(std::dynamic_pointer_cast<Box_vvcC>(box)->get_headers(&headers));
    else REQUIRE(std::dynamic_pointer_cast<Box_hvcC>(box)->get_header_nals(&headers));
    std::vector<uint8_t> expected_headers(5 * 1024, 0);
    for (size_t i = 3; i < expected_headers.size(); i += 5) expected_headers[i] = 1;
    REQUIRE(headers == expected_headers);
  }
  box.reset();
  if (mode == "accounted") {
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_total_memory, &limits, "destroyed configuration bookkeeping") == Error::Ok);
  }
}

TEST_CASE("sequence auxiliary offset allocations retain their budget")
{
  const bool multiple_chunks = GENERATE(false, true);
  const bool tight_budget = GENERATE(false, true);
  constexpr uint32_t count = 8192;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = tight_budget ? 12288 : 128 * 1024;
  TotalMemoryTracker tracker(&limits);
  StreamWriter sizes;
  sizes.write32(0);
  sizes.write32(fourcc("saiz"));
  sizes.write32(0);
  sizes.write8(multiple_chunks ? 1 : 0);
  sizes.write32(count);
  if (!multiple_chunks) {
    for (uint32_t i = 0; i < count; i++) sizes.write8(1);
  }
  StreamWriter offsets;
  offsets.write32(20);
  offsets.write32(fourcc("saio"));
  offsets.write32(0);
  offsets.write32(multiple_chunks ? 2 : 1);
  offsets.write32(0);
  if (multiple_chunks) offsets.write32(count / 2);
  std::shared_ptr<Box> sizes_box, offsets_box;
  REQUIRE(parse_box(finish_box(sizes), &limits, sizes_box) == Error::Ok);
  REQUIRE(parse_box(finish_box(offsets), &limits, offsets_box) == Error::Ok);
  std::vector<std::shared_ptr<Chunk>> chunks;
  if (multiple_chunks) {
    StreamWriter sample_sizes;
    sample_sizes.write32(20);
    sample_sizes.write32(fourcc("stsz"));
    sample_sizes.write32(0);
    sample_sizes.write32(1);
    sample_sizes.write32(count);
    std::shared_ptr<Box> sample_sizes_box;
    REQUIRE(parse_box(sample_sizes.get_data(), &limits, sample_sizes_box) == Error::Ok);
    auto stsz = std::dynamic_pointer_cast<Box_stsz>(sample_sizes_box);
    chunks.push_back(Chunk::create(nullptr, 1, 0, count / 2, 0, stsz));
    chunks.push_back(Chunk::create(nullptr, 1, count / 2, count / 2, count / 2, stsz));
    REQUIRE(chunks[0]);
    REQUIRE(chunks[1]);
  }
  const size_t before = available_total_memory(limits);
  AllocationStats stats;
  std::unique_ptr<SampleAuxInfoReader> reader;
  Error error;
  {
    ObserveAllocations observation(stats);
    auto result = SampleAuxInfoReader::create(std::dynamic_pointer_cast<Box_saiz>(sizes_box),
                                             std::dynamic_pointer_cast<Box_saio>(offsets_box), chunks, &limits);
    if (result) reader = std::move(*result);
    else error = result.error();
  }
  if (tight_budget) {
    REQUIRE_FALSE(reader);
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(reader);
    REQUIRE(error == Error::Ok);
  }
  const size_t after = available_total_memory(limits);
  CHECK(stats.largest <= limits.max_memory_block_size);
  CHECK(stats.peak <= limits.max_total_memory);
  REQUIRE(after <= before);
  CHECK(before - after >= stats.live);
  reader.reset();
  REQUIRE(available_total_memory(limits) == before);
}

#if WITH_UNCOMPRESSED_CODEC
TEST_CASE("Bayer conversion scratch allocations fit and consume the native budget")
{
  const uint16_t side = GENERATE(uint16_t{16}, uint16_t{32});
  const bool generous_budget = GENERATE(false, true);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_bayer_pattern_pixels = uint32_t{side} * side;
  limits.max_memory_block_size = limits.max_total_memory = generous_budget ? 64 * 1024 * 1024 : 256 * 1024;
  TotalMemoryTracker tracker(&limits);
  auto input = std::make_shared<HeifPixelImage>();
  input->create(1, 1, heif_colorspace_filter_array, heif_chroma_planar);
  REQUIRE(input->add_component(1, 1, heif_cmpd_component_type_filter_array,
                               heif_component_datatype_unsigned_integer, 8, &limits));
  uint32_t ids[] = {input->add_component_without_data(heif_cmpd_component_type_red),
                    input->add_component_without_data(heif_cmpd_component_type_green),
                    input->add_component_without_data(heif_cmpd_component_type_blue)};
  auto pixels = std::make_shared<SensorMetadataArray<heif_bayer_pattern_pixel>>();
  REQUIRE(pixels->memory_handle.alloc(uint32_t{side} * side, sizeof(heif_bayer_pattern_pixel), &limits, "input Bayer table") == Error::Ok);
  pixels->values.resize(uint32_t{side} * side);
  for (size_t i = 0; i < pixels->values.size(); i++) pixels->values[i] = {ids[i % 3], 1.0f};
  BayerPattern pattern;
  pattern.pattern_width = pattern.pattern_height = side;
  pattern.pixels = pixels;
  input->set_bayer_pattern(pattern);
  Op_bayer_bilinear_to_RGB24_32 operation;
  AllocationStats stats;
  Result<std::shared_ptr<HeifPixelImage>> result;
  {
    ObserveAllocations observation(stats);
    result = operation.convert_colorspace(input, {}, {}, {}, {}, &limits);
  }
  CHECK(stats.largest <= limits.max_memory_block_size);
  CHECK(stats.peak <= limits.max_total_memory);
  if (result) {
    CHECK(tracker.get_max_total_memory_used() >= stats.peak);
    REQUIRE((*result)->get_width() == 1);
    REQUIRE((*result)->get_height() == 1);
  }
  else {
    REQUIRE_FALSE(generous_budget);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }
}
#endif

TEST_CASE("shared string properties and metadata copies stay within their budget")
{
  const std::string mode = GENERATE("GIMI", "auxC", "metadata copy");
  const bool copying_metadata = mode == "metadata copy";
  constexpr size_t string_size = 65536;
  const auto bytes = make_string_images(copying_metadata ? 1 : 16, string_size, mode == "auxC");
  HeifContext context;
  auto& limits = *context.get_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = 256 * 1024;
  if (copying_metadata) {
    REQUIRE(context.read_from_memory(bytes.data(), bytes.size(), false) == Error::Ok);
    const size_t before = available_total_memory(limits);
    AllocationStats stats;
    ImageDescription copy;
    {
      ObserveAllocations observation(stats);
      copy.copy_metadata_from(*context.get_primary_image(true));
    }
    REQUIRE(copy.get_gimi_sample_content_id() == std::string(string_size, 'x'));
    const size_t after = available_total_memory(limits);
    REQUIRE(after <= before);
    // String payload accounting may exclude the single trailing NUL byte.
    CHECK(before - after + 1 >= stats.live);
    context.get_primary_image(true)->set_gimi_sample_content_id("replacement");
    REQUIRE(copy.get_gimi_sample_content_id() == std::string(string_size, 'x'));
    REQUIRE(context.get_primary_image(true)->get_gimi_sample_content_id() == "replacement");
  }
  else {
    AllocationStats stats;
    Error error;
    {
      ObserveAllocations observation(stats);
      error = context.read_from_memory(bytes.data(), bytes.size(), false);
    }
    CHECK(stats.live <= limits.max_total_memory);
    if (error != Error::Ok) REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
    else if (mode == "GIMI") REQUIRE(context.get_primary_image(true)->get_gimi_sample_content_id() == std::string(string_size, 'x'));
    else {
      const auto auxiliaries = context.get_primary_image(true)->get_aux_images();
      REQUIRE(auxiliaries.size() == 15);
      REQUIRE(auxiliaries[0]->get_aux_type() == std::string(string_size, 'x'));
    }
  }
}

TEST_CASE("iloc growth accounts for capacity and simultaneous old and new buffers")
{
  const bool block_limit = GENERATE(false, true);
  const bool partial_budget = GENERATE(false, true);
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc("iloc"));
  writer.write32(0);
  writer.write8(0x44);
  writer.write8(0);
  writer.write16(1);
  writer.write16(1);
  writer.write16(0);
  writer.write16(2);
  writer.write32(0);
  writer.write32(3072);
  writer.write32(3072);
  writer.write32(1024);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = block_limit ? 4096 : 0;
  limits.max_total_memory = partial_budget ? 3072 : block_limit ? 0 : 4096;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(finish_box(writer), &limits, box) == Error::Ok);
  auto iloc = std::dynamic_pointer_cast<Box_iloc>(box);
  REQUIRE(iloc);
  const std::vector<uint8_t> bytes(4096, 0xAA);
  auto reader = std::make_shared<StreamReader_memory>(bytes.data(), bytes.size(), false);
  MemoryHandle owner;
  AllocationStats stats;
  std::vector<uint8_t> data;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = iloc->read_data(1, reader, nullptr, &data, &limits, &owner);
  }
  // Failure diagnostics need less than 1 KiB beyond the payload budget.
  const size_t diagnostic_allowance = error == Error::Ok ? 0 : 1024;
  if (block_limit) CHECK(stats.largest <= limits.max_memory_block_size);
  else CHECK(stats.peak <= limits.max_total_memory + diagnostic_allowance);
  if (partial_budget) {
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(data.empty());
  }
  else {
    REQUIRE(error == Error::Ok);
    REQUIRE(data == bytes);
  }
}

TEST_CASE("box reservations remain held until their vector storage is freed")
{
  constexpr uint32_t count = 128;
  constexpr size_t table_size = count * sizeof(Box_stts::TimeToSample);
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc("stts"));
  writer.write32(0);
  writer.write32(count);
  for (uint32_t i = 0; i < count; i++) {
    writer.write32(1);
    writer.write32(i + 1);
  }
  const auto bytes = finish_box(writer);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = table_size;
  TotalMemoryTracker tracker(&limits);
  AllocationStats stats;
  stats.capture_size = table_size;
  std::shared_ptr<Box> box;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parse_box(bytes, &limits, box);
  }
  REQUIRE(error == Error::Ok);
  REQUIRE(stats.captured);
  FreeWatch watch{stats.captured, &limits};
  free_watch = &watch;
  box.reset();
  free_watch = nullptr;
  REQUIRE(watch.visited);
  CHECK(watch.reservation_held);
  MemoryHandle probe;
  REQUIRE(probe.alloc(table_size, &limits, "destroyed box storage") == Error::Ok);
}
