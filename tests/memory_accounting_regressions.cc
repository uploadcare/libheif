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
#include "codecs/jpeg2000_boxes.h"
#include "compression.h"
#include "region.h"
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
struct FreeWatch;

struct alignas(std::max_align_t) AllocationHeader
{
  size_t size;
  AllocationStats* owner;
  AllocationHeader* previous;
  AllocationHeader* next;
};

struct AllocationStats
{
  size_t minimum_size = 512;
  FreeWatch* watch = nullptr;
  size_t live = 0;
  size_t peak = 0;
  size_t largest = 0;
  size_t total = 0;
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
  const void* address;
  const heif_security_limits* limits;
  bool visited = false;
  bool reservation_held = false;
  size_t probe_amount = 1;
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
  header->owner = allocation_stats && size >= allocation_stats->minimum_size ? allocation_stats : nullptr;
  header->previous = nullptr;
  header->next = nullptr;
  if (auto* stats = header->owner) {
    header->next = stats->head;
    if (header->next) header->next->previous = header;
    stats->head = header;
    stats->live += size;
    stats->total += size;
    stats->peak = std::max(stats->peak, stats->live);
    stats->largest = std::max(stats->largest, size);
    if (size == stats->capture_size) {
      stats->captured = header + 1;
      if (stats->watch) stats->watch->address = header + 1;
    }
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
    watch->reservation_held = probe.alloc(watch->probe_amount, watch->limits, "storage destruction probe").sub_error_code == heif_suberror_Security_limit_exceeded;
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

std::vector<uint8_t> make_string_images(uint32_t count, size_t string_size, const std::string& kind)
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
    if (kind != "auxC" && kind != "mime") file.add_property(*id, gimi, false);
    else if (kind == "auxC" && i > 0) {
      file.add_property(*id, aux, false);
      file.add_iref_reference(*id, fourcc("auxl"), {primary});
    }
  }
  if (kind == "mime") {
    const std::string type = "application/" + std::string(string_size - 12, 'x');
    const uint8_t payload[] = {1};
    auto id = file.add_infe_mime(type.c_str(), heif_metadata_compression_off, payload, sizeof(payload));
    REQUIRE(id);
    file.add_iref_reference(*id, fourcc("cdsc"), {primary});
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
  const std::string mode = GENERATE("GIMI", "auxC", "metadata copy", "mime");
  const bool copying_metadata = mode == "metadata copy";
  constexpr size_t string_size = 65536;
  const auto bytes = make_string_images(copying_metadata || mode == "mime" ? 1 : 16, string_size, mode);
  HeifContext context;
  auto& limits = *context.get_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = mode == "mime" ? string_size + 4096 : 256 * 1024;
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
    if (mode == "mime") stats.minimum_size = string_size;
    Error error;
    {
      ObserveAllocations observation(stats);
      error = context.read_from_memory(bytes.data(), bytes.size(), false);
    }
    CHECK(stats.live <= limits.max_total_memory);
    if (error != Error::Ok) REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
    else if (mode == "mime") {
      const auto& metadata = context.get_primary_image(true)->get_metadata();
      REQUIRE(metadata.size() == 1);
      REQUIRE(metadata[0]->content_type.size() == string_size);
      CHECK(limits.max_total_memory - available_total_memory(limits) + 1 >= stats.live);
    }
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
  const std::string kind = GENERATE("stts", "ctts", "stsc", "stco", "stsz", "stss", "saiz", "saio", "sdtp");
  INFO(kind);
  constexpr uint32_t count = 1024;
  const size_t entry_size = kind == "stts" ? sizeof(Box_stts::TimeToSample) :
                            kind == "ctts" || kind == "saio" ? 8 : kind == "stsc" ? 12 :
                            kind == "saiz" || kind == "sdtp" ? 1 : 4;
  const size_t table_size = count * entry_size;
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc(kind.c_str()));
  writer.write32(0);
  if (kind == "saiz") writer.write8(0);
  if (kind == "stsz") writer.write32(0);
  if (kind != "sdtp") writer.write32(count);
  for (uint32_t i = 0; i < count; i++) {
    if (kind == "saiz" || kind == "sdtp") writer.write8(1);
    else if (kind == "stts" || kind == "ctts") {
      writer.write32(1); writer.write32(i + 1);
    }
    else if (kind == "stsc") {
      writer.write32(i + 1); writer.write32(1); writer.write32(1);
    }
    else writer.write32(i + 1);
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

TEST_CASE("terminated strings account for capacity and transient growth")
{
  const size_t length = GENERATE(size_t{8193}, size_t{16385});
  const std::string mode = GENERATE("block", "total", "generous", "disabled");
  const std::string expected(length, 'x');
  StreamWriter writer;
  writer.write(expected);
  const auto bytes = writer.get_data();
  auto reader = std::make_shared<StreamReader_memory>(bytes.data(), bytes.size(), false);
  BitstreamRange range(reader, bytes.size());
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? length : mode == "generous" ? 4 * length : 0;
  limits.max_total_memory = mode == "total" ? length : mode == "generous" ? 4 * length : 0;
  TotalMemoryTracker tracker(&limits);
  MemoryHandle owner;
  std::string output;
  AllocationStats stats;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = range.read_string(output, owner, &limits);
  }
  // Payload budgets may exclude the one trailing NUL byte of string storage.
  if (limits.max_memory_block_size) CHECK(stats.largest <= limits.max_memory_block_size + 1);
  if (limits.max_total_memory) CHECK(stats.peak <= limits.max_total_memory + 1);
  if (mode == "generous" || mode == "disabled") REQUIRE(error == Error::Ok);
  if (error == Error::Ok) {
    REQUIRE(output == expected);
    if (mode == "generous") CHECK(tracker.get_max_total_memory_used() + 1 >= stats.peak);
  }
  else REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
}

TEST_CASE("reference tables obey independent block and retained total budgets")
{
  const std::string mode = GENERATE("block", "total", "retained", "disabled");
  const std::string shape = GENERATE("many targets", "distinct sources", "shared source");
  const uint16_t count = shape == "many targets" ? 10 : 1000;
  const uint16_t targets = shape == "many targets" ? 1000 : 1;
  StreamWriter writer;
  writer.write32(0); writer.write32(fourcc("iref")); writer.write32(0);
  for (uint16_t i = 0; i < count; i++) {
    writer.write32(12 + 2 * targets); writer.write32(fourcc("dimg"));
    writer.write16(shape == "shared source" ? 1 : i + 1); writer.write16(targets);
    for (uint16_t j = 0; j < targets; j++) writer.write16(11);
  }
  const auto bytes = finish_box(writer);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 1024 : 0;
  limits.max_total_memory = mode == "total" ? 1024 : mode == "retained" ? 1024 * 1024 : 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  AllocationStats stats;
  if (mode == "retained") stats.minimum_size = 0;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parse_box(bytes, &limits, box);
  }
  if (limits.max_memory_block_size) CHECK(stats.largest <= limits.max_memory_block_size);
  if (limits.max_total_memory) CHECK(stats.peak <= limits.max_total_memory);
  if (mode == "retained" || mode == "disabled") REQUIRE(error == Error::Ok);
  if (error == Error::Ok) {
    auto references = std::dynamic_pointer_cast<Box_iref>(box);
    REQUIRE(references);
    REQUIRE(references->get_references(1, fourcc("dimg")) == std::vector<uint32_t>(targets, 11));
    StreamWriter output;
    REQUIRE(box->write(output) == Error::Ok);
    REQUIRE(output.get_data() == bytes);
    if (mode == "retained") {
      CHECK(limits.max_total_memory - available_total_memory(limits) >= stats.live);
      CHECK(tracker.get_max_total_memory_used() >= stats.peak);
    }
  }
  else REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
  box.reset();
  if (mode == "retained") REQUIRE(available_total_memory(limits) == limits.max_total_memory);
}

TEST_CASE("reference queries preserve order across parsing and later additions")
{
  Box_iref original;
  original.add_references(9, fourcc("dimg"), {1, 2});
  original.add_references(3, fourcc("thmb"), {5});
  original.add_references(9, fourcc("auxl"), {3});
  original.add_references(9, fourcc("dimg"), {4});
  StreamWriter writer;
  REQUIRE(static_cast<const Box&>(original).write(writer) == Error::Ok);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(writer.get_data(), heif_get_global_security_limits(), box) == Error::Ok);
  auto references = std::dynamic_pointer_cast<Box_iref>(box);
  REQUIRE(references);
  REQUIRE(references->has_references(9));
  REQUIRE_FALSE(references->has_references(7));
  REQUIRE(references->get_references_from(7).empty());
  REQUIRE(references->get_references(9, fourcc("thmb")).empty());
  REQUIRE(references->get_references(9, fourcc("dimg")) == std::vector<uint32_t>{1, 2});
  const auto from_nine = references->get_references_from(9);
  REQUIRE(from_nine.size() == 3);
  CHECK(from_nine[0].header.get_short_type() == fourcc("dimg"));
  CHECK(from_nine[0].to_item_ID == std::vector<uint32_t>{1, 2});
  CHECK(from_nine[1].header.get_short_type() == fourcc("auxl"));
  CHECK(from_nine[1].to_item_ID == std::vector<uint32_t>{3});
  CHECK(from_nine[2].header.get_short_type() == fourcc("dimg"));
  CHECK(from_nine[2].to_item_ID == std::vector<uint32_t>{4});
  references->add_references(3, fourcc("cdsc"), {9});
  references->add_references(1, fourcc("thmb"), {9});
  references->overwrite_reference(9, fourcc("dimg"), 1, 6);
  REQUIRE(references->get_references_from(3).size() == 2);
  REQUIRE(references->get_references(3, fourcc("cdsc")) == std::vector<uint32_t>{9});
  REQUIRE(references->has_references(1));
  REQUIRE(references->get_references(9, fourcc("dimg")) == std::vector<uint32_t>{1, 6});
  original.add_references(3, fourcc("cdsc"), {9});
  original.add_references(1, fourcc("thmb"), {9});
  original.overwrite_reference(9, fourcc("dimg"), 1, 6);
  StreamWriter expected, actual;
  REQUIRE(static_cast<const Box&>(original).write(expected) == Error::Ok);
  REQUIRE(box->write(actual) == Error::Ok);
  REQUIRE(actual.get_data() == expected.get_data());
}

TEST_CASE("empty AVC parameter sets account for descriptor storage")
{
  const std::string mode = GENERATE("block", "total", "retained", "disabled");
  StreamWriter writer;
  writer.write32(0); writer.write32(fourcc("avcC"));
  writer.write8(1); writer.write8(66); writer.write8(0); writer.write8(0);
  writer.write8(255); writer.write8(224); writer.write8(255);
  for (int i = 0; i < 255; i++) writer.write16(0);
  const auto bytes = finish_box(writer);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 1024 : 0;
  limits.max_total_memory = mode == "total" ? 1024 : mode == "retained" ? 32768 : 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  AllocationStats stats;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parse_box(bytes, &limits, box);
  }
  if (limits.max_memory_block_size) CHECK(stats.largest <= limits.max_memory_block_size);
  if (limits.max_total_memory) CHECK(stats.peak <= limits.max_total_memory);
  if (mode == "retained" || mode == "disabled") REQUIRE(error == Error::Ok);
  if (error == Error::Ok) {
    StreamWriter output;
    REQUIRE(box->write(output) == Error::Ok);
    REQUIRE(output.get_data() == bytes);
    if (mode == "retained") CHECK(limits.max_total_memory - available_total_memory(limits) >= stats.live);
  }
  else REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
  box.reset();
  if (mode == "retained") REQUIRE(available_total_memory(limits) == limits.max_total_memory);
}

TEST_CASE("palette column capacity stays accounted through storage destruction")
{
  const bool generous = GENERATE(false, true);
  constexpr size_t count = 128, columns = 129;
  const size_t logical_size = count * (sizeof(Box_pclr::PaletteEntry) + columns * sizeof(uint16_t));
  StreamWriter writer;
  writer.write32(0); writer.write32(fourcc("pclr")); writer.write16(count); writer.write8(columns);
  for (size_t i = 0; i < columns; i++) writer.write8(7);
  for (size_t i = 0; i < count * columns; i++) writer.write8(1);
  const auto bytes = finish_box(writer);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = generous ? 4 * logical_size : logical_size;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  AllocationStats stats;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parse_box(bytes, &limits, box);
  }
  CHECK(stats.largest <= limits.max_memory_block_size);
  CHECK(stats.peak <= limits.max_total_memory);
  if (generous) REQUIRE(error == Error::Ok);
  if (error != Error::Ok) {
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
    return;
  }
  auto palette = std::dynamic_pointer_cast<Box_pclr>(box);
  REQUIRE(palette);
  REQUIRE(palette->get_entries().size() == count);
  REQUIRE(palette->get_entries()[0].columns == std::vector<uint16_t>(columns, 1));
  StreamWriter output;
  REQUIRE(box->write(output) == Error::Ok);
  REQUIRE(output.get_data() == bytes);
  if (generous) {
    CHECK(limits.max_total_memory - available_total_memory(limits) >= stats.live);
    FreeWatch watch{palette->get_entries()[0].columns.data(), &limits};
    watch.probe_amount = limits.max_total_memory - logical_size + 1;
    palette.reset();
    free_watch = &watch;
    box.reset();
    free_watch = nullptr;
    REQUIRE(watch.visited);
    CHECK(watch.reservation_held);
    REQUIRE(available_total_memory(limits) == limits.max_total_memory);
  }
}

TEST_CASE("polygon capacity stays accounted through storage destruction")
{
  const bool generous = GENERATE(false, true);
  constexpr uint32_t count = 1025;
  const size_t logical_size = count * sizeof(RegionGeometry_Polygon::Point);
  StreamWriter writer;
  writer.write32(count);
  for (uint32_t i = 0; i < count; i++) { writer.write32(i); writer.write32(i); }
  const auto bytes = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = generous ? 4 * logical_size : logical_size;
  TotalMemoryTracker tracker(&limits);
  auto polygon = std::make_unique<RegionGeometry_Polygon>();
  unsigned offset = 0;
  AllocationStats stats;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = polygon->parse(bytes, 32, &offset, &limits);
  }
  CHECK(stats.largest <= limits.max_memory_block_size);
  CHECK(stats.peak <= limits.max_total_memory);
  if (generous) REQUIRE(error == Error::Ok);
  if (error != Error::Ok) {
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
    return;
  }
  REQUIRE(polygon->points.size() == count);
  REQUIRE(polygon->points.back().x == count - 1);
  REQUIRE(polygon->points.back().y == count - 1);
  if (generous) {
    CHECK(limits.max_total_memory - available_total_memory(limits) >= stats.live);
    FreeWatch watch{polygon->points.data(), &limits};
    watch.probe_amount = limits.max_total_memory - logical_size + 1;
    free_watch = &watch;
    polygon.reset();
    free_watch = nullptr;
    REQUIRE(watch.visited);
    CHECK(watch.reservation_held);
    REQUIRE(available_total_memory(limits) == limits.max_total_memory);
  }
}

TEST_CASE("opening many ipma boxes uses linear allocation volume")
{
  const uint32_t count = GENERATE(512, 1024);
  const auto input = make_string_images(1, 0, "GIMI");
  HeifFile source;
  source.set_security_limits(heif_get_global_security_limits());
  REQUIRE(source.read_from_memory(input.data(), input.size(), false) == Error::Ok);
  auto iprp = source.get_meta_box()->get_child_box<Box_iprp>();
  REQUIRE(iprp);
  for (uint32_t i = 0; i < count; i++) {
    auto ipma = std::make_shared<Box_ipma>();
    ipma->add_property_for_item_ID(i + 2, {false, 1});
    iprp->append_child_box(ipma);
  }
  StreamWriter writer;
  source.derive_box_versions();
  source.write(writer);
  const auto bytes = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_children_per_box = count + 10;
  limits.max_total_memory = 16 * 1024 * 1024;
  TotalMemoryTracker tracker(&limits);
  HeifFile parsed;
  parsed.set_security_limits(&limits);
  AllocationStats stats;
  Error error;
  {
    ObserveAllocations observation(stats);
    error = parsed.read_from_memory(bytes.data(), bytes.size(), false);
  }
  REQUIRE(error == Error::Ok);
  CHECK(stats.total <= size_t{count} * 4096);
  const auto* properties = parsed.get_ipma_box()->get_properties_for_item_ID(count + 1);
  REQUIRE(properties);
  REQUIRE(properties->size() == 1);
  CHECK(properties->front().property_index == 1);
}

#if HAVE_ZLIB || HAVE_BROTLI
TEST_CASE("failed decompression releases only the current output reservation")
{
  const char* codecs[] = {
#if HAVE_ZLIB
    "zlib", "deflate",
#endif
#if HAVE_BROTLI
    "brotli",
#endif
  };
  const std::string codec = GENERATE_COPY(Catch::Generators::from_range(codecs));
  const std::string failure = GENERATE("expected size", "block", "total");
  INFO(codec);
  INFO(failure);
  const size_t chunk = codec == "brotli" ? 262144 : 8192;
  const std::vector<uint8_t> payload(chunk + 1, 0xAA);
  std::vector<uint8_t> compressed;
#if HAVE_ZLIB
  if (codec == "zlib") compressed = compress_zlib(payload.data(), payload.size());
  if (codec == "deflate") compressed = compress_deflate(payload.data(), payload.size());
#endif
#if HAVE_BROTLI
  if (codec == "brotli") compressed = compress_brotli(payload.data(), payload.size());
#endif
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = failure == "block" ? chunk : 0;
  limits.max_total_memory = failure == "total" ? 17 + 3 * chunk : 8 * chunk;
  TotalMemoryTracker tracker(&limits);
  MemoryHandle owner;
  REQUIRE(owner.alloc(17, &limits, "pre-existing caller reservation") == Error::Ok);
  const size_t before = available_total_memory(limits);
  auto decompress = [&](uint64_t expected) {
    Result<std::vector<uint8_t>> result;
#if HAVE_ZLIB
    if (codec == "zlib") result = decompress_zlib(compressed, &limits, expected, &owner);
    if (codec == "deflate") result = decompress_deflate(compressed, &limits, expected, &owner);
#endif
#if HAVE_BROTLI
    if (codec == "brotli") result = decompress_brotli(compressed, &limits, expected, &owner);
#endif
    return result;
  };
  for (int attempt = 0; attempt < 2; attempt++) {
    auto result = decompress(failure == "expected size" ? chunk : payload.size());
    REQUIRE_FALSE(result);
    CHECK(result.error().sub_error_code == (failure == "expected size"
          ? heif_suberror_Decompression_invalid_data : heif_suberror_Security_limit_exceeded));
    CHECK(available_total_memory(limits) == before);
  }
  limits.max_memory_block_size = 0;
  limits.max_total_memory = 8 * chunk;
  {
    auto result = decompress(payload.size());
    REQUIRE(result);
    REQUIRE(*result == payload);
    CHECK(available_total_memory(limits) == limits.max_total_memory - 17 - result->capacity());
  }
  owner.free();
  CHECK(available_total_memory(limits) == limits.max_total_memory);
}

TEST_CASE("decompression output capacity fits block and total budgets")
{
  const char* codecs[] = {
#if HAVE_ZLIB
    "zlib", "deflate",
#endif
#if HAVE_BROTLI
    "brotli",
#endif
  };
  const std::string codec = GENERATE_COPY(Catch::Generators::from_range(codecs));
  const bool generous = GENERATE(false, true);
  const size_t size = codec == "brotli" ? 262145 : 8193;
  const std::vector<uint8_t> payload(size, 0xAA);
  std::vector<uint8_t> compressed;
#if HAVE_ZLIB
  if (codec == "zlib") compressed = compress_zlib(payload.data(), payload.size());
  if (codec == "deflate") compressed = compress_deflate(payload.data(), payload.size());
#endif
#if HAVE_BROTLI
  if (codec == "brotli") compressed = compress_brotli(payload.data(), payload.size());
#endif
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = generous ? 8 * size : size;
  TotalMemoryTracker tracker(&limits);
  MemoryHandle owner;
  Result<std::vector<uint8_t>> result;
  AllocationStats stats;
  {
    ObserveAllocations observation(stats);
#if HAVE_ZLIB
    if (codec == "zlib") result = decompress_zlib(compressed, &limits, size, &owner);
    if (codec == "deflate") result = decompress_deflate(compressed, &limits, size, &owner);
#endif
#if HAVE_BROTLI
    if (codec == "brotli") result = decompress_brotli(compressed, &limits, size, &owner);
#endif
  }
  CHECK(stats.largest <= limits.max_memory_block_size);
  // Failure diagnostics need less than 1 KiB beyond the output budget.
  const size_t diagnostic_allowance = result ? 0 : 1024;
  CHECK(stats.peak <= limits.max_total_memory + diagnostic_allowance);
  if (generous) REQUIRE(result);
  if (result) {
    REQUIRE(*result == payload);
    if (generous) CHECK(tracker.get_max_total_memory_used() >= stats.peak);
  }
  else REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
}
#endif

TEST_CASE("derived-image input reservations survive until the parsing buffer is freed")
{
  const std::string kind = GENERATE("grid", "iovl");
  constexpr size_t payload_size = 8192;
  HeifFile file;
  file.set_security_limits(heif_get_global_security_limits());
  file.new_empty_file();
  file.get_ftyp_box()->set_major_brand(fourcc("mif1"));
  file.get_ftyp_box()->add_compatible_brand(fourcc("mif1"));
  auto tile = file.add_new_image(fourcc("mski"));
  auto primary = file.add_new_image(fourcc(kind.c_str()));
  REQUIRE(tile);
  REQUIRE(primary);
  file.set_primary_item_id(*primary);
  file.append_iloc_data(*tile, {0}, 0);
  auto mask = std::make_shared<Box_mskC>();
  mask->set_bits_per_pixel(8);
  file.add_property(*tile, mask, true);
  REQUIRE(file.add_ispe_property(*tile, 1, 1, true) == Error::Ok);
  REQUIRE(file.add_ispe_property(*primary, 1, 1, true) == Error::Ok);
  file.add_iref_reference(*primary, fourcc("dimg"), {*tile});
  StreamWriter spec;
  spec.write8(0); spec.write8(0); // version and flags
  if (kind == "grid") {
    spec.write8(0); spec.write8(0); // one row and one column
  }
  else {
    for (int i = 0; i < 4; i++) spec.write16(0); // background colour
  }
  spec.write16(1); spec.write16(1); // width and height
  if (kind == "iovl") { spec.write16(0); spec.write16(0); }
  auto payload = spec.get_data();
  payload.resize(payload_size, 0);
  file.append_iloc_data(*primary, payload, 0);
  file.derive_box_versions();
  StreamWriter writer;
  file.write(writer);
  const auto bytes = writer.get_data();
  HeifContext context;
  auto& limits = *context.get_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = 32768;
  FreeWatch watch{nullptr, &limits};
  watch.probe_amount = limits.max_total_memory - payload_size + 1;
  AllocationStats stats;
  stats.capture_size = payload_size;
  stats.watch = &watch;
  Error error;
  free_watch = &watch;
  {
    ObserveAllocations observation(stats);
    error = context.read_from_memory(bytes.data(), bytes.size(), false);
  }
  free_watch = nullptr;
  REQUIRE(error == Error::Ok);
  REQUIRE(context.get_primary_image(true)->get_width() == 1);
  REQUIRE(context.get_primary_image(true)->get_height() == 1);
  REQUIRE(available_total_memory(limits) > limits.max_total_memory - payload_size);
  REQUIRE(watch.visited);
  CHECK(watch.reservation_held);
}
