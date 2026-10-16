/*
  libheif box memory-limit tests

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
#include "codecs/avif_boxes.h"
#include "codecs/avc_boxes.h"
#include "codecs/hevc_boxes.h"
#include "codecs/vvc_boxes.h"
#include "mini.h"
#include "file.h"
#include "nclx.h"
#include "security_limits.h"
#include "sequences/seq_boxes.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<uint8_t> make_box(const std::string& kind, uint32_t count)
{
  if (kind == "avcS" || kind == "avcP" || kind == "avcE" || kind == "vvcC") {
    std::vector<uint8_t> nal(count, 0x08);
    StreamWriter writer;
    if (kind == "vvcC") {
      Box_vvcC box;
      auto& config = box.get_configuration();
      config.native_ptl.num_bytes_constraint_info = 1;
      config.native_ptl.general_constraint_info = {0};
      if (count) box.append_nal_data(nal);
      REQUIRE(box.write(writer) == Error::Ok);
    }
    else {
      Box_avcC box;
      box.get_configuration().configuration_version = 1;
      box.get_configuration().AVCProfileIndication = kind == "avcE" ? 100 : 66;
      box.get_configuration().lengthSize = 4;
      if (count) {
        if (kind == "avcS") box.append_sps_nal(nal.data(), nal.size());
        if (kind == "avcP") box.append_pps_nal(nal.data(), nal.size());
        if (kind == "avcE") box.append_sps_ext_nal(nal.data(), nal.size());
      }
      REQUIRE(box.write(writer) == Error::Ok);
    }
    return writer.get_data();
  }

  StreamWriter writer;
  writer.write32(0);
  const bool is_icc = kind == "prof" || kind == "rICC";
  writer.write32(is_icc ? fourcc("colr") : fourcc(kind.substr(0, 4).c_str()));

  if (kind == "elst0" || kind == "elst1") {
    writer.write32(kind == "elst1" ? 0x01000000 : 0);
    writer.write32(count);
    for (uint32_t i = 0; i < count; i++) {
      if (kind == "elst1") {
        writer.write64(i + 1);
        writer.write64(i);
      }
      else {
        writer.write32(i + 1);
        writer.write32(i);
      }
      writer.write16(1);
      writer.write16(0);
    }
  }
  else if (kind == "hvcC") {
    HEVCDecoderConfigurationRecord config{};
    config.configuration_version = 1;
    config.bit_depth_luma = 8;
    config.bit_depth_chroma = 8;
    HEVCDecoderConfigurationRecord::NalArray array{};
    if (count) {
      std::vector<uint8_t> nal(count);
      for (uint32_t i = 0; i < count; i++) {
        nal[i] = static_cast<uint8_t>(i);
      }
      array.m_nal_units.push_back(std::move(nal));
    }
    config.m_nal_array.push_back(std::move(array));
    REQUIRE(config.write(writer) == Error::Ok);
  }
  else {
    if (kind == "av1C") {
      writer.write32(0x81000000);
    }
    else if (is_icc) {
      writer.write32(fourcc(kind.c_str()));
    }
    for (uint32_t i = 0; i < count; i++) {
      writer.write8(static_cast<uint8_t>(i));
    }
  }

  auto size = static_cast<uint32_t>(writer.get_data().size());
  writer.set_position(0);
  writer.write32(size);
  return writer.get_data();
}

size_t allocation_size(const std::string& kind, uint32_t count)
{
  return (kind == "elst0" || kind == "elst1") ? count * sizeof(Box_elst::Entry) : count;
}

std::vector<uint8_t> make_mini(bool inherited_configs, bool hdr = true)
{
  Box_mini mini;
  mini.set_orientation(1);
  mini.set_width(16);
  mini.set_height(16);
  mini.set_chroma_subsampling(3);
  mini.set_alpha_flag(hdr);
  mini.set_hdr_flag(hdr);
  mini.set_gainmap_flag(hdr);
  mini.set_gainmap_width(16);
  mini.set_gainmap_height(16);
  mini.set_gainmap_chroma_subsampling(3);
  mini.set_icc_flag(true);
  mini.set_tmap_icc_flag(true);
  mini.set_main_item_codec_config({0x81, 0, 0, 0});
  mini.set_alpha_item_codec_config({0x81, static_cast<uint8_t>(inherited_configs ? 0 : 1), 0, 0});
  mini.set_gainmap_item_codec_config({0x81, static_cast<uint8_t>(inherited_configs ? 0 : 2), 0, 0});
  mini.set_icc_data(std::vector<uint8_t>(32, 0xAA));
  mini.set_tmap_icc_data(std::vector<uint8_t>(24, 0xBB));
  mini.set_gainmap_metadata(std::vector<uint8_t>(16, 0xCC));
  mini.set_main_item_data({0});
  mini.set_alpha_item_data({0});
  mini.set_gainmap_item_data({0});
  StreamWriter writer;
  REQUIRE(mini.write(writer) == Error::Ok);
  return writer.get_data();
}

Error parse_box(const std::vector<uint8_t>& data, const heif_security_limits* limits,
                std::shared_ptr<Box>& box)
{
  auto reader = std::make_shared<StreamReader_memory>(data.data(), data.size(), false);
  BitstreamRange range(reader, data.size());
  return Box::read(range, &box, limits);
}

} // namespace


TEST_CASE("box payload allocations respect block and total memory limits")
{
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1", "prof", "rICC", "hvcC",
                                    "avcS", "avcP", "avcE", "vvcC");
  INFO("box: " << kind);
  const auto data = make_box(kind, 32);
  const size_t amount = allocation_size(kind, 32);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = amount;
  limits.max_total_memory = amount;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  SECTION("exact budget accepts and preserves the payload") {
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    if (kind == "av1C") {
      auto av1C = std::dynamic_pointer_cast<Box_av1C>(box);
      REQUIRE(av1C);
      std::vector<uint8_t> headers;
      REQUIRE(av1C->get_headers(&headers));
      REQUIRE(headers == std::vector<uint8_t>(data.begin() + 12, data.end()));
    }
    else {
      StreamWriter writer;
      REQUIRE(box->write(writer) == Error::Ok);
      REQUIRE(writer.get_data() == data);
    }
  }

  SECTION("block limit rejects the allocation independently of the total limit") {
    limits.max_memory_block_size = amount - 1;
    limits.max_total_memory = 0;
    Error err = parse_box(data, &limits, box);
    if (kind == "jpgC") {
      REQUIRE(err.error_code == heif_error_Invalid_input);
      REQUIRE(err.sub_error_code == heif_suberror_Unspecified);
      REQUIRE(err.message == "jpgC block exceeds maximum size");
    }
    else {
      REQUIRE(err.error_code == heif_error_Memory_allocation_error);
      REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    }
  }

  SECTION("total limit rejects the allocation independently of the block limit") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = amount - 1;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("disabled block limit accepts a payload within the total budget") {
    limits.max_memory_block_size = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }

  SECTION("disabled total limit accepts a payload within the block budget") {
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }

  SECTION("both limits disabled accept the payload") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }
}


TEST_CASE("parsed box storage remains charged until the box is destroyed")
{
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1", "prof", "rICC", "hvcC",
                                    "avcS", "avcP", "avcE", "vvcC");
  INFO("box: " << kind);
  const auto data = make_box(kind, 32);
  const size_t amount = allocation_size(kind, 32);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = amount;
  limits.max_total_memory = 2 * amount;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> first, second, third;

  REQUIRE(parse_box(data, &limits, first) == Error::Ok);
  REQUIRE(parse_box(data, &limits, second) == Error::Ok);
  Error err = parse_box(data, &limits, third);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);

  first.reset();
  REQUIRE(parse_box(data, &limits, third) == Error::Ok);
}


TEST_CASE("empty box payloads fit a minimal memory budget")
{
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1", "prof", "rICC", "hvcC",
                                    "avcS", "avcP", "avcE", "vvcC");
  INFO("box: " << kind);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_box(kind, 0), &limits, box) == Error::Ok);
}


TEST_CASE("truncated edit lists fail before reserving their declared storage")
{
  const std::string kind = GENERATE("elst0", "elst1");
  auto data = make_box(kind, 1);
  data[15] = 2;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Invalid_input);
  REQUIRE(err.sub_error_code == heif_suberror_End_of_data);
  REQUIRE(tracker.get_max_total_memory_used() == 0);
}


TEST_CASE("ICC profile size limits remain independent of memory limits")
{
  const std::string kind = GENERATE("prof", "rICC");
  const auto data = make_box(kind, 32);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 0;
  limits.max_total_memory = 0;
  limits.max_color_profile_size = 31;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Invalid_input);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  REQUIRE(err.message == "Color profile exceeds maximum supported size");

  limits.max_color_profile_size = 32;
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);

  box.reset();
  limits.max_color_profile_size = 0;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
}


TEST_CASE("shared ICC storage stays charged after its colr box is destroyed")
{
  const std::string kind = GENERATE("prof", "rICC");
  const auto data = make_box(kind, 32);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  auto colr = std::dynamic_pointer_cast<Box_colr>(box);
  REQUIRE(colr);
  auto profile = colr->get_color_profile();
  colr.reset();
  box.reset();

  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);

  profile.reset();
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
}


TEST_CASE("nclx parsing does not consume the ICC payload budget")
{
  StreamWriter writer;
  writer.write32(19);
  writer.write32(fourcc("colr"));
  writer.write32(fourcc("nclx"));
  writer.write16(1);
  writer.write16(1);
  writer.write16(1);
  writer.write8(0x80);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  limits.max_color_profile_size = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(writer.get_data(), &limits, box) == Error::Ok);
  StreamWriter output;
  REQUIRE(box->write(output) == Error::Ok);
  REQUIRE(output.get_data() == writer.get_data());
}


TEST_CASE("hvcC accounts for all NAL payloads within and across arrays")
{
  const bool separate_arrays = GENERATE(false, true);
  auto data = make_box("hvcC", 32);
  // The configuration header ends at byte 31; each array starts with a
  // one-byte type and a two-byte NAL count.
  const auto second_start = data.begin() + (separate_arrays ? 31 : 34);
  const std::vector<uint8_t> second(second_start, data.end());
  data.insert(data.end(), second.begin(), second.end());
  data[separate_arrays ? 30 : 33] = 2;
  StreamWriter writer;
  writer.write32(static_cast<uint32_t>(data.size()));
  const auto header = writer.get_data();
  std::copy(header.begin(), header.end(), data.begin());

  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 64;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  StreamWriter output;
  REQUIRE(box->write(output) == Error::Ok);
  REQUIRE(output.get_data() == data);
  box.reset();

  limits.max_total_memory = 63;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  box.reset();
  REQUIRE(parse_box(make_box("hvcC", 32), &limits, box) == Error::Ok);
}


TEST_CASE("truncated hvcC NAL payloads fail before reserving storage")
{
  auto data = make_box("hvcC", 32);
  // Claim a NAL larger than the remaining payload.
  data[35] = 33;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Invalid_input);
  REQUIRE(err.sub_error_code == heif_suberror_End_of_data);
  REQUIRE(tracker.get_max_total_memory_used() == 0);
}


TEST_CASE("mini retained payloads share the budget with the parsing buffer")
{
  const bool inherited_configs = GENERATE(false, true);
  const auto data = make_mini(inherited_configs);
  const size_t retained = 3 * 4 + 32 + 24 + 16;
  const size_t peak = data.size() - 8 + retained;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = data.size();
  limits.max_total_memory = peak;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  SECTION("exact peak budget accepts all payloads and preserves serialization") {
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    auto mini = std::dynamic_pointer_cast<Box_mini>(box);
    REQUIRE(mini);
    // Parsing keeps image offsets rather than image bytes; restore the write-only data.
    mini->set_main_item_data({0});
    mini->set_alpha_item_data({0});
    mini->set_gainmap_item_data({0});
    StreamWriter writer;
    REQUIRE(box->write(writer) == Error::Ok);
    REQUIRE(writer.get_data() == data);

    // The temporary parsing buffer is gone, but every retained byte is still charged.
    limits.max_total_memory = retained;
    MemoryHandle probe;
    Error err = probe.alloc(1, &limits, "budget probe");
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    mini.reset();
    box.reset();
    REQUIRE(probe.alloc(1, &limits, "budget probe") == Error::Ok);
  }

  SECTION("one byte below peak rejects and releases the failed parse") {
    limits.max_total_memory = peak - 1;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    box.reset();
    limits.max_total_memory = 1;
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") == Error::Ok);
  }

  SECTION("disabled limits accept retained payloads") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }
}


TEST_CASE("expanded mini ICC storage remains charged after the file is destroyed")
{
  const auto mini_data = make_mini(true, false);
  StreamWriter writer;
  Box_ftyp ftyp;
  ftyp.set_major_brand(heif_brand2_mif3);
  ftyp.set_minor_version(heif_brand2_avif);
  REQUIRE(ftyp.write(writer) == Error::Ok);
  writer.write(mini_data);
  const auto data = writer.get_data();

  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1024;
  limits.max_total_memory = 1024;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  REQUIRE(file->read_from_memory(data.data(), data.size(), false) == Error::Ok);

  std::shared_ptr<const color_profile> profile;
  for (const auto& colr : file->get_ipco_box()->get_child_boxes<Box_colr>()) {
    if (colr->get_color_profile()->get_type() == fourcc("prof")) {
      profile = colr->get_color_profile();
    }
  }
  REQUIRE(profile);
  REQUIRE(std::dynamic_pointer_cast<const color_profile_raw>(profile)->get_data() ==
          std::vector<uint8_t>(32, 0xAA));
  file.reset();

  limits.max_total_memory = 32;
  MemoryHandle probe;
  Error err = probe.alloc(1, &limits, "budget probe");
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  profile.reset();
  REQUIRE(probe.alloc(1, &limits, "budget probe") == Error::Ok);
}


TEST_CASE("AVC and VVC reject truncated payloads before reserving storage")
{
  const std::string kind = GENERATE("avcS", "avcP", "avcE", "vvcC");
  auto data = make_box(kind, 32);
  // Declare more than the remaining bytes, including AVC's trailing PPS count.
  const size_t length_offset = kind == "avcS" ? 15 : kind == "avcP" ? 16 : kind == "avcE" ? 20 : data.size() - 33;
  data[length_offset] = 34;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Invalid_input);
  REQUIRE(err.sub_error_code == heif_suberror_End_of_data);
  REQUIRE(tracker.get_max_total_memory_used() == 0);
}


TEST_CASE("AVC and VVC accumulate all payloads within one box")
{
  const bool vvc = GENERATE(false, true);
  std::vector<uint8_t> nal(32, 0x08);
  StreamWriter writer;
  if (vvc) {
    Box_vvcC box;
    box.get_configuration().native_ptl.num_bytes_constraint_info = 1;
    box.get_configuration().native_ptl.general_constraint_info = {0};
    box.append_nal_data(nal);
    box.append_nal_data(nal);
    nal[1] = 0x10;
    box.append_nal_data(nal);
    REQUIRE(box.write(writer) == Error::Ok);
  }
  else {
    Box_avcC box;
    box.get_configuration().configuration_version = 1;
    box.get_configuration().AVCProfileIndication = 100;
    box.get_configuration().lengthSize = 4;
    box.append_sps_nal(nal.data(), nal.size());
    box.append_pps_nal(nal.data(), nal.size());
    box.append_sps_ext_nal(nal.data(), nal.size());
    REQUIRE(box.write(writer) == Error::Ok);
  }
  const auto data = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 96;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  box.reset();
  limits.max_total_memory = 95;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  box.reset();
  limits.max_total_memory = 96;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
}
