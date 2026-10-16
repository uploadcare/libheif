/*
  libheif memory-limit tests

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
#include "codecs/decoder.h"
#include "codecs/avc_dec.h"
#include "codecs/avif_dec.h"
#include "codecs/hevc_dec.h"
#include "codecs/jpeg_dec.h"
#include "codecs/jpeg_boxes.h"
#include "codecs/jpeg2000_dec.h"
#include "codecs/vvc_dec.h"
#include "context.h"
#include "image-items/mask_image.h"
#include "region.h"
#if WITH_UNCOMPRESSED_CODEC
#include "codecs/uncompressed/unc_decoder.h"
#endif
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
    else if (kind == "auxC") {
      writer.write32(0);
      writer.write(std::string("urn:example:aux"));
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

std::vector<uint8_t> make_mask_file(const std::vector<uint8_t>& region_data = {})
{
  HeifFile file;
  file.set_security_limits(heif_get_global_security_limits());
  file.new_empty_file();
  file.get_ftyp_box()->set_major_brand(fourcc("mif1"));
  file.get_ftyp_box()->add_compatible_brand(fourcc("mif1"));
  const std::vector<uint8_t> pixels(64 * 64, 0xAA);
  auto mask_id = file.add_new_image(fourcc("mski"));
  REQUIRE(mask_id);
  file.append_iloc_data(*mask_id, pixels, 0);
  file.set_primary_item_id(*mask_id);
  REQUIRE(file.add_ispe_property(*mask_id, 64, 64, true) == Error::Ok);
  auto mskC = std::make_shared<Box_mskC>();
  mskC->set_bits_per_pixel(8);
  file.add_property(*mask_id, mskC, true);
  if (!region_data.empty()) {
    auto region_id = file.add_infe(fourcc("rgan"), region_data.data(), region_data.size());
    REQUIRE(region_id);
    file.add_iref_reference(*region_id, fourcc("cdsc"), {*mask_id});
  }
  StreamWriter writer;
  file.derive_box_versions();
  file.write(writer);
  return writer.get_data();
}

} // namespace


TEST_CASE("box payload allocations respect block and total memory limits")
{
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1", "prof", "rICC", "hvcC",
                                    "avcS", "avcP", "avcE", "vvcC", "auxC");
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
                                    "avcS", "avcP", "avcE", "vvcC", "auxC");
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
                                    "avcS", "avcP", "avcE", "vvcC", "auxC");
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


TEST_CASE("iloc rejects an exhausted total budget before copying item data")
{
  Box_iloc iloc;
  REQUIRE(iloc.append_data(1, std::vector<uint8_t>(32, 0xAA), 0) == Error::Ok);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 31;
  TotalMemoryTracker tracker(&limits);
  std::vector<uint8_t> data;
  Error err = iloc.read_data(1, nullptr, nullptr, &data, &limits);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  REQUIRE(data.empty());
}


TEST_CASE("decoder input assembly accounts configuration and cached data together")
{
  const std::string kind = GENERATE("jpgC", "hvcC", "avcS", "avcP", "avcE", "vvcC", "av1C");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 64;
  const size_t header_size = (kind == "jpgC" || kind == "av1C") ? 16 : 20;
  const size_t combined_size = header_size + 32;
  limits.max_total_memory = 16 + 32 + combined_size;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_box(kind, 16), &limits, box) == Error::Ok);
  std::shared_ptr<Decoder> decoder;
  if (kind == "jpgC") decoder = std::make_shared<Decoder_JPEG>(std::dynamic_pointer_cast<Box_jpgC>(box));
  if (kind == "hvcC") decoder = std::make_shared<Decoder_HEVC>(std::dynamic_pointer_cast<Box_hvcC>(box));
  if (kind == "avcS" || kind == "avcP" || kind == "avcE") decoder = std::make_shared<Decoder_AVC>(std::dynamic_pointer_cast<Box_avcC>(box));
  if (kind == "vvcC") decoder = std::make_shared<Decoder_VVC>(std::dynamic_pointer_cast<Box_vvcC>(box));
  if (kind == "av1C") decoder = std::make_shared<Decoder_AVIF>(std::dynamic_pointer_cast<Box_av1C>(box));
  REQUIRE(decoder);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  DataExtent extent;
  extent.m_file = file;
  REQUIRE(extent.m_raw_memory_handle.alloc(32, &limits, "test cached input") == Error::Ok);
  extent.m_raw.assign(32, 0xAA);
  decoder->set_data_extent(std::move(extent));
  auto headers = decoder->read_bitstream_configuration_data();
  REQUIRE(headers);
  REQUIRE(headers->size() == header_size);

  SECTION("exact budgets retain the assembled output until its owner is destroyed") {
    limits.max_memory_block_size = combined_size;
    {
      MemoryHandle owner;
      std::vector<uint8_t> assembled;
      auto result = decoder->get_compressed_data(true, assembled, owner);
      REQUIRE(result);
      REQUIRE(*result == &assembled);
      std::vector<uint8_t> expected = *headers;
      expected.insert(expected.end(), 32, 0xAA);
      REQUIRE(**result == expected);
      REQUIRE(decoder->get_data_extent().m_raw == std::vector<uint8_t>(32, 0xAA));
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "retained assembly") != Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(combined_size, &limits, "released assembly") == Error::Ok);
  }

  SECTION("complete assembled size must fit the block limit") {
    limits.max_memory_block_size = combined_size - 1;
    MemoryHandle owner;
    std::vector<uint8_t> assembled;
    auto result = decoder->get_compressed_data(true, assembled, owner);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(assembled == *headers);
  }

  SECTION("assembly and original storage must fit the total budget concurrently") {
    limits.max_total_memory--;
    {
      MemoryHandle owner;
      std::vector<uint8_t> assembled;
      auto result = decoder->get_compressed_data(true, assembled, owner);
      REQUIRE_FALSE(result);
      REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
      REQUIRE(assembled == *headers);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(combined_size - 1, &limits, "released failed assembly") == Error::Ok);
  }

  SECTION("configuration is rejected before copying when its budget is exhausted") {
    limits.max_total_memory = 48 + header_size - 1;
    MemoryHandle owner;
    std::vector<uint8_t> assembled;
    auto result = decoder->get_compressed_data(true, assembled, owner);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(assembled.empty());
  }

  SECTION("configuration including length prefixes must fit the block limit") {
    limits.max_memory_block_size = header_size - 1;
    MemoryHandle owner;
    std::vector<uint8_t> assembled;
    auto result = decoder->get_compressed_data(true, assembled, owner);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(assembled.empty());
  }

  SECTION("frames without configuration borrow the cache even with no spare budget") {
    limits.max_total_memory = 48;
    MemoryHandle owner;
    std::vector<uint8_t> assembled;
    auto result = decoder->get_compressed_data(false, assembled, owner);
    REQUIRE(result);
    REQUIRE(*result == &decoder->get_data_extent().m_raw);
    REQUIRE(assembled.empty());
  }

  SECTION("disabled limits allow assembly") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    MemoryHandle owner;
    std::vector<uint8_t> assembled;
    auto result = decoder->get_compressed_data(true, assembled, owner);
    REQUIRE(result);
    REQUIRE((*result)->size() == combined_size);
  }
}

TEST_CASE("empty decoder configuration borrows cached input without another allocation")
{
  const std::string kind = GENERATE("JPEG", "JPEG2000", "AV1");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  std::shared_ptr<Decoder> decoder;
  if (kind == "JPEG") decoder = std::make_shared<Decoder_JPEG>(nullptr);
  if (kind == "JPEG2000") decoder = std::make_shared<Decoder_JPEG2000>(nullptr);
  if (kind == "AV1") decoder = std::make_shared<Decoder_AVIF>(std::make_shared<Box_av1C>());
  REQUIRE(decoder);
  DataExtent extent;
  extent.m_file = file;
  REQUIRE(extent.m_raw_memory_handle.alloc(32, &limits, "test cached input") == Error::Ok);
  extent.m_raw.assign(32, 0xAA);
  decoder->set_data_extent(std::move(extent));
  MemoryHandle owner;
  std::vector<uint8_t> assembled;
  auto result = decoder->get_compressed_data(true, assembled, owner);
  REQUIRE(result);
  REQUIRE(*result == &decoder->get_data_extent().m_raw);
  REQUIRE(**result == std::vector<uint8_t>(32, 0xAA));
  REQUIRE(assembled.empty());
}

TEST_CASE("mask decoding counts input and pixel storage concurrently")
{
  const auto bytes = make_mask_file();
  heif_security_limits limits = *heif_get_global_security_limits();
  size_t pixel_bytes;
  {
    TotalMemoryTracker tracker(&limits);
    HeifPixelImage pixels;
    pixels.create(64, 64, heif_colorspace_monochrome, heif_chroma_monochrome);
    REQUIRE(pixels.add_channel(heif_channel_Y, 64, 64, 8, &limits) == Error::Ok);
    pixel_bytes = tracker.get_max_total_memory_used();
  }
  constexpr size_t input_bytes = 64 * 64;
  const bool sufficient = GENERATE(false, true);
  limits.max_memory_block_size = std::max(input_bytes, pixel_bytes);
  limits.max_total_memory = input_bytes + pixel_bytes - (sufficient ? 0 : 1);
  HeifContext context;
  context.set_security_limits(&limits);
  REQUIRE(context.read_from_memory(bytes.data(), bytes.size(), false) == Error::Ok);
  auto image = context.get_primary_image(false);
  REQUIRE(image);
  heif_decoding_options options{};
  {
    auto result = image->decode_compressed_image(options, false, 0, 0, {});
    if (sufficient) {
      REQUIRE(result);
      size_t stride;
      const uint8_t* data = (*result)->get_channel_memory(heif_channel_Y, &stride);
      REQUIRE(data[0] == 0xAA);
      REQUIRE(data[63 * stride + 63] == 0xAA);
    }
    else {
      REQUIRE_FALSE(result);
      REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    }
  }
  context.get_security_limits()->max_memory_block_size = 0;
  MemoryHandle probe;
  REQUIRE(probe.alloc(limits.max_total_memory, context.get_security_limits(), "released mask input and pixels") == Error::Ok);
}

TEST_CASE("region opening counts input and parsed points concurrently")
{
  RegionItem region(0, 64, 64);
  auto polygon = std::make_shared<RegionGeometry_Polygon>();
  polygon->points = {{0, 0}, {63, 0}, {63, 63}};
  region.add_region(polygon);
  std::vector<uint8_t> payload;
  REQUIRE(region.encode(payload) == Error::Ok);
  const auto bytes = make_mask_file(payload);
  const size_t point_bytes = polygon->points.size() * sizeof(RegionGeometry_Polygon::Point);
  const bool sufficient = GENERATE(false, true);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = std::max(payload.size(), point_bytes);
  limits.max_total_memory = payload.size() + point_bytes - (sufficient ? 0 : 1);
  HeifContext context;
  context.set_security_limits(&limits);
  Error err = context.read_from_memory(bytes.data(), bytes.size(), false);
  if (sufficient) {
    REQUIRE(err == Error::Ok);
    REQUIRE(context.get_primary_image(false)->get_region_item_ids().size() == 1);
    MemoryHandle probe;
    REQUIRE(probe.alloc(payload.size(), context.get_security_limits(), "released region input") == Error::Ok);
    REQUIRE(probe.alloc(1, context.get_security_limits(), "retained region points") != Error::Ok);
  }
  else {
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    context.get_security_limits()->max_memory_block_size = 0;
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_total_memory, context.get_security_limits(), "released failed region input") == Error::Ok);
  }
}

TEST_CASE("metadata and cached decoder input respect the remaining context budget")
{
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  file->init_meta_box();
  auto iloc = std::make_shared<Box_iloc>();
  REQUIRE(iloc->append_data(1, std::vector<uint8_t>(32, 0xAA), 0) == Error::Ok);
  file->set_iloc_box(iloc);
  auto infe = std::make_shared<Box_infe>();
  infe->set_item_ID(1);
  infe->set_item_type_4cc(fourcc("Exif"));
  file->add_infe_box(1, infe);
  MemoryHandle occupied;
  REQUIRE(occupied.alloc(1, &limits, "other retained data") == Error::Ok);

  SECTION("metadata is rejected while another allocation occupies the budget") {
    auto result = file->get_uncompressed_item_data(1);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().error_code == heif_error_Memory_allocation_error);
    occupied.free();
    result = file->get_uncompressed_item_data(1);
    REQUIRE(result);
    REQUIRE(*result == std::vector<uint8_t>(32, 0xAA));
  }

  SECTION("failed decoder reads leave no cached allocation and can be retried") {
    DataExtent extent;
    extent.set_from_image_item(file, 1);
    auto result = extent.read_data();
    REQUIRE_FALSE(result);
    REQUIRE(result.error().error_code == heif_error_Memory_allocation_error);
    REQUIRE(extent.m_raw.empty());
    occupied.free();
    result = extent.read_data();
    REQUIRE(result);
    REQUIRE(**result == std::vector<uint8_t>(32, 0xAA));
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
    REQUIRE(extent.read_data());
  }
}


TEST_CASE("file-backed iloc reads reserve each extent before reading payload bytes")
{
  const auto method = GENERATE(uint16_t{0}, uint16_t{1});
  StreamWriter payload_writer;
  payload_writer.write32(40);
  payload_writer.write32(fourcc("idat"));
  payload_writer.write(std::vector<uint8_t>(32, 0xAA));
  const auto payload = payload_writer.get_data();
  std::shared_ptr<Box> parsed_idat;
  REQUIRE(parse_box(payload, heif_get_global_security_limits(), parsed_idat) == Error::Ok);
  auto idat = std::dynamic_pointer_cast<Box_idat>(parsed_idat);
  REQUIRE(idat);

  StreamWriter writer;
  writer.write32(40);
  writer.write32(fourcc("iloc"));
  writer.write32(0x01000000);
  writer.write8(0x44);
  writer.write8(0);
  writer.write16(1);
  writer.write16(1);
  writer.write16(method);
  writer.write16(0);
  writer.write16(2);
  for (uint32_t i = 0; i < 2; i++) {
    writer.write32((method == 0 ? 8 : 0) + i * 16);
    writer.write32(16);
  }
  std::shared_ptr<Box> parsed_iloc;
  REQUIRE(parse_box(writer.get_data(), heif_get_global_security_limits(), parsed_iloc) == Error::Ok);
  auto iloc = std::dynamic_pointer_cast<Box_iloc>(parsed_iloc);
  REQUIRE(iloc);

  class CountingReader : public StreamReader_memory {
  public:
    using StreamReader_memory::StreamReader_memory;
    size_t bytes_read = 0;
    bool read(void* data, size_t size) override {
      bytes_read += size;
      return StreamReader_memory::read(data, size);
    }
  };
  auto reader = std::make_shared<CountingReader>(payload.data(), payload.size(), false);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  TotalMemoryTracker tracker(&limits);
  MemoryHandle owner;
  std::vector<uint8_t> data;

  SECTION("exhausted budget rejects before reading the first extent") {
    limits.max_total_memory = 15;
    Error err = iloc->read_data(1, reader, idat, &data, &limits, &owner);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(reader->bytes_read == 0);
    REQUIRE(data.empty());
  }

  SECTION("a later failure leaves only the already reserved prefix") {
    limits.max_total_memory = 16;
    Error err = iloc->read_data(1, reader, idat, &data, &limits, &owner);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(reader->bytes_read == 16);
    REQUIRE(data == std::vector<uint8_t>(16, 0xAA));
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
    std::vector<uint8_t>().swap(data);
    owner.free();
    REQUIRE(probe.alloc(1, &limits, "budget probe") == Error::Ok);
  }

  SECTION("exact budget accepts and retains both extents") {
    REQUIRE(iloc->read_data(1, reader, idat, &data, &limits, &owner) == Error::Ok);
    REQUIRE(reader->bytes_read == 32);
    REQUIRE(data == std::vector<uint8_t>(32, 0xAA));
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
  }
}


#if WITH_UNCOMPRESSED_CODEC
namespace {

class MemoryTestUnciDecoder : public unc_decoder
{
public:
  explicit MemoryTestUnciDecoder(const std::shared_ptr<Box_uncC>& config)
      : unc_decoder(1, 1, nullptr, config, {}) {}

  using unc_decoder::decompress_whole_item;

  Result<std::vector<uint64_t>> get_tile_data_sizes() const override
  {
    return std::vector<uint64_t>{16, 16};
  }

  Error decode_tile(const std::vector<uint8_t>&, std::shared_ptr<HeifPixelImage>&,
                    uint32_t, uint32_t) override
  {
    return Error::Ok;
  }
};

} // namespace

TEST_CASE("unci assembled units enforce complete block and concurrent total budgets")
{
  if (!heif_metadata_compression_method_supported(heif_metadata_compression_deflate)) {
    SUCCEED("Deflate compression is not enabled in this build");
    return;
  }
  const bool whole_item = GENERATE(false, true);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 90;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  auto config = std::make_shared<Box_uncC>();
  config->set_number_of_tile_columns(1);
  config->set_number_of_tile_rows(1);
  config->set_interleave_type(0);
  MemoryTestUnciDecoder decoder(config);
  UncompressedImageCodec::unci_properties properties;
  properties.uncC = config;
  auto compression = std::make_shared<Box_cmpC>();
  compression->set_compression_type(fourcc("defl"));
  compression->set_compressed_unit_type(whole_item ? heif_cmpC_compressed_unit_type_full_item
                                                 : heif_cmpC_compressed_unit_type_image_row);
  properties.cmpC = compression;
  auto units = std::make_shared<Box_icef>();
  // Two entries deliberately reference the same stored deflate block.
  units->add_component({0, 21});
  units->add_component({0, 21});
  properties.icef = units;
  DataExtent extent;
  extent.m_file = file;
  REQUIRE(extent.m_raw_memory_handle.alloc(21, &limits, "test compressed input") == Error::Ok);
  extent.m_raw = {0x01, 0x10, 0x00, 0xEF, 0xFF};
  extent.m_raw.insert(extent.m_raw.end(), 16, 0xAA);

  if (whole_item) {
    SECTION("three units keep output capacity within the complete block budget") {
      units->add_component({0, 21});
      limits.max_memory_block_size = 48;
      limits.max_total_memory = 256;
      MemoryHandle owner;
      auto result = decoder.decompress_whole_item(extent, properties, 48, owner);
      REQUIRE(result);
      REQUIRE(*result == std::vector<uint8_t>(48, 0xAA));
      REQUIRE(result->capacity() <= limits.max_memory_block_size);
    }
  }

  SECTION("exact peak budget succeeds and output stays charged until destruction") {
    {
      MemoryHandle owner;
      std::vector<uint8_t> data;
      if (whole_item) {
        auto result = decoder.decompress_whole_item(extent, properties, 32, owner);
        REQUIRE(result);
        data = std::move(*result);
      }
      else {
        REQUIRE(decoder.fetch_tile_data(extent, properties, 0, 0, data, owner) == Error::Ok);
      }
      REQUIRE(data == std::vector<uint8_t>(32, 0xAA));
      limits.max_memory_block_size = 0;
      MemoryHandle probe;
      REQUIRE(probe.alloc(38, &limits, "remaining budget") != Error::Ok);
      REQUIRE(probe.alloc(37, &limits, "remaining budget") == Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(69, &limits, "released output budget") == Error::Ok);
  }

  SECTION("individually valid units cannot exceed the complete block limit") {
    limits.max_memory_block_size = 31;
    MemoryHandle owner;
    std::vector<uint8_t> data;
    Error err;
    if (whole_item) {
      auto result = decoder.decompress_whole_item(extent, properties, 32, owner);
      REQUIRE_FALSE(result);
      err = result.error();
    }
    else {
      err = decoder.fetch_tile_data(extent, properties, 0, 0, data, owner);
    }
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(data.empty());
  }

  SECTION("concurrent unit and assembly storage must fit the total budget") {
    limits.max_total_memory = 89;
    {
      MemoryHandle owner;
      std::vector<uint8_t> data;
      Error err;
      if (whole_item) {
        auto result = decoder.decompress_whole_item(extent, properties, 32, owner);
        REQUIRE_FALSE(result);
        err = result.error();
      }
      else {
        err = decoder.fetch_tile_data(extent, properties, 0, 0, data, owner);
      }
      REQUIRE(err.error_code == heif_error_Memory_allocation_error);
      REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    }
    limits.max_memory_block_size = 0;
    MemoryHandle probe;
    REQUIRE(probe.alloc(68, &limits, "released failed output") == Error::Ok);
  }

  SECTION("disabled limits allow the assembled output") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    MemoryHandle owner;
    std::vector<uint8_t> data;
    if (whole_item) {
      auto result = decoder.decompress_whole_item(extent, properties, 32, owner);
      REQUIRE(result);
      data = std::move(*result);
    }
    else {
      REQUIRE(decoder.fetch_tile_data(extent, properties, 0, 0, data, owner) == Error::Ok);
    }
    REQUIRE(data == std::vector<uint8_t>(32, 0xAA));
  }

  SECTION("single blob output retains its decompression reservation") {
    properties.icef = nullptr;
    limits.max_total_memory = 37;
    {
      MemoryHandle owner;
      auto result = decoder.decompress_whole_item(extent, properties, 16, owner);
      REQUIRE(result);
      REQUIRE(*result == std::vector<uint8_t>(16, 0xAA));
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "retained output") != Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(16, &limits, "released output") == Error::Ok);
  }
}

TEST_CASE("unci scattered raw tile reads check the complete tile before copying")
{
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 31;
  limits.max_total_memory = 80;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  auto config = std::make_shared<Box_uncC>();
  config->set_number_of_tile_columns(1);
  config->set_number_of_tile_rows(1);
  MemoryTestUnciDecoder decoder(config);
  UncompressedImageCodec::unci_properties properties;
  properties.uncC = config;
  DataExtent extent;
  extent.m_file = file;
  extent.m_raw.assign(32, 0xAA);
  MemoryHandle owner;
  std::vector<uint8_t> data;
  Error err = decoder.fetch_tile_data(extent, properties, 0, 0, data, owner);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  REQUIRE(data.empty());
  limits.max_memory_block_size = 32;
  REQUIRE(extent.m_raw_memory_handle.alloc(32, &limits, "test raw input") == Error::Ok);
  REQUIRE(decoder.fetch_tile_data(extent, properties, 0, 0, data, owner) == Error::Ok);
  REQUIRE(data == extent.m_raw);
}
#endif

TEST_CASE("metadata reservations survive decompression and transfer to their owner")
{
  const auto compression = GENERATE(heif_metadata_compression_off,
                                    heif_metadata_compression_zlib,
                                    heif_metadata_compression_deflate,
                                    heif_metadata_compression_brotli);
  if (!heif_metadata_compression_method_supported(compression)) {
    SUCCEED("Compression method is not enabled in this build");
    return;
  }
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1024;
  limits.max_total_memory = 4096;
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  const std::vector<uint8_t> payload(512, 0xAA);
  auto id = file->add_infe_mime("application/rdf+xml", compression, payload.data(), payload.size());
  REQUIRE(id);

  SECTION("only retained output remains charged after a successful read") {
    ImageMetadata metadata;
    {
      auto result = file->get_uncompressed_item_data(*id, &metadata.m_memory_handle);
      REQUIRE(result);
      REQUIRE(*result == payload);
      metadata.m_data = std::move(*result);
    }
    limits.max_total_memory = payload.size();
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
    REQUIRE(metadata.m_data == payload);
  }

  SECTION("compressed input and output must fit concurrently") {
    if (compression == heif_metadata_compression_off) return;
    limits.max_total_memory = payload.size();
    ImageMetadata metadata;
    auto result = file->get_uncompressed_item_data(*id, &metadata.m_memory_handle);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().error_code == heif_error_Memory_allocation_error);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }
}


TEST_CASE("compressed metadata block limits apply to the complete output")
{
  const auto compression = GENERATE(heif_metadata_compression_zlib,
                                    heif_metadata_compression_deflate,
                                    heif_metadata_compression_brotli);
  if (!heif_metadata_compression_method_supported(compression)) {
    SUCCEED("Compression method is not enabled in this build");
    return;
  }
  const size_t chunk_size = compression == heif_metadata_compression_brotli ? 262144 : 8192;
  const std::vector<uint8_t> payload(2 * chunk_size, 0xAA);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = payload.size();
  limits.max_total_memory = 0;
  TotalMemoryTracker tracker(&limits);
  HeifFile file;
  file.set_security_limits(&limits);
  auto id = file.add_infe_mime("application/rdf+xml", compression, payload.data(), payload.size());
  REQUIRE(id);
  ImageMetadata metadata;

  SECTION("one byte below the complete size rejects otherwise acceptable chunks") {
    limits.max_memory_block_size = payload.size() - 1;
    auto result = file.get_uncompressed_item_data(*id, &metadata.m_memory_handle);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().error_code == heif_error_Memory_allocation_error);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("an exact block budget accepts the complete output") {
    auto result = file.get_uncompressed_item_data(*id, &metadata.m_memory_handle);
    REQUIRE(result);
    REQUIRE(*result == payload);
  }

  SECTION("a disabled block limit accepts the complete output") {
    limits.max_memory_block_size = 0;
    auto result = file.get_uncompressed_item_data(*id, &metadata.m_memory_handle);
    REQUIRE(result);
    REQUIRE(*result == payload);
  }
}
