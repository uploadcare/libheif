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
#include "codecs/jpeg2000_boxes.h"
#include "codecs/vvc_dec.h"
#include "context.h"
#include "image-items/mask_image.h"
#include "image-items/tiled.h"
#include "region.h"
#if WITH_UNCOMPRESSED_CODEC
#include "codecs/uncompressed/unc_decoder.h"
#endif
#include "mini.h"
#include "file.h"
#include "nclx.h"
#include "security_limits.h"
#include "sequences/seq_boxes.h"
#include "text.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

struct IpmaTable : Box_ipma { using Box_ipma::Entry; };
constexpr char kAuxType[] = "urn:example:aux";

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
  else if (kind == "cdef" || kind == "j2kL") {
    writer.write16(static_cast<uint16_t>(count));
    for (uint32_t i = 0; i < count; i++) {
      writer.write16(static_cast<uint16_t>(i));
      if (kind == "cdef") {
        writer.write16(0);
      }
      else {
        writer.write8(0);
      }
      writer.write16(static_cast<uint16_t>(i + 1));
    }
  }
  else if (kind == "ipma" || kind == "ipma1") {
    writer.write32(kind == "ipma1" ? 0x01000001 : 0);
    writer.write32(count);
    for (uint32_t i = 0; i < count; i++) {
      if (kind == "ipma1") writer.write32(0x10000 + i);
      else writer.write16(static_cast<uint16_t>(i + 1));
      writer.write8(2);
      if (kind == "ipma1") {
        writer.write16(0x8001);
        writer.write16(0x8002);
      }
      else {
        writer.write8(0x81);
        writer.write8(0x82);
      }
    }
  }
  else if (kind == "cpat" || kind == "splz" || kind == "sbpm") {
    writer.write32(0);
    if (kind != "cpat") {
      writer.write32(count ? 2 : 0);
      if (count) {
        writer.write32(0);
        writer.write32(1);
      }
    }
    if (kind == "sbpm") {
      writer.write8(0);
      writer.write32(count);
      writer.write32(count);
      writer.write32(count);
      for (uint32_t i = 0; i < count; i++) writer.write32(i);
      for (uint32_t i = 0; i < count; i++) writer.write32(i);
      for (uint32_t i = 0; i < count; i++) {
        writer.write32(i);
        writer.write32(i + 1);
      }
    }
    else {
      writer.write16(static_cast<uint16_t>(count));
      writer.write16(1);
      for (uint32_t i = 0; i < count; i++) {
        if (kind == "cpat") writer.write32(0);
        writer.write_float32(1);
      }
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
      writer.write(std::string(kAuxType));
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

std::vector<uint8_t> make_string_box(const std::string& kind, size_t length)
{
  const std::string value(length, 'x');
  const bool infe = kind.substr(0, 4) == "infe";
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc(kind == "gimi" ? "uuid" : kind.substr(0, 4).c_str()));
  if (kind == "gimi") {
    const uint8_t uuid[] = {0x26, 0x1e, 0xf3, 0x74, 0x1d, 0x97, 0x5b, 0xba,
                            0xac, 0xbd, 0x9d, 0x2c, 0x8e, 0xa7, 0x35, 0x22};
    for (uint8_t byte : uuid) writer.write8(byte);
    writer.write(value, false);
  }
  else {
    writer.write32(infe ? (kind == "infe3-name" ? 0x03000000 : 0x02000000) : 0);
    if (infe) {
      if (kind == "infe3-name") writer.write32(0x10000);
      else writer.write16(1);
      writer.write16(0);
      const bool mime = kind == "infe-type" || kind == "infe-encoding" || kind == "infe-all";
      writer.write32(fourcc(mime ? "mime" : kind == "infe-uri" ? "uri " : "hvc1"));
      writer.write(kind == "infe-name" || kind == "infe3-name" || kind == "infe-all" ? value : std::string{});
      if (mime) {
        writer.write(kind == "infe-type" || kind == "infe-all" ? value : std::string{});
        writer.write(kind == "infe-encoding" || kind == "infe-all" ? value : std::string{});
      }
      else if (kind == "infe-uri") {
        writer.write(value);
      }
    }
    else {
      if (kind == "hdlr") {
        writer.write32(0);
        writer.write32(fourcc("pict"));
        for (int i = 0; i < 3; i++) writer.write32(0);
      }
      const int fields = kind == "udes" ? 4 : 1;
      for (int i = 0; i < fields; i++) writer.write(value);
    }
  }
  const auto size = static_cast<uint32_t>(writer.get_data().size());
  writer.set_position(0);
  writer.write32(size);
  return writer.get_data();
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

// Include retained parser bookkeeping when deriving exact total budgets.
// The allocation-hook tests independently check these charges against real allocations.
size_t parsed_storage_size(const std::vector<uint8_t>& data)
{
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  return tracker.get_max_total_memory_used();
}

size_t allocation_size(const std::string& kind, uint32_t count)
{
  if (kind == "hvcC" || kind == "vvcC") {
    return parsed_storage_size(make_box(kind, count));
  }
  if (kind == "auxC") {
    return count + sizeof(kAuxType) - 1;
  }
  return (kind == "elst0" || kind == "elst1") ? count * sizeof(Box_elst::Entry) : count;
}

std::vector<uint8_t> make_mask_file(const std::vector<uint8_t>& region_data = {},
                                    const std::vector<std::vector<uint8_t>>& text_payloads = {})
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
  for (const auto& payload : text_payloads) {
    auto text_id = file.add_infe_mime("text/plain", heif_metadata_compression_off,
                                      payload.data(), payload.size());
    REQUIRE(text_id);
    file.add_iref_reference(*text_id, fourcc("text"), {*mask_id});
  }
  StreamWriter writer;
  file.derive_box_versions();
  file.write(writer);
  return writer.get_data();
}

} // namespace


TEST_CASE("tili opening enforces context limits on its offset table")
{
  HeifFile file;
  file.set_security_limits(heif_get_global_security_limits());
  file.new_empty_file();
  file.get_ftyp_box()->set_major_brand(fourcc("mif1"));
  file.get_ftyp_box()->add_compatible_brand(fourcc("mif1"));
  auto id = file.add_new_image(fourcc("tili"));
  REQUIRE(id);
  file.set_primary_item_id(*id);
  REQUIRE(file.add_ispe_property(*id, 64, 64, true) == Error::Ok);
  auto config = std::make_shared<Box_tilC>();
  heif_tiled_image_parameters params = config->get_parameters();
  params.tile_width = params.tile_height = 8;
  params.compression_format_fourcc = fourcc("jpeg");
  config->set_parameters(params);
  file.add_property(*id, config, true);
  file.append_iloc_data(*id, std::vector<uint8_t>(64 * 8, 0), 0);
  StreamWriter writer;
  file.derive_box_versions();
  file.write(writer);
  const auto bytes = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();

  SECTION("the context tile count applies before allocating the table") {
    limits.max_number_of_tiles = 63;
  }
  SECTION("the table must fit the block limit") {
    limits.max_memory_block_size = 64;
    limits.max_total_memory = 0;
  }
  SECTION("the table must fit the total limit") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 128;
  }

  HeifContext context;
  context.set_security_limits(&limits);
  REQUIRE(context.read_from_memory(bytes.data(), bytes.size(), false) == Error::Ok);
  auto image = context.get_primary_image(true);
  REQUIRE(image);
  REQUIRE(image->get_item_error().sub_error_code == heif_suberror_Security_limit_exceeded);
}


TEST_CASE("tili offset tables retain checked memory reservations")
{
  Box_tilC config;
  auto params = config.get_parameters();
  params.image_width = params.image_height = 16;
  params.tile_width = params.tile_height = 8;
  heif_security_limits limits = *heif_get_global_security_limits();
  size_t table_bytes;
  {
    TotalMemoryTracker tracker(&limits);
    TiledHeader header;
    REQUIRE(header.set_parameters(params, &limits) == Error::Ok);
    table_bytes = tracker.get_max_total_memory_used();
    REQUIRE(table_bytes >= 4 * sizeof(uint64_t));
  }
  limits.max_memory_block_size = table_bytes;
  limits.max_total_memory = table_bytes;
  TotalMemoryTracker tracker(&limits);
  auto header = std::make_unique<TiledHeader>();

  SECTION("exact budgets accept initialized entries and retain the table") {
    REQUIRE(header->set_parameters(params, &limits) == Error::Ok);
    REQUIRE(header->get_num_tiles() == 4);
    for (uint32_t i = 0; i < 4; i++) {
      REQUIRE_FALSE(header->is_tile_offset_known(i));
      REQUIRE(header->get_tile_size(i) == 0);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "retained offset table") != Error::Ok);
  }

  SECTION("block limits reject the whole table independently of total limits") {
    limits.max_memory_block_size = table_bytes - 1;
    limits.max_total_memory = 0;
    Error err = header->set_parameters(params, &limits);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(header->get_num_tiles() == 0);
  }

  SECTION("total limits reject the table independently of block limits") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = table_bytes - 1;
    REQUIRE(header->set_parameters(params, &limits).sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_total_memory, &limits, "failed table allocation") == Error::Ok);
  }

  SECTION("multiple tables share the budget and destruction releases it") {
    limits.max_total_memory = 2 * table_bytes;
    TiledHeader second, third;
    REQUIRE(header->set_parameters(params, &limits) == Error::Ok);
    REQUIRE(second.set_parameters(params, &limits) == Error::Ok);
    REQUIRE(third.set_parameters(params, &limits).sub_error_code == heif_suberror_Security_limit_exceeded);
    header.reset();
    REQUIRE(third.set_parameters(params, &limits) == Error::Ok);
  }

  SECTION("moving the header transfers its retained reservation") {
    REQUIRE(header->set_parameters(params, &limits) == Error::Ok);
    {
      TiledHeader moved = std::move(*header);
      header.reset();
      REQUIRE(moved.get_num_tiles() == 4);
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "moved offset table") != Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(table_bytes, &limits, "destroyed moved offset table") == Error::Ok);
  }

  SECTION("disabled limits allow the table") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    limits.max_number_of_tiles = 0;
    REQUIRE(header->set_parameters(params, &limits) == Error::Ok);
    REQUIRE(header->get_num_tiles() == 4);
  }

  SECTION("an unrepresentable table is rejected without allocating") {
    limits.max_number_of_tiles = 0;
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    params.image_width = params.image_height = UINT32_MAX;
    params.tile_width = params.tile_height = 1;
    REQUIRE(header->set_parameters(params, &limits).sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE(header->get_num_tiles() == 0);
  }
}

TEST_CASE("tili offset reads count temporary input alongside retained storage")
{
  Box_tilC config;
  auto params = config.get_parameters();
  params.image_width = params.image_height = 16;
  params.tile_width = params.tile_height = 8;
  params.offset_field_length = params.size_field_length = 32;
  heif_security_limits limits = *heif_get_global_security_limits();
  size_t table_bytes;
  {
    TotalMemoryTracker tracker(&limits);
    TiledHeader header;
    REQUIRE(header.set_parameters(params, &limits) == Error::Ok);
    table_bytes = tracker.get_max_total_memory_used();
  }
  constexpr size_t input_bytes = 4 * 8;
  limits.max_memory_block_size = std::max(table_bytes, input_bytes);
  limits.max_total_memory = table_bytes + input_bytes;
  TotalMemoryTracker tracker(&limits);
  TiledHeader header;
  REQUIRE(header.set_parameters(params, &limits) == Error::Ok);
  StreamWriter writer;
  for (uint32_t i = 0; i < 4; i++) {
    writer.write32(64 + i * 8);
    writer.write32(8);
  }
  auto payload = writer.get_data();
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  file->new_empty_file();

  SECTION("exact concurrent budgets preserve offsets and serialization") {
    auto id = file->add_infe(fourcc("tili"), payload.data(), payload.size());
    REQUIRE(id);
    REQUIRE(header.read_full_offset_table(file, *id, &limits) == Error::Ok);
    for (uint32_t i = 0; i < 4; i++) {
      REQUIRE(header.get_tile_offset(i) == 64 + i * 8);
      REQUIRE(header.get_tile_size(i) == 8);
    }
    auto encoded = header.write_offset_table();
    REQUIRE(encoded);
    REQUIRE(*encoded == payload);
  }

  SECTION("input and retained storage must fit concurrently") {
    limits.max_total_memory--;
    auto id = file->add_infe(fourcc("tili"), payload.data(), payload.size());
    REQUIRE(id);
    REQUIRE(header.read_full_offset_table(file, *id, &limits).sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE_FALSE(header.is_tile_offset_known(0));
  }

  SECTION("temporary input obeys the current block limit") {
    limits.max_memory_block_size = input_bytes - 1;
    auto id = file->add_infe(fourcc("tili"), payload.data(), payload.size());
    REQUIRE(id);
    REQUIRE(header.read_full_offset_table(file, *id, &limits).sub_error_code == heif_suberror_Security_limit_exceeded);
    REQUIRE_FALSE(header.is_tile_offset_known(0));
  }

  SECTION("truncated input is rejected before reading table entries") {
    payload.pop_back();
    auto id = file->add_infe(fourcc("tili"), payload.data(), payload.size());
    REQUIRE(id);
    REQUIRE(header.read_full_offset_table(file, *id, &limits) != Error::Ok);
    REQUIRE_FALSE(header.is_tile_offset_known(0));
  }

  limits.max_memory_block_size = 0;
  MemoryHandle probe;
  REQUIRE(probe.alloc(limits.max_total_memory - table_bytes, &limits, "released offset input") == Error::Ok);
  REQUIRE(probe.alloc(1, &limits, "retained offset storage") != Error::Ok);
}

TEST_CASE("box payload allocations respect block and total memory limits")
{
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1", "prof", "rICC", "hvcC",
                                    "avcS", "avcP", "avcE", "vvcC", "auxC");
  INFO("box: " << kind);
  const auto data = make_box(kind, 32);
  const size_t amount = allocation_size(kind, 32);
  const size_t block_amount = (kind == "auxC" || kind == "hvcC" || kind == "vvcC") ? 32 : amount;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = block_amount;
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
    limits.max_memory_block_size = block_amount - 1;
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
  limits.max_memory_block_size = std::max(size_t{1}, allocation_size(kind, 0));
  limits.max_total_memory = limits.max_memory_block_size;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_box(kind, 0), &limits, box) == Error::Ok);
}


TEST_CASE("parsed box strings enforce block and retained total budgets")
{
  const std::string kind = GENERATE("auxC", "infe-name", "infe3-name", "infe-type", "infe-encoding",
                                    "infe-uri", "infe-all", "udes", "elng", "uri ", "auxi", "hdlr", "url ", "gimi");
  INFO("box: " << kind);
  const size_t length = GENERATE(size_t{32}, size_t{8193});
  const size_t total_bytes = length * (kind == "udes" ? 4 : kind == "infe-all" ? 3 : 1);
  const auto data = make_string_box(kind, length);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = length;
  limits.max_total_memory = total_bytes;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  SECTION("exact budgets accept and preserve every string") {
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    StreamWriter writer;
    REQUIRE(box->write(writer) == Error::Ok);
    REQUIRE(writer.get_data() == data);
  }

  SECTION("each string must fit the block limit independently of the total") {
    limits.max_memory_block_size = length - 1;
    limits.max_total_memory = 0;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("all strings in the box must fit the total budget") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = total_bytes - 1;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(total_bytes - 1, &limits, "released failed string parse") == Error::Ok);
  }

  SECTION("strings stay charged across retained boxes and are released on destruction") {
    limits.max_total_memory = 2 * total_bytes;
    std::shared_ptr<Box> second, third;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    REQUIRE(parse_box(data, &limits, second) == Error::Ok);
    Error err = parse_box(data, &limits, third);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    box.reset();
    REQUIRE(parse_box(data, &limits, third) == Error::Ok);
  }

  SECTION("empty strings fit a minimal budget") {
    limits.max_memory_block_size = 1;
    limits.max_total_memory = 1;
    REQUIRE(parse_box(make_string_box(kind, 0), &limits, box) == Error::Ok);
  }

  SECTION("disabled block limits still allow strings within the total budget") {
    limits.max_memory_block_size = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }

  SECTION("disabled total limits still allow strings within the block budget") {
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }

  SECTION("disabled memory limits allow strings") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }
}

TEST_CASE("parsed box tables enforce allocation and retained total budgets")
{
  const std::string kind = GENERATE("cpat", "splz", "sbpm", "cdef", "j2kL", "ipma", "ipma1");
#if !WITH_UNCOMPRESSED_CODEC
  if (kind == "cpat" || kind == "splz" || kind == "sbpm") {
    SKIP("Uncompressed codec is not enabled");
  }
#endif
  INFO("box: " << kind);
  constexpr uint32_t count = 4;
  size_t largest_allocation;
  size_t total_allocation;
  if (kind == "cpat") {
    largest_allocation = total_allocation = count * sizeof(BayerPatternPixelCmpd);
  }
  else if (kind == "splz") {
    largest_allocation = count * sizeof(float);
    total_allocation = largest_allocation + 2 * sizeof(uint32_t);
  }
  else if (kind == "sbpm") {
    largest_allocation = count * sizeof(SensorBadPixelsMap::BadPixelCoordinate);
    total_allocation = largest_allocation + (2 + 2 * count) * sizeof(uint32_t);
  }
  else if (kind == "cdef") {
    largest_allocation = total_allocation = count * sizeof(Box_cdef::Channel);
  }
  else if (kind == "j2kL") {
    largest_allocation = total_allocation = count * sizeof(Box_j2kL::Layer);
  }
  else {
    largest_allocation = count * sizeof(IpmaTable::Entry);
    total_allocation = largest_allocation + count * 2 * sizeof(Box_ipma::PropertyAssociation);
  }
  const auto data = make_box(kind, count);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = largest_allocation;
  limits.max_total_memory = total_allocation;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;

  SECTION("exact block and total budgets accept the table") {
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    if (kind == "j2kL") {
      auto layers = std::dynamic_pointer_cast<Box_j2kL>(box);
      REQUIRE(layers);
      REQUIRE(layers->get_layers().size() == count);
      REQUIRE(layers->get_layers().back().decode_layers == count);
    }
    else {
      StreamWriter writer;
      REQUIRE(box->write(writer) == Error::Ok);
      REQUIRE(writer.get_data() == data);
    }
  }

  SECTION("the largest individual vector must fit the block limit") {
    limits.max_memory_block_size--;
    limits.max_total_memory = 0;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("all retained vectors must fit the total limit") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory--;
    Error err = parse_box(data, &limits, box);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("retained boxes share a budget and destruction releases it") {
    limits.max_total_memory = 2 * total_allocation;
    std::shared_ptr<Box> second, third;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    REQUIRE(parse_box(data, &limits, second) == Error::Ok);
    Error err = parse_box(data, &limits, third);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    box.reset();
    REQUIRE(parse_box(data, &limits, third) == Error::Ok);
  }

  SECTION("disabled limits accept the table") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  }

  SECTION("truncated first tables fail before reserving declared storage") {
    auto truncated = data;
    if (kind == "splz" || kind == "sbpm") {
      truncated.resize(19); // full header, component count, incomplete first component
    }
    else if (kind == "ipma" || kind == "ipma1") {
      truncated.resize(18); // full header, entry count, incomplete first entry
    }
    else {
      truncated.pop_back();
    }
    const auto size = static_cast<uint32_t>(truncated.size());
    truncated[0] = static_cast<uint8_t>(size >> 24);
    truncated[1] = static_cast<uint8_t>(size >> 16);
    truncated[2] = static_cast<uint8_t>(size >> 8);
    truncated[3] = static_cast<uint8_t>(size);
    Error err = parse_box(truncated, &limits, box);
    REQUIRE(err.error_code == heif_error_Invalid_input);
    REQUIRE(err.sub_error_code == heif_suberror_End_of_data);
    REQUIRE(tracker.get_max_total_memory_used() == 0);
  }
}

TEST_CASE("empty parsed box tables fit a minimal memory budget")
{
  const std::string kind = GENERATE("sbpm", "cdef", "j2kL", "ipma", "ipma1");
#if !WITH_UNCOMPRESSED_CODEC
  if (kind == "sbpm") {
    SKIP("Uncompressed codec is not enabled");
  }
#endif
  INFO("box: " << kind);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_box(kind, 0), &limits, box) == Error::Ok);
}

TEST_CASE("merged ipma tables account copies alongside their original storage")
{
  constexpr size_t entry_count = 4;
  const size_t source_count = GENERATE(1, 3);
  const size_t entry_bytes = entry_count * sizeof(IpmaTable::Entry);
  const size_t box_bytes = entry_bytes + entry_count * 2 * sizeof(Box_ipma::PropertyAssociation);
  const std::string failure = GENERATE("none", "block", "total");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = entry_bytes * (1 + source_count);
  limits.max_total_memory = box_bytes * (1 + 2 * source_count);
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> first;
  std::vector<std::shared_ptr<Box_ipma>> sources;
  const auto data = make_box("ipma", entry_count);
  REQUIRE(parse_box(data, &limits, first) == Error::Ok);
  for (size_t i = 0; i < source_count; i++) {
    std::shared_ptr<Box> box;
    REQUIRE(parse_box(data, &limits, box) == Error::Ok);
    auto source = std::dynamic_pointer_cast<Box_ipma>(box);
    REQUIRE(source);
    sources.push_back(std::move(source));
  }
  auto* first_ipma = dynamic_cast<Box_ipma*>(first.get());
  REQUIRE(first_ipma);
  if (failure == "block") limits.max_memory_block_size--;
  if (failure == "total") limits.max_total_memory--;
  Error err = first_ipma->insert_entries_from_other_ipma_boxes(sources, &limits);
  if (failure == "none") {
    REQUIRE(err == Error::Ok);
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "retained merged entries") != Error::Ok);
    first.reset();
    limits.max_memory_block_size = 0;
    REQUIRE(probe.alloc((1 + source_count) * box_bytes, &limits, "released original and merged entries") == Error::Ok);
  }
  else {
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    StreamWriter writer;
    REQUIRE(first->write(writer) == Error::Ok);
    REQUIRE(writer.get_data() == data);
    MemoryHandle probe;
    limits.max_memory_block_size = 0;
    REQUIRE(probe.alloc(limits.max_total_memory - (1 + source_count) * box_bytes, &limits, "released failed merge reservation") == Error::Ok);
  }
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
  const size_t amount = parsed_storage_size(data);
  limits.max_memory_block_size = 64;
  limits.max_total_memory = amount;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  StreamWriter output;
  REQUIRE(box->write(output) == Error::Ok);
  REQUIRE(output.get_data() == data);
  box.reset();

  limits.max_total_memory = amount - 1;
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
  const size_t amount = parsed_storage_size(data);
  limits.max_memory_block_size = 96;
  limits.max_total_memory = amount;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(data, &limits, box) == Error::Ok);
  box.reset();
  limits.max_total_memory = amount - 1;
  Error err = parse_box(data, &limits, box);
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  box.reset();
  limits.max_total_memory = amount;
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
  const size_t original_storage = allocation_size(kind, 16) + 32;
  limits.max_total_memory = original_storage + combined_size;
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
    limits.max_total_memory = original_storage + header_size - 1;
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
    limits.max_total_memory = original_storage;
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
  const size_t table_bytes = sizeof(IpmaTable::Entry) + 2 * sizeof(Box_ipma::PropertyAssociation);
  const bool sufficient = GENERATE(false, true);
  limits.max_memory_block_size = std::max(input_bytes, pixel_bytes);
  limits.max_total_memory = table_bytes + input_bytes + pixel_bytes - (sufficient ? 0 : 1);
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
  REQUIRE(probe.alloc(limits.max_total_memory - table_bytes, context.get_security_limits(), "released mask input and pixels") == Error::Ok);
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
  const size_t table_bytes = sizeof(IpmaTable::Entry) + 2 * sizeof(Box_ipma::PropertyAssociation);
  const bool sufficient = GENERATE(false, true);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = std::max(payload.size(), point_bytes);
  limits.max_total_memory = table_bytes + payload.size() + point_bytes - (sufficient ? 0 : 1);
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
    REQUIRE(probe.alloc(limits.max_total_memory - table_bytes, context.get_security_limits(), "released failed region input") == Error::Ok);
  }
}

TEST_CASE("text parsing enforces independent limits and preserves payloads")
{
  std::vector<uint8_t> payload(32, 'T');
  payload[4] = 0;
  payload[5] = 0xFF;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = payload.size();
  limits.max_total_memory = payload.size();
  TotalMemoryTracker tracker(&limits);
  auto item = std::make_shared<TextItem>();

  SECTION("exact budgets preserve the complete text payload") {
    REQUIRE(item->parse(std::vector<uint8_t>(payload), &limits) == Error::Ok);
    auto text = item->get_item_text();
    REQUIRE(text);
    REQUIRE(*text == std::string(payload.begin(), payload.end()));
    auto result = item->encode();
    REQUIRE(result);
    REQUIRE(*result == payload);
  }

  SECTION("block limits apply independently of total limits") {
    limits.max_memory_block_size = payload.size() - 1;
    limits.max_total_memory = 0;
    Error err = item->parse(std::vector<uint8_t>(payload), &limits);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    auto text = item->get_item_text();
    REQUIRE(text);
    REQUIRE(text->empty());
  }

  SECTION("total limits apply independently of block limits") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = payload.size() - 1;
    Error err = item->parse(std::vector<uint8_t>(payload), &limits);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_total_memory, &limits, "failed text parse") == Error::Ok);
  }

  SECTION("empty text needs no payload reservation") {
    limits.max_memory_block_size = 1;
    limits.max_total_memory = 1;
    REQUIRE(item->parse({}, &limits) == Error::Ok);
    auto text = item->get_item_text();
    REQUIRE(text);
    REQUIRE(text->empty());
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "empty text") == Error::Ok);
  }

  SECTION("disabled limits allow text payloads") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    REQUIRE(item->parse(std::vector<uint8_t>(payload), &limits) == Error::Ok);
    auto text = item->get_item_text();
    REQUIRE(text);
    REQUIRE(*text == std::string(payload.begin(), payload.end()));
  }
}

TEST_CASE("text loading retries after a context budget failure")
{
  const std::vector<uint8_t> payload(512, 'T');
  const auto bytes = make_mask_file({}, {payload});
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = payload.size();
  HeifContext context;
  context.set_security_limits(&limits);
  REQUIRE(context.read_from_memory(bytes.data(), bytes.size(), false) == Error::Ok);
  const auto& ids = context.get_primary_image(false)->get_text_item_ids();
  REQUIRE(ids.size() == 1);
  auto item = context.get_text_item(ids[0]);
  REQUIRE(item);
  context.get_security_limits()->max_total_memory = 1;
  auto text = item->get_item_text();
  REQUIRE_FALSE(text);
  REQUIRE(text.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  context.get_security_limits()->max_total_memory = limits.max_total_memory;
  auto retry = item->get_item_text();
  REQUIRE(retry);
  REQUIRE(*retry == std::string(payload.begin(), payload.end()));
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


TEST_CASE("failed file-range reads preserve the caller's existing reservation")
{
  const auto bytes = make_mask_file();
  heif_security_limits limits = *heif_get_global_security_limits();
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  REQUIRE(file->read(std::make_shared<StreamReader_memory>(bytes.data(), bytes.size(), false)) == Error::Ok);
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 32;
  TotalMemoryTracker tracker(&limits);
  MemoryHandle owner;
  REQUIRE(owner.alloc(8, &limits, "existing caller reservation") == Error::Ok);
  DataExtent extent;
  extent.set_file_range(file, bytes.size(), 16);

  for (int i = 0; i < 4; i++) {
    auto result = extent.read_data(0, 16, &owner);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_End_of_data);
    MemoryHandle probe;
    REQUIRE(probe.alloc(24, &limits, "released failed read") == Error::Ok);
    REQUIRE(probe.alloc(1, &limits, "existing caller reservation remains") != Error::Ok);
  }

  extent.set_file_range(file, 0, 16);
  auto result = extent.read_data(0, 16, &owner);
  REQUIRE(result);
  REQUIRE(*result == std::vector<uint8_t>(bytes.begin(), bytes.begin() + 16));
  MemoryHandle probe;
  REQUIRE(probe.alloc(8, &limits, "remaining budget after successful read") == Error::Ok);
  REQUIRE(probe.alloc(1, &limits, "successful read remains charged") != Error::Ok);
}

TEST_CASE("file-backed iloc reads reserve the complete output before reading payload bytes")
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

  SECTION("a budget that fits only a prefix rejects before reading any extent") {
    limits.max_total_memory = 16;
    Error err = iloc->read_data(1, reader, idat, &data, &limits, &owner);
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(reader->bytes_read == 0);
    REQUIRE(data.empty());
    MemoryHandle probe;
    REQUIRE(probe.alloc(16, &limits, "unchanged budget") == Error::Ok);
  }

  SECTION("exact budget accepts and retains both extents") {
    REQUIRE(iloc->read_data(1, reader, idat, &data, &limits, &owner) == Error::Ok);
    REQUIRE(reader->bytes_read == 32);
    REQUIRE(data == std::vector<uint8_t>(32, 0xAA));
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
  }

  SECTION("replacement storage must fit alongside the existing destination") {
    const bool sufficient = GENERATE(false, true);
    limits.max_memory_block_size = 48;
    limits.max_total_memory = sufficient ? 64 : 63;
    REQUIRE(owner.alloc(16, &limits, "existing destination") == Error::Ok);
    data.assign(16, 0xBB);
    Error err = iloc->read_data(1, reader, idat, &data, &limits, &owner);
    if (sufficient) {
      REQUIRE(err == Error::Ok);
      REQUIRE(reader->bytes_read == 32);
      std::vector<uint8_t> expected(16, 0xBB);
      expected.insert(expected.end(), 32, 0xAA);
      REQUIRE(data == expected);
    }
    else {
      REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
      REQUIRE(reader->bytes_read == 0);
      REQUIRE(data == std::vector<uint8_t>(16, 0xBB));
      MemoryHandle probe;
      REQUIRE(probe.alloc(47, &limits, "unchanged budget after rejection") == Error::Ok);
    }
  }
}


#if WITH_UNCOMPRESSED_CODEC
TEST_CASE("sensor pattern copies retain their parsed payload budget")
{
  const std::string kind = GENERATE("cpat", "splz", "sbpm");
  const auto bytes = make_box(kind, 2);
  const size_t budget = kind == "cpat" ? 16 : kind == "splz" ? 16 : 40;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = budget;
  limits.max_total_memory = budget;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(bytes, &limits, box) == Error::Ok);
  std::shared_ptr<Box> retained;
  if (kind == "cpat") {
    auto copy = std::make_shared<Box_cpat>();
    copy->set_pattern(std::dynamic_pointer_cast<Box_cpat>(box)->get_pattern());
    retained = copy;
  }
  else if (kind == "splz") {
    auto source = std::make_unique<ImageDescription>();
    source->add_polarization_pattern(std::dynamic_pointer_cast<Box_splz>(box)->get_pattern());
    ImageDescription image;
    image.copy_metadata_from(*source);
    source.reset();
    auto copy = std::make_shared<Box_splz>();
    copy->set_pattern(image.get_polarization_patterns()[0]);
    retained = copy;
  }
  else {
    auto source = std::make_unique<ImageDescription>();
    source->add_sensor_bad_pixels_map(std::dynamic_pointer_cast<Box_sbpm>(box)->get_bad_pixels_map());
    ImageDescription image;
    image.copy_metadata_from(*source);
    source.reset();
    auto copy = std::make_shared<Box_sbpm>();
    copy->set_bad_pixels_map(image.get_sensor_bad_pixels_maps()[0]);
    retained = copy;
  }
  box.reset();
  StreamWriter writer;
  REQUIRE(retained->write(writer) == Error::Ok);
  REQUIRE(writer.get_data() == bytes);
  MemoryHandle probe;
  REQUIRE(probe.alloc(1, &limits, "retained sensor pattern").sub_error_code == heif_suberror_Security_limit_exceeded);
  retained.reset();
  REQUIRE(probe.alloc(budget, &limits, "released sensor pattern") == Error::Ok);
}


TEST_CASE("truncated snuc tables are rejected before reserving declared storage")
{
  const bool components = GENERATE(false, true);
  StreamWriter writer;
  writer.write32(components ? 16 : 25);
  writer.write32(fourcc("snuc"));
  writer.write32(0);
  writer.write32(components ? 256 : 0);
  if (!components) {
    writer.write8(0);
    writer.write32(4096);
    writer.write32(4096);
  }
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 1;
  limits.max_total_memory = 1;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(writer.get_data(), &limits, box);
  REQUIRE(err.error_code == heif_error_Invalid_input);
  REQUIRE(err.sub_error_code == heif_suberror_End_of_data);
  REQUIRE(tracker.get_max_total_memory_used() == 0);
}


TEST_CASE("sensor correction copies retain their payload budget until the last image is destroyed")
{
  const std::string copy_method = GENERATE("add", "set", "metadata");
  StreamWriter writer;
  writer.write32(61);
  writer.write32(fourcc("snuc"));
  writer.write32(0);
  writer.write32(1);
  writer.write32(0);
  writer.write8(0x80);
  writer.write32(4);
  writer.write32(1);
  for (int i = 0; i < 4; i++) writer.write_float32(float(i + 1));
  for (int i = 0; i < 4; i++) writer.write_float32(float(i));

  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = 32;
  limits.max_total_memory = 40; // Parsed IDs, remapped IDs and the two float arrays.
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(writer.get_data(), &limits, box) == Error::Ok);
  auto snuc = std::dynamic_pointer_cast<Box_snuc>(box);
  REQUIRE(snuc);

  auto source = std::make_unique<ImageDescription>();
  {
    SensorNonUniformityCorrection nuc = snuc->get_nuc();
    auto ids = map_cmpd_to_component_ids(nuc.component_ids->values, {{17}}, &limits);
    REQUIRE(ids);
    nuc.component_ids = std::move(*ids);
    source->add_sensor_nuc(nuc);
  }
  REQUIRE(snuc->get_nuc().component_ids->values == std::vector<uint32_t>{0});
  auto retained = std::make_unique<ImageDescription>();
  if (copy_method == "add") retained->add_sensor_nuc(source->get_sensor_nuc()[0]);
  if (copy_method == "set") retained->set_sensor_nuc(source->get_sensor_nuc());
  if (copy_method == "metadata") retained->copy_metadata_from(*source);
  REQUIRE(retained->get_sensor_nuc()[0].data == snuc->get_nuc().data);
  source.reset();
  snuc.reset();
  box.reset();
  limits.max_total_memory = 36; // Only the remapped IDs and float arrays remain.

  REQUIRE(retained->get_sensor_nuc().size() == 1);
  REQUIRE(retained->get_sensor_nuc()[0].component_ids->values == std::vector<uint32_t>{17});
  REQUIRE(retained->get_sensor_nuc()[0].data->nuc_gains == std::vector<float>{1, 2, 3, 4});
  REQUIRE(retained->get_sensor_nuc()[0].data->nuc_offsets == std::vector<float>{0, 1, 2, 3});
  MemoryHandle probe;
  Error err = probe.alloc(1, &limits, "sensor correction lifetime probe");
  REQUIRE(err.error_code == heif_error_Memory_allocation_error);
  REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  auto another = std::make_unique<ImageDescription>();
  another->copy_metadata_from(*retained);
  retained.reset();
  REQUIRE(probe.alloc(1, &limits, "remaining sensor correction owner") != Error::Ok);
  another.reset();
  REQUIRE(probe.alloc(32, &limits, "released sensor correction budget") == Error::Ok);
  MemoryHandle id_probe;
  REQUIRE(id_probe.alloc(4, &limits, "released sensor component budget") == Error::Ok);
}


TEST_CASE("snuc component tables independently obey block and total limits")
{
  StreamWriter writer;
  writer.write32(65);
  writer.write32(fourcc("snuc"));
  writer.write32(0);
  writer.write32(8);
  for (int i = 0; i < 8; i++) writer.write32(static_cast<uint32_t>(i));
  writer.write8(0);
  writer.write32(1);
  writer.write32(1);
  writer.write_float32(1);
  writer.write_float32(0);
  const std::string mode = GENERATE("block", "total", "exact", "disabled");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 31 : mode == "exact" ? 32 : 0;
  limits.max_total_memory = mode == "total" ? 31 : mode == "exact" ? 40 : 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(writer.get_data(), &limits, box);
  if (mode == "block" || mode == "total") {
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(err == Error::Ok);
    auto snuc = std::dynamic_pointer_cast<Box_snuc>(box);
    REQUIRE(snuc->get_nuc().component_ids->values == std::vector<uint32_t>{0, 1, 2, 3, 4, 5, 6, 7});
  }
}


TEST_CASE("decoded Bayer tables obey allocation budgets and stay charged through image copies")
{
  const std::string mode = GENERATE("block", "total", "exact");
  constexpr uint32_t count = 1024;
  constexpr size_t table_bytes = count * sizeof(heif_bayer_pattern_pixel);
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_bayer_pattern_pixels = count;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_box("cpat", count), &limits, box) == Error::Ok);
  auto cmpd = std::make_shared<Box_cmpd>();
  cmpd->add_component({heif_cmpd_component_type_monochrome, {}});
  auto config = std::make_shared<Box_uncC>();
  config->add_component({0, 8, 0, 0});
  UncompressedImageCodec::unci_properties properties;
  properties.cmpd = cmpd;
  properties.uncC = config;
  std::vector<uint32_t> component_ids;
  {
    auto image = UncompressedImageCodec::create_image(properties, 1, 1, component_ids, &limits);
    REQUIRE(image);
  }
  // Include the same pixel-plane allocation as a decode without a Bayer table.
  const size_t peak_budget = tracker.get_max_total_memory_used() + count * sizeof(uint32_t) + table_bytes;
  properties.cpat = std::dynamic_pointer_cast<Box_cpat>(box);
  limits.max_memory_block_size = mode == "block" ? table_bytes - 1 : table_bytes;
  limits.max_total_memory = mode == "total" ? peak_budget - 1 : peak_budget;
  auto result = UncompressedImageCodec::create_image(properties, 1, 1, component_ids, &limits);
  if (mode == "block" || mode == "total") {
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(result);
    auto image = std::move(*result);
    const auto& pattern = image->get_any_bayer_pattern();
    REQUIRE(pattern.pixels->values.size() == count);
    REQUIRE(pattern.pixels->values.front().component_gain == 1);
    REQUIRE(image->find_component_description(pattern.pixels->values.front().component_id));
    auto retained = std::make_unique<ImageDescription>();
    retained->copy_metadata_from(*image);
    image.reset();
    properties.cpat.reset();
    box.reset();
    limits.max_total_memory = table_bytes;
    MemoryHandle probe;
    REQUIRE(probe.alloc(1, &limits, "retained decoded Bayer table") != Error::Ok);
    retained.reset();
    REQUIRE(probe.alloc(table_bytes, &limits, "released decoded Bayer table") == Error::Ok);
  }
}


TEST_CASE("sensor component remapping reserves its complete output before copying")
{
  const std::string mode = GENERATE("block", "total", "exact", "disabled");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 15 : mode == "exact" ? 16 : 0;
  limits.max_total_memory = mode == "total" ? 15 : mode == "exact" ? 16 : 0;
  TotalMemoryTracker tracker(&limits);
  auto result = map_cmpd_to_component_ids({0, 1}, {{17, 18}, {17, 19}}, &limits);
  if (mode == "block" || mode == "total") {
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(result);
    auto ids = std::move(*result);
    REQUIRE(ids->values == std::vector<uint32_t>{17, 18, 19});
    if (mode == "exact") {
      auto retained = ids;
      ids.reset();
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "retained mapped IDs") != Error::Ok);
      retained.reset();
      REQUIRE(probe.alloc(16, &limits, "released mapped IDs") == Error::Ok);
    }
  }
}


TEST_CASE("sensor correction storage preserves block and total parsing limits")
{
  SensorNonUniformityCorrection nuc;
  nuc.image_width = 4;
  nuc.image_height = 1;
  auto data = std::make_shared<SensorNonUniformityCorrection::Data>();
  data->nuc_gains = {1, 2, 3, 4};
  data->nuc_offsets = {0, 1, 2, 3};
  nuc.data = std::move(data);
  Box_snuc snuc;
  snuc.set_nuc(nuc);
  StreamWriter writer;
  REQUIRE(snuc.write(writer) == Error::Ok);

  const std::string mode = GENERATE("block", "total", "exact", "disabled");
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 31 : mode == "exact" ? 32 : 0;
  limits.max_total_memory = mode == "total" ? 31 : mode == "exact" ? 32 : 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error err = parse_box(writer.get_data(), &limits, box);
  if (mode == "block" || mode == "total") {
    REQUIRE(err.error_code == heif_error_Memory_allocation_error);
    REQUIRE(err.sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(err == Error::Ok);
    StreamWriter roundtrip;
    REQUIRE(box->write(roundtrip) == Error::Ok);
    REQUIRE(roundtrip.get_data() == writer.get_data());
  }
}

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

TEST_CASE("codec header scratch obeys limits while compressed input remains retained")
{
  const std::string codec = GENERATE("AVC", "HEVC", "VVC");
  INFO(codec);
  std::unique_ptr<Decoder> decoder;
  std::vector<uint8_t> sps;
  if (codec == "AVC") {
    decoder = std::make_unique<Decoder_AVC>(std::make_shared<Box_avcC>());
    sps = {0x67, 0x4d, 0x40, 0x0b, 0xec, 0xc1, 0x42, 0xbc,
           0xd3, 0x42, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00,
           0x00, 0x03, 0x00, 0x04, 0x1e, 0x28, 0x53, 0x34};
  }
  else if (codec == "HEVC") {
    decoder = std::make_unique<Decoder_HEVC>(std::make_shared<Box_hvcC>());
    sps = {0x42, 0x01, 0x01, 0x03, 0x70, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00,
           0x03, 0x00, 0x00, 0x03, 0x00, 0x3f, 0xa0, 0x0e, 0x48, 0x07, 0x47, 0x75,
           0x96, 0xea, 0x49, 0x29, 0xae, 0x6e, 0x02, 0x1a, 0x0c, 0x08, 0x00, 0x00,
           0x03, 0x00, 0xc8, 0x00, 0x00, 0x03, 0x00, 0x08, 0x40};
  }
  else {
    decoder = std::make_unique<Decoder_VVC>(std::make_shared<Box_vvcC>());
    sps = {0x00, 0x79, 0x00, 0x08, 0x12, 0x20};
  }
  sps.resize(4096, 0xAA);
  StreamWriter writer;
  for (int i = 0; i < 2; i++) {
    writer.write32(static_cast<uint32_t>(sps.size()));
    writer.write(sps);
  }
  const auto data = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();
  TotalMemoryTracker tracker(&limits);
  auto file = std::make_shared<HeifFile>();
  file->set_security_limits(&limits);
  DataExtent extent;
  extent.m_file = file;
  REQUIRE(extent.m_raw_memory_handle.alloc(data.size(), &limits, "retained compressed input") == Error::Ok);
  extent.m_raw = data;
  decoder->set_data_extent(std::move(extent));
  limits.max_memory_block_size = sps.size();
  limits.max_total_memory = data.size() + sps.size();

  SECTION("each header fits exact budgets and releases scratch before the next header") {
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE(result);
    REQUIRE(result->has_value());
    MemoryHandle probe;
    REQUIRE(probe.alloc(sps.size(), &limits, "released header scratch") == Error::Ok);
  }

  SECTION("the scratch buffer must fit the block limit") {
    limits.max_memory_block_size--;
    limits.max_total_memory = 0;
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("input and scratch must fit the total budget concurrently") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory--;
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(sps.size() - 1, &limits, "failed header scratch") == Error::Ok);
  }

  SECTION("explicit decode limits override the file limits") {
    heif_security_limits decode_limits = limits;
    decode_limits.parent = &limits;
    if (GENERATE(false, true)) {
      decode_limits.max_memory_block_size = sps.size() - 1;
    }
    else {
      decode_limits.max_total_memory--;
    }
    auto result = decoder->get_max_coded_image_size(data, &decode_limits);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
  }

  SECTION("disabled memory limits allow header inspection") {
    limits.max_memory_block_size = 0;
    limits.max_total_memory = 0;
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE(result);
    REQUIRE(result->has_value());
  }
}

TEST_CASE("unescaped header storage preserves bytes within its reserved budget")
{
  const std::vector<uint8_t> input{0, 0, 3, 1, 0, 0, 3, 2, 0, 0, 3};
  const std::vector<uint8_t> expected{0, 0, 1, 0, 0, 2, 0, 0};
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = input.size();
  limits.max_total_memory = input.size();
  TotalMemoryTracker tracker(&limits);

  SECTION("exact budgets cover reserved capacity until the owner is destroyed") {
    {
      MemoryHandle owner;
      auto result = remove_start_code_emulation(input.data(), input.size(), owner, &limits);
      REQUIRE(result);
      REQUIRE(*result == expected);
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "retained unescaped header") != Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(input.size(), &limits, "released unescaped header") == Error::Ok);
  }

  SECTION("block failures do not consume the total budget") {
    limits.max_memory_block_size--;
    MemoryHandle owner;
    auto result = remove_start_code_emulation(input.data(), input.size(), owner, &limits);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_memory_block_size, &limits, "failed header allocation") == Error::Ok);
  }

  SECTION("empty headers require no allocation") {
    MemoryHandle owner;
    auto result = remove_start_code_emulation(nullptr, 0, owner, &limits);
    REQUIRE(result);
    REQUIRE(result->empty());
    MemoryHandle probe;
    REQUIRE(probe.alloc(input.size(), &limits, "empty header") == Error::Ok);
  }

  SECTION("incomplete escape prefixes are preserved") {
    const std::vector<uint8_t> prefix = GENERATE(std::vector<uint8_t>{0}, std::vector<uint8_t>{0, 0});
    MemoryHandle owner;
    auto result = remove_start_code_emulation(prefix.data(), prefix.size(), owner, &limits);
    REQUIRE(result);
    REQUIRE(*result == prefix);
  }
}

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

  SECTION("lazy metadata retains its reservation and reuses loaded data") {
    {
      ImageMetadata metadata;
      metadata.item_id = *id;
      metadata.set_source(file);
      REQUIRE(metadata.ensure_loaded() == Error::Ok);
      REQUIRE(metadata.m_data == payload);
      limits.max_total_memory = payload.size();
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
      REQUIRE(metadata.ensure_loaded() == Error::Ok);
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(payload.size(), &limits, "released metadata") == Error::Ok);
  }

  SECTION("lazy text retains its reservation and reuses loaded data") {
    {
      TextItem text(*id, file);
      auto result = text.get_item_text();
      REQUIRE(result);
      REQUIRE(*result == std::string(payload.size(), char(0xAA)));
      limits.max_total_memory = payload.size();
      MemoryHandle probe;
      REQUIRE(probe.alloc(1, &limits, "budget probe") != Error::Ok);
      REQUIRE(text.get_item_text());
    }
    MemoryHandle probe;
    REQUIRE(probe.alloc(payload.size(), &limits, "released text") == Error::Ok);
  }

  SECTION("releasing output preserves the cumulative decompression work charge") {
    if (compression == heif_metadata_compression_off) return;
    limits.max_total_memory = payload.size() + payload.size() / 2;
    {
      MemoryHandle memory_handle;
      auto result = file->get_uncompressed_item_data(*id, &memory_handle);
      REQUIRE(result);
      REQUIRE(*result == payload);
    }
    MemoryHandle memory_handle;
    auto result = file->get_uncompressed_item_data(*id, &memory_handle);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().sub_error_code == heif_suberror_Security_limit_exceeded);
    MemoryHandle probe;
    REQUIRE(probe.alloc(limits.max_total_memory, &limits, "released output") == Error::Ok);
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

#if WITH_UNCOMPRESSED_CODEC
TEST_CASE("component strings respect independent block and total budgets")
{
  const std::string kind = GENERATE("cmpd", "GIMI");
  const std::string mode = GENERATE("block", "total", "retained", "disabled");
  constexpr size_t payload_size = 4096;
  StreamWriter writer;
  if (kind == "cmpd") {
    writer.write32(0);
    writer.write32(fourcc("cmpd"));
    writer.write32(1);
    writer.write16(0x8000);
    writer.write(std::string(payload_size, 'x'));
  }
  else {
    Box_gimi_component_content_ids property;
    property.set_content_ids({std::string(payload_size, 'x')});
    REQUIRE(static_cast<const Box&>(property).write(writer) == Error::Ok);
  }
  const auto size = static_cast<uint32_t>(writer.get_data().size());
  writer.set_position(0);
  writer.write32(size);
  const auto bytes = writer.get_data();
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = mode == "block" ? 32 : 0;
  limits.max_total_memory = mode == "total" ? 32 : mode == "retained" ? 65536 : 0;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  Error error = parse_box(bytes, &limits, box);
  if (mode == "block" || mode == "total") {
    REQUIRE(error.error_code == heif_error_Memory_allocation_error);
    REQUIRE(error.sub_error_code == heif_suberror_Security_limit_exceeded);
  }
  else {
    REQUIRE(error == Error::Ok);
    if (kind == "cmpd") {
      auto property = std::dynamic_pointer_cast<Box_cmpd>(box);
      REQUIRE(property->get_components()[0].component_type_uri == std::string(payload_size, 'x'));
    }
    else {
      auto property = std::dynamic_pointer_cast<Box_gimi_component_content_ids>(box);
      REQUIRE(property->get_content_ids() == std::vector<std::string>{std::string(payload_size, 'x')});
    }
    if (mode == "retained") {
      MemoryHandle probe;
      REQUIRE(probe.alloc(limits.max_total_memory - payload_size + 1, &limits, "retained component string") != Error::Ok);
      box.reset();
      REQUIRE(probe.alloc(limits.max_total_memory, &limits, "released component string") == Error::Ok);
    }
  }
}
#endif

TEST_CASE("old reservations cannot credit a newly registered tracker")
{
  const size_t new_size = GENERATE(size_t{32}, size_t{64});
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = 64;
  MemoryHandle old_owner;
  {
    TotalMemoryTracker first(&limits);
    REQUIRE(old_owner.alloc(64, &limits, "surviving old allocation") == Error::Ok);
  }
  TotalMemoryTracker second(&limits);
  MemoryHandle new_owner;
  REQUIRE(new_owner.alloc(new_size, &limits, "new tracker allocation") == Error::Ok);
  MemoryHandle moved(std::move(old_owner));
  MemoryHandle surviving_owner;
  surviving_owner = std::move(moved);
  surviving_owner.free(32);
  surviving_owner.free();
  MemoryHandle probe;
  CHECK(probe.alloc(65 - new_size, &limits, "new tracker overflow").sub_error_code == heif_suberror_Security_limit_exceeded);
  probe.free();
  new_owner.free();
  REQUIRE(probe.alloc(64, &limits, "released new tracker allocation") == Error::Ok);
}

TEST_CASE("shared content IDs retain their reservation until the last metadata copy is released")
{
  constexpr size_t length = 4096;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = length;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_string_box("gimi", length), &limits, box) == Error::Ok);
  auto property = std::dynamic_pointer_cast<Box_gimi_content_id>(box);
  REQUIRE(property);
  ImageDescription original;
  original.set_gimi_sample_content_id(property->get_shared_content_id());
  ImageDescription copy;
  copy.copy_metadata_from(original);
  property.reset();
  box.reset();
  original.set_gimi_sample_content_id("replacement");
  REQUIRE(copy.get_gimi_sample_content_id() == std::string(length, 'x'));
  REQUIRE(original.get_gimi_sample_content_id() == "replacement");
  MemoryHandle probe;
  REQUIRE(probe.alloc(1, &limits, "retained shared content ID") != Error::Ok);
  copy.set_gimi_sample_content_id(std::string{});
  REQUIRE(probe.alloc(length, &limits, "released shared content ID") == Error::Ok);
}

TEST_CASE("replacing parsed property strings preserves snapshots and releases the box")
{
  const std::string kind = GENERATE("gimi", "auxC");
  constexpr size_t length = 4096;
  heif_security_limits limits = *heif_get_global_security_limits();
  limits.max_memory_block_size = limits.max_total_memory = length;
  TotalMemoryTracker tracker(&limits);
  std::shared_ptr<Box> box;
  REQUIRE(parse_box(make_string_box(kind, length), &limits, box) == Error::Ok);
  std::weak_ptr<Box> original_box = box;
  std::shared_ptr<const MemoryTrackedString> snapshot;
  if (kind == "gimi") {
    auto property = std::dynamic_pointer_cast<Box_gimi_content_id>(box);
    REQUIRE(property);
    snapshot = property->get_shared_content_id();
    property->set_content_id("replacement");
    REQUIRE(property->get_content_id() == "replacement");
  }
  else {
    auto property = std::dynamic_pointer_cast<Box_auxC>(box);
    REQUIRE(property);
    snapshot = property->get_shared_aux_type();
    property->set_aux_type("replacement");
    REQUIRE(property->get_aux_type() == "replacement");
  }
  box.reset();
  REQUIRE(original_box.expired());
  REQUIRE(snapshot);
  REQUIRE(snapshot->value == std::string(length, 'x'));
  MemoryHandle probe;
  REQUIRE(probe.alloc(1, &limits, "retained property snapshot") != Error::Ok);
  snapshot.reset();
  REQUIRE(probe.alloc(length, &limits, "released property snapshot") == Error::Ok);
}
