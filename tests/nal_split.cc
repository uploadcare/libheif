/*
  libheif unit tests - NAL unit reader

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
#include "codecs/decoder.h"
#include "codecs/avc_dec.h"
#include "codecs/avc_boxes.h"
#include "codecs/hevc_dec.h"
#include "codecs/hevc_boxes.h"
#include "codecs/vvc_dec.h"
#include "codecs/vvc_boxes.h"

#include <cstdint>
#include <vector>

namespace {

std::vector<std::pair<const uint8_t*, size_t>> collect_nal_units(const uint8_t* data, size_t size)
{
  std::vector<std::pair<const uint8_t*, size_t>> units;
  size_t offset = 0;
  while (auto nal = next_nal_unit_4byte_length_prefixed(data, size, offset)) {
    units.push_back(*nal);
  }
  REQUIRE(offset == size);
  REQUIRE_FALSE(next_nal_unit_4byte_length_prefixed(data, size, offset));
  return units;
}

} // namespace

TEST_CASE("nal_units: two well-formed NAL units") {
  std::vector<uint8_t> buf{
      0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC,   // NAL of 3 bytes
      0x00, 0x00, 0x00, 0x02, 0xDD, 0xEE};        // NAL of 2 bytes
  auto units = collect_nal_units(buf.data(), buf.size());
  REQUIRE(units.size() == 2);
  REQUIRE(units[0].second == 3);
  REQUIRE(units[0].first[0] == 0xAA);
  REQUIRE(units[1].second == 2);
  REQUIRE(units[1].first[0] == 0xDD);
}

TEST_CASE("nal_units: length running past the end stops cleanly") {
  // First NAL is fine; second declares 100 bytes but only 2 remain.
  std::vector<uint8_t> buf{
      0x00, 0x00, 0x00, 0x01, 0xAA,
      0x00, 0x00, 0x00, 0x64, 0xBB, 0xCC};
  auto units = collect_nal_units(buf.data(), buf.size());
  REQUIRE(units.size() == 1);
  REQUIRE(units[0].second == 1);
  REQUIRE(units[0].first[0] == 0xAA);
}

TEST_CASE("nal_units: zero-length NAL is skipped, parsing continues") {
  std::vector<uint8_t> buf{
      0x00, 0x00, 0x00, 0x00,                     // zero-length NAL
      0x00, 0x00, 0x00, 0x01, 0x7E};              // 1-byte NAL
  auto units = collect_nal_units(buf.data(), buf.size());
  REQUIRE(units.size() == 1);
  REQUIRE(units[0].second == 1);
  REQUIRE(units[0].first[0] == 0x7E);
}

TEST_CASE("nal_units: a lone truncated length prefix yields nothing") {
  std::vector<uint8_t> buf{0x00, 0x00, 0x00};  // fewer than 4 bytes
  auto units = collect_nal_units(buf.data(), buf.size());
  REQUIRE(units.empty());
}

TEST_CASE("nal_units: empty input yields nothing") {
  auto units = collect_nal_units(nullptr, 0);
  REQUIRE(units.empty());
}

TEST_CASE("nal_units: malformed tails preserve preceding packets") {
  const std::vector<uint8_t> tail = GENERATE(std::vector<uint8_t>{0},
                                           std::vector<uint8_t>{0, 0},
                                           std::vector<uint8_t>{0, 0, 0},
                                           std::vector<uint8_t>{0xFF, 0xFF, 0xFF, 0xFF},
                                           std::vector<uint8_t>{0, 0, 0, 8, 0, 0, 0, 1, 0xBB});
  std::vector<uint8_t> buf{0, 0, 0, 1, 0xAA};
  buf.insert(buf.end(), tail.begin(), tail.end());
  auto units = collect_nal_units(buf.data(), buf.size());
  REQUIRE(units.size() == 1);
  REQUIRE(units[0].first == buf.data() + 4);
  REQUIRE(units[0].second == 1);
}

TEST_CASE("nal_units: many tiny packets preserve order and borrowed data") {
  constexpr size_t count = 100000;
  std::vector<uint8_t> buf;
  buf.reserve(count * 9);
  for (size_t i = 0; i < count; i++) {
    buf.insert(buf.end(), {0, 0, 0, 0, 0, 0, 0, 1, static_cast<uint8_t>(i)});
  }
  size_t offset = 0;
  size_t scanned = 0;
  bool preserved = true;
  while (auto nal = next_nal_unit_4byte_length_prefixed(buf.data(), buf.size(), offset)) {
    preserved &= nal->first == buf.data() + 9 * scanned + 8;
    preserved &= nal->second == 1;
    preserved &= nal->first[0] == static_cast<uint8_t>(scanned);
    scanned++;
  }
  REQUIRE(scanned == count);
  REQUIRE(preserved);
}

TEST_CASE("coded size scanning finds headers after many tiny packets") {
  const std::string codec = GENERATE("AVC", "HEVC", "VVC");
  INFO(codec);
  std::unique_ptr<Decoder> decoder;
  std::vector<uint8_t> sps;
  uint32_t width, height;
  if (codec == "AVC") {
    decoder = std::make_unique<Decoder_AVC>(std::make_shared<Box_avcC>());
    sps = {0x67, 0x4d, 0x40, 0x0b, 0xec, 0xc1, 0x42, 0xbc,
           0xd3, 0x42, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00,
           0x00, 0x03, 0x00, 0x04, 0x1e, 0x28, 0x53, 0x34};
    width = height = 160;
  }
  else if (codec == "HEVC") {
    decoder = std::make_unique<Decoder_HEVC>(std::make_shared<Box_hvcC>());
    sps = {0x42, 0x01, 0x01, 0x03, 0x70, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00,
           0x03, 0x00, 0x00, 0x03, 0x00, 0x3f, 0xa0, 0x0e, 0x48, 0x07, 0x47, 0x75,
           0x96, 0xea, 0x49, 0x29, 0xae, 0x6e, 0x02, 0x1a, 0x0c, 0x08, 0x00, 0x00,
           0x03, 0x00, 0xc8, 0x00, 0x00, 0x03, 0x00, 0x08, 0x40};
    width = 456;
    height = 464;
  }
  else {
    decoder = std::make_unique<Decoder_VVC>(std::make_shared<Box_vvcC>());
    // Minimal SPS prefix: one sublayer, 4:2:0, no PTL or cropping, 1x1, 8 bits.
    sps = {0x00, 0x79, 0x00, 0x08, 0x12, 0x20};
    width = height = 1;
  }
  std::vector<uint8_t> data;
  for (size_t i = 0; i < 100000; i++) {
    data.insert(data.end(), {0, 0, 0, 0, 0, 0, 0, 1, 0});
  }

  SECTION("packets without a size header return no dimensions") {
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE(result);
    REQUIRE_FALSE(result->has_value());
  }

  SECTION("a later header is inspected and a malformed tail stops the scan") {
    data.insert(data.end(), {0, 0, 0, static_cast<uint8_t>(sps.size())});
    data.insert(data.end(), sps.begin(), sps.end());
    data.insert(data.end(), {0xFF, 0xFF, 0xFF, 0xFF});
    auto result = decoder->get_max_coded_image_size(data);
    REQUIRE(result);
    REQUIRE(result->has_value());
    REQUIRE((*result)->width == width);
    REQUIRE((*result)->height == height);
  }
}
