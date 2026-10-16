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
#include "security_limits.h"
#include "sequences/seq_boxes.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> make_box(const std::string& kind, uint32_t count)
{
  StreamWriter writer;
  writer.write32(0);
  writer.write32(fourcc(kind.substr(0, 4).c_str()));

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
  else {
    if (kind == "av1C") {
      writer.write32(0x81000000);
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
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1");
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
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1");
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
  const std::string kind = GENERATE("unkn", "jpgC", "av1C", "elst0", "elst1");
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
