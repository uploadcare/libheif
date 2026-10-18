/*
 * HEIF codec.
 * Copyright (c) 2024 Brad Hards <bradh@frogmouth.net>
 *
 * This file is part of libheif.
 *
 * libheif is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * libheif is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libheif.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "compression.h"

#if HAVE_BROTLI

const size_t BUF_SIZE = (1 << 18);
#include <algorithm>
#include <brotli/decode.h>
#include <brotli/encode.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#include "error.h"
#include "security_limits.h"


Result<std::vector<uint8_t>> decompress_brotli(const std::vector<uint8_t> &compressed_input,
                                               const heif_security_limits* limits,
                                               uint64_t max_output_size, MemoryHandle* memory_handle)
{
    BrotliDecoderResult result = BROTLI_DECODER_RESULT_ERROR;
    MemoryHandle scratch_memory;
    size_t scratch_size = BUF_SIZE;
    if (limits && limits->max_memory_block_size) {
        scratch_size = std::min<uint64_t>(scratch_size, limits->max_memory_block_size);
    }
    if (limits && limits->max_total_memory) {
        scratch_size = std::min<uint64_t>(scratch_size, std::max<uint64_t>(1, limits->max_total_memory / 2));
    }
    // One extra byte detects output exceeding the declared size.
    if (max_output_size < scratch_size) {
        scratch_size = static_cast<size_t>(max_output_size) + 1;
    }
    if (auto err = scratch_memory.alloc(scratch_size, limits, "brotli scratch buffer")) {
        return err;
    }
    std::vector<uint8_t> buffer(scratch_size, 0);
    size_t available_in = compressed_input.size();
    const std::uint8_t *next_in = reinterpret_cast<const std::uint8_t *>(compressed_input.data());
    size_t available_out = buffer.size();
    std::uint8_t *next_output = buffer.data();

    std::unique_ptr<BrotliDecoderState, void(*)(BrotliDecoderState*)> state(BrotliDecoderCreateInstance(0, 0, 0), BrotliDecoderDestroyInstance);

    // Track the growth of `output` against the security limits. Without this, a
    // high-ratio "decompression bomb" would expand a few KB of input into GBs of
    // output, bypassing max_memory_block_size / max_total_memory (GHSA-24wx-9w62-c96w).
    MemoryHandle output_memory_handle;
    std::vector<uint8_t> output;

    // Append the data decoded into `buffer` to `output`.
    auto append_decoded_data = [&]() -> Error {
        size_t n_new_bytes = static_cast<size_t>(std::distance(buffer.data(), next_output));

        // Stop as soon as there is more data than the caller expects. This keeps a
        // decompression bomb from inflating up to the security limits when the size
        // of the decompressed data is known in advance (GHSA-fcmw-5764-7rq8).
        if (n_new_bytes > max_output_size - output.size()) {
            return Error(heif_error_Invalid_input, heif_suberror_Decompression_invalid_data,
                         "Decompressed brotli data is larger than expected.");
        }

        if (limits && limits->max_memory_block_size &&
            (output.size() > limits->max_memory_block_size ||
             n_new_bytes > limits->max_memory_block_size - output.size())) {
            return Error(heif_error_Memory_allocation_error, heif_suberror_Security_limit_exceeded,
                         "Decompressed brotli data exceeds the maximum memory block size");
        }

        if (n_new_bytes) {
            const size_t new_size = output.size() + n_new_bytes;
            if (new_size <= output.capacity()) {
              output.insert(output.end(), buffer.data(), buffer.data() + n_new_bytes);
            }
            else {
              size_t capacity = std::max(new_size, output.capacity() <= output.max_size() / 2
                                        ? output.capacity() * 2 : output.max_size());
              capacity = std::min<uint64_t>(capacity, max_output_size);
              if (limits && limits->max_memory_block_size) {
                capacity = std::min<uint64_t>(capacity, limits->max_memory_block_size);
              }
              if (auto err = output_memory_handle.alloc(capacity, limits, "brotli decompression output")) {
                  return err;
              }
              const size_t old_capacity = output.capacity();
              {
                  std::vector<uint8_t> replacement;
                  replacement.reserve(capacity);
                  replacement.insert(replacement.end(), output.begin(), output.end());
                  replacement.insert(replacement.end(), buffer.data(), buffer.data() + n_new_bytes);
                  output.swap(replacement);
              }
              output_memory_handle.free(old_capacity);
            }
        }
        return Error::Ok;
    };

    while (true)
    {
        result = BrotliDecoderDecompressStream(state.get(), &available_in, &next_in, &available_out, &next_output, 0);

        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
        {
            if (Error err = append_decoded_data()) {
                return err;
            }
            available_out = buffer.size();
            next_output = buffer.data();
        }
        else if (result == BROTLI_DECODER_RESULT_SUCCESS)
        {
            if (Error err = append_decoded_data()) {
                return err;
            }
            break;
        }
        else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
        {
            std::stringstream sstr;
            sstr << "Error performing brotli inflate - insufficient data.\n";
            return Error(heif_error_Invalid_input, heif_suberror_Decompression_invalid_data, sstr.str());
        }
        else if (result == BROTLI_DECODER_RESULT_ERROR)
        {
            const char* errorMessage = BrotliDecoderErrorString(BrotliDecoderGetErrorCode(state.get()));
            std::stringstream sstr;
            sstr << "Error performing brotli inflate - " << errorMessage << "\n";
            return Error(heif_error_Invalid_input, heif_suberror_Decompression_invalid_data, sstr.str());
        }
        else
        {
            const char* errorMessage = BrotliDecoderErrorString(BrotliDecoderGetErrorCode(state.get()));
            std::stringstream sstr;
            sstr << "Unknown error performing brotli inflate - " << errorMessage << "\n";
            return Error(heif_error_Invalid_input, heif_suberror_Decompression_invalid_data, sstr.str());
        }
    }

    if (memory_handle) {
        if (auto err = memory_handle->merge(std::move(output_memory_handle))) {
            return err;
        }
    }
    return output;
}


std::vector<uint8_t> compress_brotli(const uint8_t* input, size_t size)
{
  std::unique_ptr<BrotliEncoderState, void(*)(BrotliEncoderState*)> state(BrotliEncoderCreateInstance(nullptr, nullptr, nullptr), BrotliEncoderDestroyInstance);

  size_t available_in = size;
  const uint8_t* next_in = input;

  std::vector<uint8_t> tmp(BUF_SIZE);
  size_t available_out = BUF_SIZE;
  uint8_t* next_out = tmp.data();

  std::vector<uint8_t> result;

  for (;;) {
    BROTLI_BOOL success = BrotliEncoderCompressStream(state.get(),
                                                      BROTLI_OPERATION_FINISH,
                                                      &available_in,
                                                      &next_in,
                                                      &available_out,
                                                      &next_out,
                                                      nullptr);
    if (!success) {
      return {};
    }

    if (next_out != tmp.data()) {
      result.insert(result.end(), tmp.data(), tmp.data() + std::distance(tmp.data(), next_out));
      available_out = BUF_SIZE;
      next_out = tmp.data();
    }

    if (BrotliEncoderIsFinished(state.get())) {
      break;
    }
  }

  return result;
}

#endif
