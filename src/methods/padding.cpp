#include "bytearray.h"
#include <iostream>
#include <unordered_set>

bytearray pkcs(const bytearray& b, size_t block_size) {
  bytearray padded(b);
  size_t pt_size = b.size();
  size_t num_pad = block_size - pt_size % block_size;

  for (size_t i = 0; i < num_pad; ++i) {
    padded.push_back(num_pad);
  }
  return padded;
}

bytearray strip_pkcs(const bytearray& b) {
  unordered_set<BYTE> padding_bytes;
  size_t padding_count = 0;
  size_t last_byte_found = 0xdeadbeef;
  decltype(b.rbegin()) rit;

  for (rit = b.rbegin(); rit != b.rend(); ++rit) {
    auto byte = *rit;

    if (byte >= 0x1 && byte <= 0x10) {
      if (last_byte_found == 0xdeadbeef) {
        last_byte_found = byte;
      } else if (last_byte_found != byte) {
        break;
      }

      padding_bytes.insert(byte);
      ++padding_count;
    } else {
      break;
    }
  }

  if (padding_count == 0) {
    throw std::overflow_error("No padding detected.");
  } else if (padding_count > 0) {
    BYTE padding_byte = (*padding_bytes.begin());
    if (padding_byte != padding_count) {
      throw std::overflow_error("Incorrect padding byte detected.");
    }
  }

  bytearray stripped;
  for (auto it = b.rend() - 1; it != rit - 1; --it) {
    stripped.push_back(*it);
  }

  return stripped;
}

bool valid_padding(const bytearray& b) {
  bool valid = true;
  try {
    strip_pkcs(b);
  } catch (overflow_error e) {
    valid = false;
  }

  return valid;
}
