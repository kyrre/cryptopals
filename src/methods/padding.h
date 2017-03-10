#pragma once

#include <unordered_set>
#include "bytearray.h"

bytearray& pkcs_padding(bytearray& b, size_t block_size) {
  size_t pad_num = max(0UL, block_size - b.size());

  for (size_t i = 0; i < pad_num; ++i) {
    b.push_back(pad_num);
  }

  return b;
}


bytearray strip_pkcs_padding(const bytearray& b) {

  bool valid = true;
  unordered_set<BYTE> padding_bytes;
  size_t padding_count = 0;
  decltype(b.rbegin()) rit;
  for(rit = b.rbegin(); rit != b.rend(); ++rit ) {
    auto byte = *rit;
    if (byte >= 0x1 && byte <= 0xf) {
      padding_bytes.insert(byte);
      ++padding_count;
    } else {
      break;
    }
  }

  if (padding_bytes.size() > 1) {
    throw std::overflow_error("Different padding bytes detected.");
  } else if (padding_count > 0) {
    BYTE padding_byte  = (*padding_bytes.begin());
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
