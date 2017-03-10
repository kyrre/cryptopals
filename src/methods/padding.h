#pragma once

#include "bytearray.h"

bytearray& pkcs_padding(bytearray& b, size_t block_size) {
  size_t pad_num = max(0UL, block_size - b.size());

  for (size_t i = 0; i < pad_num; ++i) {
    b.push_back(pad_num);
  }

  return b;
}
