#pragma once
#include "bytearray.h"

bytearray to_bytes(const string &s) {

  vector<uint8_t> bytes;
  size_t n = s.length() - 2;

  for (size_t i = 0; i <= n; i += 2) {
    bytes.push_back(
        static_cast<uint8_t>(strtol(s.substr(i, 2).c_str(), NULL, 16)));
  }

  return bytearray(bytes);
}
