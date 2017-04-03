#pragma once

#include "analysis/frequency.h"
#include "bytearray.h"
#include "hex.h"

using std::pair;
using std::vector;
using std::string;
using std::make_pair;

pair<BYTE, bytearray> find_xor_encrypted_line(vector<string> lines) {
  byte_key_info minimum;
  bytearray plaintext;

  for (const auto& line : lines) {
    auto cipher = hex::decode(line);
    auto info = frequency_analysis(cipher);

    if (minimum.dist > info.dist) {
      minimum = byte_key_info(info.dist, info.key);
      plaintext = cipher ^ minimum.key;
    }
  }

  return std::make_pair(minimum.key, plaintext);
}
