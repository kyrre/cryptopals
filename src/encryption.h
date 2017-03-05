#pragma once

#include <boost/functional/hash.hpp>
#include <vector>

#include "aes.h"
#include "bytearray.h"
#include "frequency_analysis.h"
#include "fs.h"
#include "hex.h"

using namespace std;

pair<BYTE, bytearray> find_xor_encrypted_line(vector<string> lines) {

  byte_key_info minimum;
  bytearray plaintext;

  for (const auto &line : lines) {
    auto cipher = hex::decode(line);
    auto info = frequency_analysis(cipher);

    if (minimum.dist > info.dist) {
      minimum = byte_key_info(info.dist, info.key);
      plaintext = cipher ^ minimum.key;
    }
  }

  return make_pair(minimum.key, plaintext);
}

bytearray find_ebc_encrypted_line(const vector<string> &lines) {

  boost::hash<bytearray> bytearray_hasher;

  string encrypted_line;

  for (const string &line : lines) {

    if (line == "")
      continue;

    bytearray bytes = hex::decode(line);

    map<size_t, size_t> blocks;
    for (const auto &c : chunk(bytes, 16)) {

      assert(c.size() == 16);

      size_t h = bytearray_hasher(c);
      if (!blocks.count(h)) {
        blocks[h] = 0;
      }

      blocks[h] += 1;
    }

    for (auto &b : blocks) {
      if (b.second != 1) {
        encrypted_line = line;
      }
    }
  }

  return hex::decode(encrypted_line);
}
