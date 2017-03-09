#pragma once

#include <boost/functional/hash.hpp>
#include <unordered_map>
#include <unordered_set>
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

  for (const auto& line : lines) {
    auto cipher = hex::decode(line);
    auto info = frequency_analysis(cipher);

    if (minimum.dist > info.dist) {
      minimum = byte_key_info(info.dist, info.key);
      plaintext = cipher ^ minimum.key;
    }
  }

  return make_pair(minimum.key, plaintext);
}

auto count_unique_blocks(const bytearray& bytes, const size_t block_size = 16) {
  unordered_map<bytearray, size_t, boost::hash<bytearray>> blocks;

  for (const auto& c : chunk(bytes, block_size)) {
    if (!blocks.count(c)) {
      blocks[c] = 0;
    }

    blocks[c] += 1;
  }

  return blocks;
}

bool duplicate_blocks(const bytearray& cipher, const size_t block_size) {
  auto counts = count_unique_blocks(cipher, block_size);
  bool found_duplicate = false;

  for (const auto& c : counts) {
    if (c.second > 1) {
      found_duplicate = true;
      continue;
    }
  }

  return found_duplicate;
}

bytearray find_ebc_encrypted_line(const vector<string>& lines) {
  string encrypted_line;

  for (const string& line : lines) {
    if (line == "")
      continue;

    auto blocks = count_unique_blocks(hex::decode(line));

    for (auto& b : blocks) {
      if (b.second != 1) {
        encrypted_line = line;
      }
    }
  }

  return hex::decode(encrypted_line);
}

auto find_duplicated_blocks(const bytearray& bytes,
                            const size_t block_size = 16) {
  auto counts = count_unique_blocks(bytes, block_size);
  unordered_set<bytearray, boost::hash<bytearray>> duplicates;

  for (const auto& c : counts) {
    if (c.second > 1) {
      duplicates.insert(c.first);
    }
  }

  return duplicates;
}

bytearray find_duplicated_block(const bytearray& bytes,
                                const size_t block_size = 16) {
  unordered_map<bytearray, size_t, boost::hash<bytearray>> blocks;
  unordered_set<bytearray, boost::hash<bytearray>> duplicates;

  for (const auto& c : chunk(bytes, block_size)) {
    if (!blocks.count(c)) {
      blocks[c] = 0;
    } else {
      return c;
    }

    blocks[c] += 1;
  }
}
