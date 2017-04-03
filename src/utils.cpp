#include <boost/algorithm/string.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "bytearray.h"
#include "utils.h"

using namespace std;
using block_counter = unordered_map<bytearray, size_t, boost::hash<bytearray>>;

vector<string> split(const string& s, const string& sep) {
  vector<string> lines;
  boost::split(lines, s, boost::is_any_of(sep));

  return lines;
}

pair<string, string> key_value(const string& s) {
  vector<string> kv = split(s, "=");

  return make_pair(kv[0], kv[1]);
}

unordered_map<string, string> parse_query_string(const string& query_str) {
  unordered_map<string, string> kv;
  for (auto& token : split(query_str, "&")) {
    string key, value;
    tie(key, value) = key_value(token);

    kv[key] = value;
  }

  return kv;
}

bytearray slice(const bytearray& a, size_t start, size_t size) {
  if (start >= a.size()) {
    return bytearray();
  }

  auto _begin = begin(a) + start;
  auto _end = min(end(a), _begin + size);

  return bytearray(_begin, _end);
}

bytearray nth_block(const bytearray& a, size_t block_size, size_t n) {
  return slice(a, n * block_size, block_size);
}

bytearray first(const bytearray& a, size_t block_size) {
  return nth_block(a, block_size, 0);
}

vector<bytearray> chunk(const bytearray& b, const size_t chunk_size) {
  vector<bytearray> chunks;
  size_t num_chunks = b.size() / chunk_size + ((b.size() % chunk_size) != 0);

  for (size_t i = 0; i < num_chunks; ++i) {
    bytearray chunk = slice(b, i * chunk_size, chunk_size);
    if (chunk.size() != 0) {
      chunks.push_back(chunk);
    } else {
      break;
    }
  }

  return chunks;
}

block_counter unique_block_counts(const bytearray& bytes,
                                  const size_t block_size) {
  block_counter blocks;

  for (const auto& c : chunk(bytes, block_size)) {
    if (!blocks.count(c)) {
      blocks[c] = 0;
    }

    blocks[c] += 1;
  }

  return blocks;
}

bool duplicate_blocks(const bytearray& cipher, const size_t block_size) {
  auto counts = unique_block_counts(cipher, block_size);
  bool found_duplicate = false;

  for (const auto& c : counts) {
    if (c.second > 1) {
      found_duplicate = true;
      continue;
    }
  }

  return found_duplicate;
}

auto find_duplicated_blocks(const bytearray& bytes,
                            const size_t block_size) {
  block_counter counts = unique_block_counts(bytes, block_size);
  unordered_set<bytearray, boost::hash<bytearray>> duplicates;

  for (const auto& c : counts) {
    if (c.second > 1) {
      duplicates.insert(c.first);
    }
  }

  return duplicates;
}

bytearray find_duplicated_block(const bytearray& bytes,
                                const size_t block_size) {
  block_counter blocks;
  bytearray duplicated_block;
  unordered_set<bytearray, boost::hash<bytearray>> duplicates;

  for (auto&& c : chunk(bytes, block_size)) {
    if (!blocks.count(c)) {
      blocks[c] = 0;
    } else {
      duplicated_block = c;
      continue;
    }
    blocks[c] += 1;
  }

  return duplicated_block;
}
