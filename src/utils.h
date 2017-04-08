#pragma once

#include <boost/algorithm/string.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "bytearray.h"

using namespace std;
using block_counter = unordered_map<bytearray, size_t, boost::hash<bytearray>>;

vector<string> split(const string& s, const string& sep);

pair<string, string> key_value(const string& s);

unordered_map<string, string> parse_query_string(const string& query_str);

bytearray slice(const bytearray& a, size_t start, size_t size);
bytearray nth_block(const bytearray& a, size_t block_size, size_t n);
bytearray first(const bytearray& a, size_t block_size);

vector<bytearray> chunk(const bytearray& b, const size_t chunk_size);

block_counter unique_block_counts(const bytearray& bytes,
                                  const size_t block_size = 16);

bool duplicate_blocks(const bytearray& cipher, const size_t block_size);

auto find_duplicated_blocks(const bytearray& bytes,
                            const size_t block_size = 16);

bytearray find_duplicated_block(const bytearray& bytes,
                                const size_t block_size = 16);

bytearray long_to_bytes(unsigned long num);
