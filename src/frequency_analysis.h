#pragma once

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cmath>
#include <iostream>
#include <iostream>
#include <limits>
#include <map>
#include <queue>
#include <queue>
#include <string>
#include <vector>

#include <boost/range/irange.hpp>

#include "bytearray.h"
#include "frequency_analysis.h"
#include "hamming.h"
#include "hist.h"

const hist en_relative_frequencies = {
    {'e', .12702}, {'t', .0956},  {'a', .06517}, {'o', .07507}, {'i', .06966},
    {'n', .06749}, {'s', .06327}, {'h', .06094}, {'r', .05987}, {'d', .04253},
    {'l', .04025}, {'c', .02782}, {'u', .02758}, {'m', .02406}, {'w', .02360},
    {'f', .02228}, {'g', .02015}, {'y', .01974}, {'p', .01929}, {'b', .01242},
    {'v', .00978}, {'k', .00772}, {'j', .00153}, {'x', .00150}, {'q', .00095},
    {'z', .00074}, {':', .05000}, {' ', .17200}, {',', .09},    {'.', .09}};

auto compute_frequencies(const bytearray &plaintext) {
  hist freq;

  const double total = static_cast<double>(plaintext.size());
  for (const auto &a : plaintext) {
    freq[tolower(a)] += (1.0 / total);
  }
  return freq;
}

struct byte_key_info {
  double dist;
  BYTE key;

  byte_key_info(double dist_ = std::numeric_limits<double>::max(),
                BYTE key_ = 'A')
      : dist{dist_}, key{key_} {}

  byte_key_info(const byte_key_info &rhs) : dist{rhs.dist}, key{rhs.key} {}

  byte_key_info &operator=(byte_key_info &&rhs) {
    dist = rhs.dist;
    key = rhs.key;

    return *this;
  }
};

auto frequency_analysis(const bytearray &ciphertext) {

  byte_key_info minimum;
  for (auto key = 0x0; key <= 0xff; ++key) {

    auto freq = compute_frequencies(ciphertext ^ key);
    auto dist = en_relative_frequencies - freq;

    if (minimum.dist > dist) {
      minimum = byte_key_info(dist, key);
    }
  }

  return minimum;
}

bytearray slice(const bytearray &a, size_t start, size_t size) {

  if (start >= a.size()) {
    return bytearray();
  }

  auto _begin = begin(a) + start;
  auto _end = min(end(a), _begin + size);

  return bytearray(_begin, _end);
}

vector<bytearray> chunk(const bytearray &b, const size_t chunk_size) {

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

auto guess_key_size(const bytearray &cipher, const size_t num_guesses) {

  auto KEYSIZES = boost::irange(2, 40, 1);

  using ENTRY = pair<size_t, double>;
  auto cmp = [](ENTRY a, ENTRY b) { return a.second > b.second; };

  auto get_chunk = [&cipher](size_t i, const size_t KEYSIZE) {
    return slice(cipher, i * KEYSIZE, KEYSIZE);
  };

  priority_queue<ENTRY, vector<ENTRY>, decltype(cmp)> distances(cmp);

  for (const size_t KEYSIZE : KEYSIZES) {

    const size_t n = 4;
    double total = 0.0;

    for (size_t i = 0; i < (n - 1); i += 1) {
      total += hamming(get_chunk(i, KEYSIZE), get_chunk(i + 1, KEYSIZE));
    }

    double dist = total / n;
    double normalized_dist = dist / static_cast<double>(KEYSIZE);

    distances.push(make_pair(KEYSIZE, normalized_dist));
  }

  vector<ENTRY> guesses;

  size_t i = 0;
  while (i < num_guesses && !distances.empty()) {
    auto dist = distances.top();
    guesses.push_back(dist);
    distances.pop();
    ++i;
  }

  return guesses;
}

bytearray break_repeatable_xor(const bytearray &cipher, const size_t size) {

  auto chunks = chunk(cipher, size);

  vector<BYTES> blocks;
  for (size_t j = 0; j < size; ++j) {
    BYTES block;
    for (const auto &chunk : chunks) {
      block.push_back(chunk[j]);
    }
    blocks.push_back(block);
  }

  bytearray repeating_key;
  for (const auto &block : blocks) {
    auto decrypted = frequency_analysis(block);
    repeating_key.push_back(decrypted.key);
  }

  return repeating_key;
}
