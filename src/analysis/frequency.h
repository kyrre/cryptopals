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
#include "hamming.h"
#include "hist.h"
#include "utils.h"



// this does not sum to 1
extern const hist en_relative_frequencies;

struct byte_key_info {
  double dist;
  BYTE key;

  byte_key_info(double dist_ = std::numeric_limits<double>::max(),
                BYTE key_ = 'A')
      : dist{dist_}, key{key_} {}

  byte_key_info(const byte_key_info& rhs) : dist{rhs.dist}, key{rhs.key} {}

  byte_key_info& operator=(byte_key_info&& rhs) {
    dist = rhs.dist;
    key = rhs.key;

    return *this;
  }
};


hist compute_frequencies(const bytearray& plaintext);

byte_key_info frequency_analysis(const bytearray& ciphertext);

vector<pair<size_t, double>> guess_key_size(const bytearray& cipher, const size_t num_guesses);

bytearray break_repeatable_xor(const bytearray& cipher, const size_t size);
