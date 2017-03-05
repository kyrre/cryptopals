#pragma once

#include "bytearray.h"
#include <cmath>
#include <initializer_list>
#include <map>

using namespace std;

class hist {
private:
  map<BYTE, double> freq;

public:
  using value_type = decltype(freq)::value_type;
  using iterator = decltype(freq)::iterator;
  using const_iterator = decltype(freq)::const_iterator;

  auto begin() { return freq.begin(); }
  auto end() { return freq.end(); }

  hist() {}
  hist(initializer_list<pair<BYTE const, double>> list);
  hist(const hist &&rhs);

  hist &operator=(const hist &&rhs);
  double &operator[](const BYTE byte);
  double operator[](const BYTE byte) const;

  // chi-square distance, would be more elegant
  // to have some vectorized operations for pow() and / !
  friend double operator-(const hist &lhs, const hist &rhs) {
    double dist = 0.0;
    for (const auto &element : lhs.freq) {
      auto ch = element.first;
      dist += pow(lhs[ch] - rhs[ch], 2.0) / (lhs[ch] + rhs[ch]);
    }

    return dist;
  }
};
