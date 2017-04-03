#include "hist.h"
#include <assert.h>

double& hist::operator[](const BYTE byte) {
  if (!freq.count(byte)) {
    freq[byte] = 0.0;
  }

  return freq[byte];
}

double hist::operator[](const BYTE byte) const {
  double ret = 0.0;

  if (freq.count(byte)) {
    ret = freq.at(byte);
  }

  return ret;
}

hist::hist(initializer_list<pair<BYTE const, double>> list) : freq(list) {}
hist::hist(const hist&& rhs) : freq(move(rhs.freq)){};

hist& hist::operator=(const hist&& rhs) {
  assert(this != &rhs);
  freq = move(rhs.freq);

  return *this;
}
