#include "hamming.h"
#include "bytearray.h"
#include <limits>

inline size_t popcount(const BYTE a, const BYTE b) {
  const int NUM_BITS = 8;

  size_t diff = 0;
  const BYTE x = a ^ b;
  for (size_t i = 0; i < NUM_BITS; i += 1) {
    if (((x >> i) & 0x1) == 0x1) {
      ++diff;
    }
  }
  return diff;
}

size_t hamming(const bytearray& a, const bytearray& b) {
  if (a.size() != b.size()) {
    return std::numeric_limits<BYTE>::max();
  }

  size_t dist = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) {
      dist += popcount(a[i], b[i]);
    }
  }
  return dist;
}
