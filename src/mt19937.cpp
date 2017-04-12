#include "mt19937.h"

MT19937::MT19937(int seed) : MT(n) {
  seed_mt(seed);
}

int MT19937::operator()() {
  return extract_number();
}

void MT19937::seed_mt(int seed) {
  index = n;
  MT[0] = seed;

  for (int i = 1; i < n; ++i) {
    MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i);
  }
}

void MT19937::twist() {
  for (int i = 0; i < n; ++i) {
    int x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask);
    int xA = x >> 1;
    if ((x % 2) != 0) {
      xA = xA ^ a;
    }
    MT[i] = MT[(i + m) % n] ^ xA;
  }
  index = 0;
}

int MT19937::extract_number() {
  int i = index;
  if (index >= n) {
    twist();
    i = index;
  }

  int y = MT[i];
  y = y ^ ((y >> u) & d);
  y = y ^ ((y << s) & b);
  y = y ^ ((y << t) & c);
  y = y ^ (y >> l);

  index = index + 1;
  return y;
}
