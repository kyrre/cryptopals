#include "mt19937.h"

#include <vector>

MT19937::MT19937(unsigned int seed) : MT(n) {
  seed_mt(seed);
}

unsigned int MT19937::operator()() {
  return extract_number();
}

void MT19937::seed_mt(unsigned int seed) {
  index = n;
  MT[0] = seed;

  for (unsigned int i = 1; i < n; ++i) {
    MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i);
  }
}

void MT19937::twist() {
  for (unsigned int i = 0; i < n; ++i) {
    unsigned int x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask);
    unsigned int xA = x >> 1;
    if ((x % 2) != 0) {
      xA = xA ^ a;
    }
    MT[i] = MT[(i + m) % n] ^ xA;
  }
  index = 0;
}

unsigned int MT19937::extract_number() {
  int i = index;
  if (index >= n) {
    twist();
    i = index;
  }

  unsigned int y = MT[i];
  y = y ^ ((y >> u) & d);
  y = y ^ ((y << s) & b);
  y = y ^ ((y << t) & c);
  y = y ^ (y >> l);

  index = index + 1;
  return y;
}

unsigned int MT19937::untemper(unsigned int y) {
  unsigned y0, y1, y2, y3;

  // copied from reschly. did the first one but threw in the towel
  y3 = (y & 0xffffc000);

  // low 14 = (high 14 >> 18) ^ low 14
  y3 |= ((y >> 18) ^ (y & 0x3fff));

  // y3 := y2 xor (left shift by 15 bits(y2) and (4022730752)) // 0xefc60000
  // bits not masked by xor carry over from y2 to y3 and vice-versa
  y2 = (y3 & 0x1039ffff);

  // now know the low 17 bits of y2, so strip off the xor
  y2 |= ((y3 ^ ((y2 << 15) & c)) & 0xfffe0000);

  // y2 := y1 xor (left shift by 7 bits(y1) and (2636928640)) // 0x9d2c5680
  // Bits 0-6 carry over:
  y1 = y2 & 0x7f;

  // recover bits 7-13 by masking off xor of 0-6
  y1 |= ((((y1 << 7) & b) ^ y2) & (0x7f << 7));

  // recover bits 14-20 by maksing off xor of 7-13
  y1 |= ((((y1 << 7) & b) ^ y2) & (0x7f << 14));

  // recover bits 21-27 by masking off xor of 14-20
  y1 |= ((((y1 << 7) & b) ^ y2) & (0x7f << 21));

  // recover bits 28-31 by masking off xor if bits 21-24
  y1 |= ((((y1 << 7) & b) ^ y2) & 0xf0000000);

  // y1 := y0 xor (right shift by 11 bits(y0))
  // high 11 bits carry over:
  y0 = (y1 & 0xffe00000);
  // recover next 11 bits
  y0 |= (((y0 >> 11) ^ y1) & 0x001ffc00);

  // recover last 10
  y0 |= (((y0 >> 11) ^ y1) & 0x3ff);

  return y0;
}

MT19937::MT19937(vector<unsigned int>& mt_state) : MT(mt_state){};

vector<unsigned int> generate_sample(MT19937& mt) {
  vector<unsigned int> b;
  for (size_t i = 0; i < 32; ++i) {
    b.push_back(mt());
  }
  return b;
}

pair<unsigned int, bool> brute_force_seed(vector<unsigned int>& sample,
                                          unsigned int start,
                                          unsigned int end) {
  unsigned int seed_guess;
  bool found_seed = false;
  for (seed_guess = start; seed_guess < end && !found_seed; ++seed_guess) {
    MT19937 mt(seed_guess);

    if (sample == generate_sample(mt)) {
      found_seed = true;
    }
  }

  return make_pair(seed_guess, found_seed);
}
