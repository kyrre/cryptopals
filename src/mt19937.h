#pragma once

#include <random>

using namespace std;

class MT19937 {
 public:
  const unsigned int w = 32;
  const unsigned int n = 624;
  const unsigned int m = 397;
  const unsigned int r = 31;

  const unsigned int a = 0x9908B0DF;

  const unsigned int u = 11;
  const unsigned int d = 0xFFFFFFFF;

  const unsigned int s = 7;
  const unsigned int b = 0x9D2C5680;

  const unsigned int t = 15;
  const unsigned int c = 0xEFC60000;

  const unsigned int l = 18;

  const unsigned int f = 1812433253;

  vector<unsigned int> MT;
  unsigned int index = n + 1;

  const unsigned int lower_mask = (1u << r) - 1u;
  const unsigned int upper_mask = ~lower_mask;

  MT19937(unsigned int seed);
  MT19937(vector<unsigned int>& mt_state);

  unsigned int operator()();
  void seed_mt(unsigned int seed);

  void twist();
  unsigned int extract_number();
  unsigned int untemper(unsigned int y);
};

vector<unsigned int> generate_sample(MT19937& mt);
pair<unsigned int, bool> brute_force_seed(vector<unsigned int>& sample,
                                          unsigned int start = time(NULL) -
                                                               1000,
                                          unsigned int end = time(NULL));
