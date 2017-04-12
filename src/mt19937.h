#pragma once

#include <random>

using namespace std;

class MT19937 {
 public:
  const int w = 32;
  const int n = 624;
  const int m = 397;
  const int r = 31;

  const int a = 0x9908B0DF;

  const int u = 11;
  const int d = 0xFFFFFFFF;

  const int s = 7;
  const int b = 0x9D2C5680;

  const int t = 15;
  const int c = 0xEFC60000;

  const int l = 18;

  const int f = 1812433253;

  vector<int> MT;
  int index = n + 1;

  const int lower_mask = (1 << r) - 1;
  const int upper_mask = ~lower_mask;

  MT19937(int seed);

  int operator()();
  void seed_mt(int seed);

  void twist();
  int extract_number();
};
