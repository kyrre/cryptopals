#include <algorithm>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <unordered_map>

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "fs.h"
#include "methods/aes.h"
#include "methods/padding.h"
#include "oracle/aes.h"
#include "oracle/profile.h"

using namespace std;
using namespace oracle::aes;


class MT19937 {
public:
  int w = 32;
  int n = 624;
  int m = 397;
  int r = 31;

  int a = 0x9908B0DF;

  int u = 11;
  int d = 0xFFFFFFFF;

  int s = 7;
  int b = 0x9D2C5680;

  int t = 15;
  int c = 0xEFC60000;

  int l = 18;

  int f = 1812433253;

  vector<int> MT;
  int index = n + 1;

  const int lower_mask = (1 << r) - 1;
  const int upper_mask = ~lower_mask;

  MT19937(int seed) : MT{n} {
    seed_mt(seed);
  }

  int operator()() {
    return extract_number();
  }

  void seed_mt(int seed) {
    index = n;
    MT[0] = seed;

    for(int i = 1; i < n; ++i) {
      MT[i] =  (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i);
    }
  }

	void twist() {
     for (int i = 0; i < n; ++i) {
         int x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask);
         int xA = x >> 1;
         if ((x % 2) != 0) { 
           xA = xA ^ a;
         }
         MT[i] = MT[(i + m) % n] ^ xA;
     }
     index = 0;
 }

  int extract_number() {

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

};

int main() {



	MT19937 mt(1);

  cout << mt() << endl;
  cout << mt() << endl;
  cout << mt() << endl;
  cout << mt() << endl;
  cout << mt() << endl;







}
