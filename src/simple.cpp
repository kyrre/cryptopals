#include <algorithm>
#include <chrono>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include "fs.h"
#include "mt19937.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

using namespace std;
using namespace oracle::aes;

void wait_for(int lower = 1, int upper = 10) {
  default_random_engine generator;
  uniform_int_distribution<int> distribution(lower, upper);

  auto duration = chrono::seconds(distribution(generator));

  this_thread::sleep_for(duration);
}

vector<int> generate_sample(MT19937& mt) {
  vector<int> b;
  for (size_t i = 0; i < 32; ++i) {
    b.push_back(mt());
  }
  return b;
}

pair<int, bool> brute_force_seed(vector<int>& sample,
                                 int start = time(NULL) - 1000,
                                 int end = time(NULL)) {
  int seed_guess;
  bool found_seed = false;
  for (seed_guess = start; seed_guess < end && !found_seed; ++seed_guess) {
    MT19937 mt(seed_guess);

    if (sample == generate_sample(mt)) {
      found_seed = true;
    }
  }

  return make_pair(seed_guess, found_seed);
}

void untemper() {}

int main() {
  MT19937 mt(1);
  vector<int> sample = generate_sample(mt);
}
