#include <catch.hpp>
#include <vector>

#include "mt19937.h"


using namespace std;

TEST_CASE("Clone") {

  MT19937 mt(1);
  vector<unsigned int> sample = generate_sample(mt);
	unsigned int y = 10;

	vector<unsigned int> output;
	for(size_t i = 0; i < 624; ++i) {
		unsigned random_value = mt();
		output.push_back(mt.untemper(random_value));
	}

	MT19937 clone(output);

  for(size_t i = 0; i < 100; ++i) {
	  REQUIRE(clone() == mt());
  }



}


