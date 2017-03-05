#include "catch.hpp"

#include "hist.h"

TEST_CASE("chi-square", "[histogram]") {
  hist h1 = {{'K', 10.0}};
  hist h2 = {{'K', 4.0}};

  auto dist = h1 - h2;
  auto expected = Approx(2.57143);

  REQUIRE(dist == expected);
}
