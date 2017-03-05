#include "catch.hpp"

#include "bytearray.h"
#include "hamming.h"

TEST_CASE("Hamming") {

  bytearray a("this is a test");
  bytearray b("wokka wokka!!!");

  REQUIRE(hamming(a, b) == 37);
}
