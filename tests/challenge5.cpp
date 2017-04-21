#include <catch.hpp>
#include "dh.h"


TEST_CASE("Diffie-Hellman") {
  DH param;

  bigint s  = powm(param.B,  param.a, param.p);
  bigint _s = powm(param.A, param.b, param.p);

  REQUIRE(s == _s);
}


