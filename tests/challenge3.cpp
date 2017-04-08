#include <catch.hpp>

#include "fs.h"
#include "utils.h"
#include "bytearray.h"
#include "oracle/aes.h"
#include "oracle/profile.h"
#include "methods/padding.h"
#include "methods/aes.h"
#include "analysis/aes.h"


TEST_CASE("Task 17") {


  using namespace oracle::aes;


  bytearray message = bytearray(16, 'B');
  bytearray pt(16, 'A');
  pt = pt + message + message;

  bytearray cipher = aes_cbc_encrypt(pt, key);

  REQUIRE(cbc_attack_block(cipher, 1) == message);
}


TEST_CASE("Task 18") {


}
