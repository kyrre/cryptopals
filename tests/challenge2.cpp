#include <catch.hpp>

#include "aes.h"
#include "bytearray.h"
#include "encoding.h"
#include "fs.h"

TEST_CASE("Task 9") {

  bytearray bytes("YELLOW SUBMARINE");
  bytearray expected("YELLOW SUBMARINE\x04\x04\x04\x04");

  REQUIRE(pkcs_padding(bytes, 20) == expected);
}

TEST_CASE("AES Encrypt/Decrypt") {

  bytearray ciphertext =
      read_base64("/home/kyrre/projects/cryptopals/tests/data/7.txt");

  bytearray key("YELLOW SUBMARINE");
  REQUIRE(aes_ebc_encrypt(aes_ebc_decrypt(ciphertext, key), key) == ciphertext);
}

TEST_CASE("AES CBC MODE") {

  string expected = read("../tests/data/regression_7.txt");
  bytearray ciphertext =
      read_base64("/home/kyrre/projects/cryptopals/tests/data/10.txt");
  bytearray key("YELLOW SUBMARINE");

  REQUIRE(aes_cbc_decrypt(ciphertext, key) == expected);
}
