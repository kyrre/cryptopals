#include <catch.hpp>

#include "bytearray.h"
#include "fs.h"
#include "methods/aes.h"
#include "oracle/aes.h"
#include "utils.h"

TEST_CASE("Task 9") {
  bytearray bytes("YELLOW SUBMARINE");
  bytearray expected("YELLOW SUBMARINE\x04\x04\x04\x04");

  REQUIRE(pkcs_padding(bytes, 20) == expected);
}

TEST_CASE("AES Encrypt/Decrypt") {
  bytearray ciphertext = read_base64("../tests/data/7.txt");

  bytearray key("YELLOW SUBMARINE");
  REQUIRE(aes_ebc_encrypt(aes_ebc_decrypt(ciphertext, key), key) == ciphertext);
}

TEST_CASE("AES CBC MODE") {
  string expected = read("../tests/data/regression_7.txt");
  bytearray ciphertext = read_base64("../tests/data/10.txt");
  bytearray key("YELLOW SUBMARINE");

  REQUIRE(aes_cbc_decrypt(ciphertext, key) == expected);
}

TEST_CASE("AES CBC MODE ENCRYPT/DECRYPT") {
  bytearray plaintext = oracle::aes::random_bytes(500 * 16);
  bytearray key = oracle::aes::random_aes_key();

  bytearray ciphertext = aes_cbc_encrypt(plaintext, key);

  REQUIRE(aes_cbc_decrypt(ciphertext, key) == plaintext);
}
