#include <catch.hpp>

#include "fs.h"
#include "utils.h"
#include "bytearray.h"
#include "oracle/aes.h"
#include "oracle/profile.h"
#include "methods/padding.h"
#include "methods/aes.h"
#include "analysis/aes.h"


TEST_CASE("Task 9") {
  bytearray bytes("YELLOW SUBMARINE");
  bytearray expected("YELLOW SUBMARINE\x04\x04\x04\x04");

  REQUIRE(pkcs(bytes, 20) == expected);
}

TEST_CASE("AES Encrypt/Decrypt") {
  bytearray ciphertext = read_base64("../tests/data/7.txt");

  bytearray key("YELLOW SUBMARINE");
  bytearray plaintext = aes_ebc_decrypt(ciphertext, key);
  bytearray ct = aes_ebc_encrypt(strip_pkcs(plaintext), key);

  REQUIRE(ct == ciphertext);
}

TEST_CASE("AES CBC MODE") {
  string expected = read("../tests/data/regression_7.txt");
  bytearray ciphertext = read_base64("../tests/data/10.txt");
  bytearray key("YELLOW SUBMARINE");

  REQUIRE(strip_pkcs(aes_cbc_decrypt(ciphertext, key)) == expected);
}

TEST_CASE("AES CBC MODE ENCRYPT/DECRYPT") {

  const size_t block_size = 16;
  bytearray plaintext = oracle::aes::random_bytes(7);
  bytearray key = oracle::aes::random_aes_key();
  bytearray iv = oracle::aes::random_bytes(block_size);

  bytearray ciphertext = aes_cbc_encrypt(plaintext, key, block_size, iv);
  bytearray pt = aes_cbc_decrypt(ciphertext, key, block_size, iv);

  REQUIRE(strip_pkcs(pt) == plaintext);
}

TEST_CASE("Byte-at-a-time ECB (Simple)") {
  using namespace aes;
  using namespace oracle::aes;
  string s = read("../tests/data/regression_12.txt");

  REQUIRE(decrypt(encryption_oracle) == s);

}

TEST_CASE("Byte-at-a-time ECB (Harder)") {
  using namespace aes;
  using namespace oracle::aes;

  string s = read("../tests/data/regression_14.txt");

  REQUIRE(decrypt_prepad(encryption_oracle_prepad) == s);
}


TEST_CASE("Profile") {
  using namespace aes;
  using namespace oracle::aes;

  Profile p = change_profile_role("foo@bar", "admin");
  string expected = "admin";

  REQUIRE(strip_pkcs(p.role) == expected);

}

TEST_CASE("Strip Padding") {

  bytearray one("ICE ICE BABY\x04\x04\x04\x04");
  string expected = "ICE ICE BABY";

  REQUIRE(strip_pkcs(one) == expected);

}

TEST_CASE("Bit Flipping CBC") {
  using namespace oracle::aes;
  auto cipher = bit_flipping_cbc();
  REQUIRE(decrypt_oracle_cbc(cipher) == true);
}
