#include <catch.hpp>

#include "fs.h"
#include "utils.h"
#include "bytearray.h"
#include "oracle/aes.h"
#include "oracle/profile.h"
#include "methods/padding.h"
#include "methods/aes.h"
#include "analysis/aes.h"

#include "sha1.h"

TEST_CASE("CTR edit") {

  using namespace oracle::aes;

  const bytearray ecb_key("YELLOW SUBMARINE");
  const string filename = "../tests/data/25.txt";

  bytearray plaintext = aes_ebc_decrypt(read_base64(filename), ecb_key);
  bytearray ciphertext = aes_ctr(plaintext, key, 0);
  bytearray new_text = bytearray(ciphertext.size(), 'A');
  bytearray keystream = edit(ciphertext, key, 0, new_text) ^ new_text;

  REQUIRE((ciphertext ^ keystream) == plaintext);
}




TEST_CASE("CTR Bit-flipping") {

  using namespace oracle::aes;

  string wanted = ";admin=true;";
  string c(wanted.size(), 'A');

  bytearray cipher = encryption_oracle_ctr(c);
  bytearray keystream = slice(cipher, 38, c.size()) ^ c;
  bytearray diff = keystream ^ bytearray(wanted);

  bytearray new_message = slice(cipher, 0, 38);
  new_message =
      new_message + diff +
      slice(cipher, 38 + diff.size(), cipher.size() - 38 - diff.size());

  REQUIRE(decrypt_oracle_ctr(new_message) == true);
}


TEST_CASE("IV=KEY") {

  using namespace oracle::aes;

  const size_t block_size = 16;
  string chosen_plaintext = string(block_size, 'A') + string(block_size, 'B') + string(block_size, 'C');
  bytearray cipher = encryption_oracle_cbc_same_iv(chosen_plaintext);

  bytearray modified = slice(cipher, 0, block_size);
  modified = modified + bytearray(block_size, 0) + modified;

  bytearray _key(block_size, 0);
  try {
    check_message_compliance(modified);
  } catch (const exception& e) {
    string pt = e.what();
     _key = slice(pt, 0, block_size) ^ slice(pt, 32, block_size);

  }

  REQUIRE(_key == key);
}

TEST_CASE("MAC") {

  const string input = "abc";
  string mac = compute_mac_value(input);

  REQUIRE(authenticate(input, mac) == true);

  mac[1] ^= 0x5;
  REQUIRE(authenticate(input, mac) == false);

}


TEST_CASE("Challenge 29") {
  const string original_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
  const string mac_value = compute_mac_value(original_message);


  auto k = forge_message(mac_value, original_message);

  string fake_message = k.first;
  string fake_mac = k.second;


  REQUIRE(authenticate(fake_message, fake_mac));

}

