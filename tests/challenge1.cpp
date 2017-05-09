#include <boost/functional/hash.hpp>
#include <catch.hpp>
#include <tuple>

#include "analysis/aes.h"
#include "analysis/frequency.h"
#include "analysis/xor.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "bytearray.h"
#include "fs.h"
#include "hex.h"
#include "utils.h"

TEST_CASE("Task 1") {
  auto bytes = hex::decode(
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120"
      "706f69736f6e6f7573206d757368726f6f6d");
  auto expected = bytearray("I'm killing your brain like a poisonous mushroom");

  REQUIRE(bytes == expected);
}

TEST_CASE("Task 2") {
  auto input = hex::decode("1c0111001f010100061a024b53535009181c");
  auto key = hex::decode("686974207468652062756c6c277320657965");

  auto expected = hex::decode("746865206b696420646f6e277420706c6179");

  REQUIRE((input ^ key) == expected);
}

TEST_CASE("Task 3") {
  auto cipher = hex::decode(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

  auto results = frequency_analysis(cipher);

  REQUIRE(results.key == 'X');
  REQUIRE((cipher ^ results.key) ==
          bytearray("Cooking MC's like a pound of bacon"));
}

TEST_CASE("Task 4") {
  const vector<string> lines = read_lines("../tests/data/4.txt");

  bytearray expected{"Now that the party is jumping\n"};

  REQUIRE(find_xor_encrypted_line(lines).second == expected);
}

TEST_CASE("Task 5") {
  const bytearray plaintext(
      "Burning 'em, if you ain't quick and nimble\n"
      "I go crazy when I hear a cymbal");
  const bytearray key("ICE");

  const bytearray expected = hex::decode(
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d62"
      "3d63343c2a26226324272765272"
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692"
      "b20283165286326302e27282f");

  REQUIRE((plaintext ^ key) == expected);
}

TEST_CASE("Task 7") {
  string expected = read("../tests/data/regression_7.txt");

  bytearray ciphertext = read_base64("../tests/data/7.txt");

  bytearray key("YELLOW SUBMARINE");

  REQUIRE(strip_pkcs(aes_ebc_decrypt(ciphertext, key)) == expected);
}

TEST_CASE("Task 8") {
  const vector<string> lines = read_lines("../tests/data/8.txt");

  bytearray expected = hex::decode(
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f"
      "6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d465"
      "97949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154"
      "789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0"
      "ab51b29933f2c123c58386b06fba186a");

  REQUIRE(aes::find_ecb_encrypted_line(lines) == expected);
}
