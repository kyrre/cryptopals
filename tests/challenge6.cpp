#include <catch.hpp>

#include "bytearray.h"
#include "dh.h"
#include "dh_message.h"

#include "methods/dsa.h"
#include "methods/rsa.h"

#include "srp_simple/simple.h"
#include "utils.h"

TEST_CASE("DSA") {
  string message = "test";
  cryptopals::DSA dsa;

  bigint H = string_to_bigint(cryptopals::sha2_trunc(message));

  cryptopals::Signature sig = dsa.sign(message, H);
  REQUIRE(dsa.validate(sig, H));

  bigint broken = string_to_bigint(cryptopals::sha2_trunc("test2"));
  REQUIRE(dsa.validate(sig, broken) == false);
}

TEST_CASE("DSA known nonce") {
  string test_message =
      "For those that envy a MC it can be hazardous to your health\n"
      "So be friendly, a matter of life and death, just like a etch-a-sketch\n";

  cryptopals::Signature signature =
      make_pair(bigint("0x60019cacdc56eedf8e080984bfa898c8c5c419a8"),
                bigint("0x961f2062efc3c68db965a90c924cf76580ec1bbc"));

  bigint y(
      "0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
      "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
      "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
      "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
      "bb283e6633451e535c45513b2d33c99ea17");

  cryptopals::DSA unknown;
  unknown.y = y;

  bigint hash_value = string_to_bigint(sha1(test_message).to_str());

  REQUIRE(unknown.validate(signature, hash_value));
  REQUIRE(unknown.validate(signature, hash_value + 1) == false);

  pair<bigint, bigint> values;
  string fingerprint = "0954edd5e0afe5542a4adf012611a91912a3ec16";
  for (bigint k = 0; k <= bigint(0xffff); ++k) {
    bigint x = unknown.recover(signature, k, hash_value);

    if (x < 0) {
      continue;
    }

    string fp = hex::encode(sha1(to_str(x)).to_str());
    std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);

    if (fingerprint == fp) {
      values = make_pair(x, k);
      break;
    }
  }

  REQUIRE(bigint("0x15FB2873D16B3E129FF76D0918FD7ADA54659E49") == values.first);
}
