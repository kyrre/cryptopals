#include <catch.hpp>
#include <fstream>

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

  cryptopals::Signature signature(bigint("0x60019cacdc56eedf8e080984bfa898c8c5c419a8"),
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
  const string fingerprint = "0954EDD5E0AFE5542A4ADF012611A91912A3EC16";
  for (bigint k = 0; k <= bigint(0xffff); ++k) {
    bigint x = unknown.recover(signature, k, hash_value);

    if (x < 0) {
      continue;
    }

    string fp = hex::encode(sha1(to_str(x)).to_str());

    if (fingerprint == fp) {
      values = make_pair(x, k);
      break;
    }
  }

  REQUIRE(bigint("0x15FB2873D16B3E129FF76D0918FD7ADA54659E49") == values.first);
}

TEST_CASE("Repeated nonce") {

  const string filename = "../tests/data/44.txt";
  vector<cryptopals::SignedMessage> messages;

  ifstream iss(filename);
  for (string line; getline(iss, line);) {
    string msg = cryptopals::parse_line(line);

    getline(iss, line);
    bigint s(cryptopals::parse_line(line));

    getline(iss, line);
    bigint r(cryptopals::parse_line(line));


    cryptopals::Signature sig(r, s);

    getline(iss, line);
    bigint m("0x" + cryptopals::parse_line(line));


    messages.push_back(cryptopals::SignedMessage(sig, m, msg));
  }

  bigint y(
      "0x2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
      "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
      "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
      "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
      "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
      "2971c3de5084cce04a2e147821");

  cryptopals::DSA dsa;
  dsa.y = y;

  string match;
  for (size_t i = 0; i < messages.size(); ++i) {
    for(size_t j = i+1; j < messages.size(); ++j) {

      const cryptopals::SignedMessage a = messages[i];
      const cryptopals::SignedMessage b = messages[j];


      // check for repeated nonce
      if (a.sig.r != b.sig.r) {
        continue;
      }

      bigint k = recover(a, b, dsa.q);
      bigint x = dsa.recover(a.sig, k, a.m);

      if (powm(dsa.g, x, dsa.p) == y) {
        match = hex::encode(sha1(to_str(x)).to_str());
        continue;
      }
    }
  }

  assert(match == "CA8F6F7C66FA362D40760D135B763EB8527D3D52");

}

TEST_CASE("Parameter tampering") {

  string message = "test";
  cryptopals::DSA dsa;
  dsa.g = 0;

  bigint H = string_to_bigint(cryptopals::sha2_trunc(message));

  cryptopals::Signature sig = dsa.sign(message, H);
  REQUIRE(dsa.validate(sig, H) == true);


  bigint broken = string_to_bigint(cryptopals::sha2_trunc("test2"));
  REQUIRE(dsa.validate(sig, broken) == true);

  dsa.g = dsa.p + 1;
  sig = dsa.sign(message, H);

  cryptopals::Signature fake_sig = generate_signature(dsa);

  assert(dsa.validate(fake_sig, H) == true);




}
