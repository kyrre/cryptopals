#pragma once

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "bigint.h"
#include "hex.h"

namespace rsa {

class PrimeGenerator {
 public:
  BIGNUM* r;
  const char* rnd_seed = "random entropy source";

  PrimeGenerator() {
    RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime_ex may fail */
  }

  bigint operator()() {
    r = BN_new();
    BN_generate_prime_ex(r, 512, 0, NULL, NULL, NULL);

    char* s = BN_bn2hex(r);
    bigint q(string("0x") + s);

    BN_free(r);
    free(s);

    return q;
  }
};

bigint _encrypt(bigint m, bigint e, bigint n) {
  bigint c = powm(m, e, n);
  return c;
}

bigint encrypt(const string& plaintext, bigint e, bigint n) {
  bigint m = string_to_bigint(plaintext);
  return _encrypt(m, e, n);
}

bigint _decrypt(bigint c, bigint d, bigint n) {
  bigint m = powm(c, d, n);
  return m;
}

string bigint_to_string(bigint a) {
  string out;
  stringstream ss;

  ss << std::hex << a;
  ss >> out;

  return hex::decode(out).to_str();
}

string decrypt(bigint c, bigint d, bigint n) {
  string out;
  stringstream ss;

  ss << std::hex << _decrypt(c, d, n);
  ss >> out;

  return hex::decode(out).to_str();
}

class RSA {
 public:
  bigint p;
  bigint q;
  bigint n;

  bigint et;
  bigint e;
  bigint d;

  PrimeGenerator gen;

  RSA() {
    p = gen();
    q = gen();
    n = p * q;

    et = (p - 1) * (q - 1);
    e = 3;
    d = invmod(e, et);
  }

  bigint encrypt(const string& message) {
    return ::rsa::encrypt(message, e, n);
  }

  string decrypt(bigint c) {
    return ::rsa::decrypt(c, d, n);
  }
};
}
