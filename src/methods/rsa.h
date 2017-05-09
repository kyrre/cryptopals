#pragma once

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "bigint.h"
#include "dh.h"
#include "hex.h"

using namespace rapidjson;
using namespace std;

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

  bigint _decrypt(bigint c) {
    return ::rsa::_decrypt(c, d, n);
  }
};

string stringify(const Document& d) {
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);

  return buffer.GetString();
}

Document parse(const string& json_str) {
  Document d;
  d.Parse(json_str.c_str());

  return d;
}

class SomeServer {
 public:
  boost::hash<bigint> hasher;
  set<size_t> hash_values;

  rsa::RSA keys;

  SomeServer(rsa::RSA _keys) : keys(_keys) {}

  bigint decrypt(bigint cipher) {
    size_t hash_value = hasher(cipher);
    bool exists = hash_values.find(hash_value) != hash_values.end();

    if (exists) {
      throw std::overflow_error("Duplicate cipher!");
    } else {
      hash_values.insert(hash_value);
      keys._decrypt(cipher);
    }
  }
};

string no_padding_attack(bigint C, rsa::RSA keys) {
  bigint N = keys.n;
  bigint E = keys.e;

  bigint S = DiffieHellman::gen() % N;

  bigint c_prime = powm(S, E, N);
  c_prime = c_prime * C % N;

  bigint S_inverse = invmod(S, N);
  bigint P = keys._decrypt(c_prime) * S_inverse % N;

  return rsa::bigint_to_string(P);
}
}
