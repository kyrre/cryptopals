#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <thread>
#include <unordered_map>

#include "fs.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"
#include "methods/rsa.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "hex.h"
#include "sha1.h"

#include "bigint.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "dh.h"

using namespace rapidjson;
using namespace std;

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

int main() {
  rsa::RSA keys1;

  string s = "{\"name\":\"Tom\"}";

  Document d = parse(s);
  cout << stringify(d) << endl;

  string plaintext = "test";

  bigint C = keys1.encrypt(plaintext);

  cout << no_padding_attack(C, keys1) << endl;
}
