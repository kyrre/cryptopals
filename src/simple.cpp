#include <algorithm>
#include <chrono>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include "fs.h"
#include "mt19937.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "sha1.h"
#include "hex.h"


using std::vector;
using std::cout;
using std::endl;

using namespace oracle::aes;


string secret_key = "AAAA";
SHA1 clone(const string& hash_value) {
  vector<uint32_t> state = sha1_state(hex::decode(hash_value));
  SHA1 s(state[0], state[1], state[2], state[3], state[4]);

  return s;
}

int main() {

  const string data = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
  string m = compute_mac_value(data);

  SHA1 s = clone(m);

  assert(s.get_digest() == m);

  string _data = pad(secret_key + data);

  SHA1 tt;
  tt.update(_data);

  assert(m == tt.get_digest());
  assert(s.get_digest() == tt.get_digest());


  // buffer optimization ruins it
  string o_pad = get_pad(secret_key + data);
  string fake_message = secret_key + data + o_pad + ";admin=true";
  string fake_pad = get_pad(fake_message);

  SHA1 fake;
  fake.update(fake_message);
  string mmm = fake.final();


  s.update(";admin=true");
  s.update(fake_pad);


  assert(s.get_digest() == mmm);


  string sx = compute_mac_value(data + o_pad + ";admin=true");

  cout << sx
       << endl
       << mmm
       << endl
       << s.get_digest()
       << endl;


  //cout << (authenticate(fake_message, s_mac) == true) << endl;
  //cout << (authenticate(fake_message, hex::decode(fake_mac)) == true) << endl;


}
