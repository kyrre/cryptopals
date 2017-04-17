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

std::string pad(std::string const &input, const size_t extra = 0) {
    static const size_t block_bits = 512;

    uint64_t length = (input.size() + extra) * 8 + 1;
    size_t remainder = length % block_bits;
    size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;

    std::string padding("\x80");
    padding.append(std::string(k/8, '\0'));
    --length;

    for (int i=sizeof(length)-1; i>-1; i--) {
            unsigned char byte = length >> (i*8) & 0xff;
            padding.push_back(byte);
        }

    std::string ret(input+padding);
    return ret;
}

std::string get_pad(std::string const &input, const size_t extra = 0) {
    static const size_t block_bits = 512;

    uint64_t length = (input.size() + extra) * 8 + 1;
    size_t remainder = length % block_bits;
    size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;

    std::string padding("\x80");
    padding.append(std::string(k/8, '\0'));
    --length;

    for (int i=sizeof(length)-1; i>-1; i--) {
            unsigned char byte = length >> (i*8) & 0xff;
            padding.push_back(byte);
        }

    std::string ret(padding);
    return ret;
}
bytearray secret_key("AAAA");

bytearray compute_mac_value(const bytearray& data) {

  SHA1 checksum;
  checksum.update(secret_key.to_str());
  checksum.update(data.to_str());

  return hex::decode(checksum.final());
}

bool authenticate(const bytearray& message, const bytearray& mac) {
  return compute_mac_value(message) == mac;
}

vector<uint32_t> sha1_state(const bytearray& m) {

  uint32_t *digest = reinterpret_cast<uint32_t*>(m.const_ptr());

  vector<uint32_t> d;
  for(size_t i= 0; i < 5; ++i) {
    d.push_back(__builtin_bswap32(digest[i]));
  }

  return d;
}

int main() {

  //const bytearray input("abc");
  //bytearray mac = compute_mac_value(input);

  //assert(authenticate(input, mac) == true);

  //mac[1] ^= 0x5;
  //assert(authenticate(input, mac) == false);

  //const bytearray data("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
  const bytearray data("test");
  bytearray m = compute_mac_value(data);


  vector<uint32_t> state = sha1_state(m);
  SHA1 s(state[0], state[1], state[2], state[3], state[4]);

  assert(hex::decode(s.get_digest()) == m);


  string _data = pad(secret_key.to_str() + data.to_str());

  SHA1 tt;
  tt.update(_data);

  assert(m == hex::decode(tt.get_digest()));

  // buffer optimizatino ruins it

  string fake_message = pad(secret_key.to_str() + data.to_str()) + ";admin=true";

  s.transforms = 1;
  s.update(";admin=true");

  SHA1 fake;
  fake.update(secret_key.to_str() + fake_message);
  string fake_pad = get_pad(secret_key.to_str() + fake_message);
  fake.update(fake_pad);

  string fake_mac = fake.get_digest();

  cout << (authenticate(fake_message, hex::decode(fake_mac)) == true) << endl;


}
