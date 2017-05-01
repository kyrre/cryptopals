#include <sstream>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>



#include "bigint.h"
#include "hex.h"
#include "sha1.h"
#include "picosha2.h"

string to_str(cpp_int i) {
  stringstream ss;
  ss << i;

  string ret;
  ss >> ret;

  return ret;
}

bytearray sha1(const string& s) {
  SHA1 h;
  h.update(s);

  return hex::decode(h.final());
}

bytearray sha1(cpp_int i) {
  return sha1(to_str(i));
}

string sha256(const string& a) {
  return picosha2::hash256_hex_string(a);
}


string sha256(cpp_int a) {
  return sha256(hex::decode(to_str(a)).to_str());
}

string hmac_sha256(bigint _key, bigint _message) {
  bytearray key(to_str(_key));
  string message = hex::decode(to_str(_message)).to_str();

  const size_t block_size = 16;

  if (key.size() > block_size) {
    key = bytearray(sha256(key.to_str()));
  }
  if (key.size() < block_size) {
    key = key + bytearray(0x00, block_size - key.size());
  }

  bytearray o_key_pad = bytearray(0x5c, block_size) ^ key;
  bytearray i_key_pad = bytearray(0x36, block_size) ^ key;

  return sha256(o_key_pad.to_str() +
                   sha256(i_key_pad.to_str() + message));
}


