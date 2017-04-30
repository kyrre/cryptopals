#include <sstream>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>

#include "bigint.h"
#include "hex.h"
#include "sha1.h"

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
