#include <algorithm>
#include <boost/algorithm/cxx11/all_of.hpp>
#include <cassert>
#include <cppcodec/base64_default_rfc4648.hpp>

#include "bytearray.h"

using namespace std;

bytearray::bytearray(const string &s) : bytes(std::begin(s), std::end(s)) {}
bytearray::bytearray(const BYTES &v) : bytes(std::begin(v), std::end(v)) {}
bytearray::bytearray(bytearray &&rhs) : bytes(move(rhs.bytes)) {}

bytearray &bytearray::operator=(bytearray &&rhs) {
  assert(this != &rhs);

  bytes = move(rhs.bytes);

  return *this;
}

bytearray &bytearray::operator=(const string &s) {
  copy(std::begin(s), std::end(s), back_inserter(bytes));
  return *this;
}

size_t bytearray::size() const { return bytes.size(); }
string bytearray::to_base64() const { return base64::encode(bytes); }
void bytearray::push_back(BYTE b) { bytes.push_back(b); }
bool bytearray::operator==(const bytearray &rhs) { return bytes == rhs.bytes; }

bytearray bytearray::operator^(const bytearray &rhs) const {

  size_t n = rhs.size();

  bytearray result;
  for (size_t i = 0; i < bytes.size(); ++i) {
    result.push_back(bytes[i] ^ rhs[i % n]);
  }

  return result;
}

BYTE bytearray::operator[](size_t index) const { return bytes[index]; }

bytearray bytearray::operator^(const BYTE b) const {
  bytearray result;
  for (const auto byte : bytes) {
    result.push_back(byte ^ b);
  }

  return result;
}

bytearray &bytearray::extend(const bytearray &rhs) {
  bytes.reserve(bytes.size() + distance(rhs.begin(), rhs.end()));
  bytes.insert(bytes.end(), rhs.begin(), rhs.end());

  return *this;
}

bool is_ascii(const bytearray &bytes) {
  return boost::algorithm::all_of(bytes.begin(), bytes.end(),
                                  [](BYTE n) { return isprint(n); });
}
