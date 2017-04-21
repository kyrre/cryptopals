#include "hex.h"
#include "bytearray.h"

namespace hex {
bytearray decode(const string& s) {
  bytearray bytes;
  size_t n = s.length() - 2;

  for (size_t i = 0; i <= n; i += 2) {
    bytes.push_back(
        static_cast<uint8_t>(strtol(s.substr(i, 2).c_str(), NULL, 16)));
  }

  return bytes;
}

string encode(const string& input) {
  static const char* const lut = "0123456789ABCDEF";
  size_t len = input.length();

  string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; ++i) {
    const unsigned char c = input[i];
    output.push_back(lut[c >> 4]);
    output.push_back(lut[c & 15]);
  }
  return output;
}

string encode(unsigned char c) {
  static const char* const lut = "0123456789abcdef";
  string output;
  output.reserve(2);
  output.push_back(lut[c >> 4]);
  output.push_back(lut[c & 15]);

  return output;
}
}
