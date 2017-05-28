#include <cppcodec/base64_default_rfc4648.hpp>

bool parity(bigint c, rsa::RSA& keys) {
  bigint pt = keys._decrypt(c);
  return ((pt % 2) == 0);
}

int main() {
  // rsa::RSA keys;

  // const string data =
  // "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
  // const string plaintext = bytearray(base64::decode(data)).to_str();

  // const bigint cipher = keys.encrypt(plaintext);
  // const bigint n = keys.n;
  // const bigint e = keys.e;
  // const bigint tmp = powm(bigint(2), e, n);

  // bigint c = cipher;

  // bigint start = 0;
  // bigint stop = n;

  // bigint real_pt_expected = string_to_bigint(plaintext);

  // while(start != stop) {
  //  c = c * tmp % n;
  //  bool even = parity(c, keys);

  //  if (even) {
  //    stop = (start + stop) / 2;
  //  } else {
  //    start = (start + stop) /  2;
  //  }
  //}

  // string pt = hex::decode(to_str(stop)).to_str();

  // assert(pt == plaintext);
