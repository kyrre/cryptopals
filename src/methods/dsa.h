#pragma once

#include "bigint.h"
#include "dh.h"

namespace cryptopals {
string sha2_trunc(const string& m) {
  return sha256(m).substr(0, 40);
}

class Signature {
 public:
  bigint r;
  bigint s;
  Signature(bigint r, bigint s) : r{r}, s{s} {}
};

class DSA {
 public:
  bigint p;
  bigint q;
  bigint g;
  bigint x;
  bigint y;
  bigint k;

  DSA(bigint p = bigint("0x800000000000000089e1855218a0e7dac38136ffafa72eda7"
                        "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
                        "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
                        "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
                        "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
                        "1a584471bb1"),
      bigint q = bigint("0xf4f47f05794b256174bba6e9b396a7707e563c5b"),
      bigint g = bigint("0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
                        "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
                        "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
                        "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
                        "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
                        "9fc95302291"))
      : p{p}, q{q}, g{g} {
    x = DiffieHellman::gen() % q;
    y = powm(g, x, p);
  }

  Signature sign(const string& message, bigint H) {
    bigint k = DiffieHellman::gen() % q;

    bigint r = powm(g, k, p);
    r = r % q;

    bigint inv_k = invmod(k, q);
    bigint s = (inv_k * (H + x * r)) % q;

    return Signature(r, s);
  }

  bool validate(Signature& sig, bigint H) {
    bigint r = sig.r;
    bigint s = sig.s;

    if (r > q && s > q) {
      return false;
    }

    bigint w = invmod(s, q);
    bigint u1 = (H * w) % q;
    bigint u2 = (r * w) % q;

    bigint v_tmp = powm(y, u2, p);
    bigint v = powm(g, u1, p);
    v = (v * v_tmp) % p;
    v = v % q;

    return v == r;
  }

  bigint recover(Signature sig, bigint k, bigint H) {
    bigint r = sig.r;
    bigint s = sig.s;
    bigint r_inv = invmod(r, q);

    return (subm(s * k, H, q) * r_inv) % q;
  }
};

Signature generate_signature(DSA& dsa, bigint z = 10) {
  bigint r = powm(dsa.y, z, dsa.p);
  r = r % dsa.q;

  bigint s = invmod(z, dsa.q);
  s = (s * r) % dsa.q;

  return Signature(r, s);
}

string parse_line(const string& line) {
  vector<string> tokens;
  boost::split(tokens, line, boost::is_any_of(":"));

  string data = tokens[1].substr(1, tokens[1].size() - 1);

  return data;
}

class SignedMessage {
 public:
  Signature sig;
  bigint m;
  string message;

  SignedMessage(Signature sig, bigint m, const string& message)
      : sig{sig}, m{m}, message{message} {}
};

bigint recover(SignedMessage a, SignedMessage b, bigint q) {
  bigint m1 = a.m;
  bigint m2 = b.m;

  bigint s1 = a.sig.s;
  bigint s2 = b.sig.s;

  bigint tmp1 = subm(m1, m2, q);
  bigint tmp2 = invmod(subm(s1, s2, q), q);
  bigint k = (tmp1 * tmp2) % q;

  return k;
}
}
