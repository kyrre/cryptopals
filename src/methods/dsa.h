#pragma once

#include "bigint.h"


namespace cryptopals {
string sha2_trunc(const string& m) {
  return sha256(m).substr(0, 40);
}

using Signature = pair<bigint, bigint>;

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

  pair<bigint, bigint> sign(const string& message, bigint H) {

    bigint k = DiffieHellman::gen() % q;

    bigint r = powm(g, k, p);
    r = r % q;

    bigint inv_k = invmod(k, q);
    bigint s = (inv_k * (H + x * r)) % q;

    return make_pair(r, s);
  }

  bool validate(pair<bigint, bigint> sig, bigint H) {
    bigint r = sig.first;
    bigint s = sig.second;

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
    bigint r = sig.first;
    bigint s = sig.second;
    bigint r_inv = invmod(r, q);

    return ((s * k - H) * r_inv) % q;
  }
};
}
