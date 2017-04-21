#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <thread>
#include <unordered_map>
#include <random>

#include "fs.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "sha1.h"
#include "hex.h"


#include "dh.h"



class Participant{
public:

  cpp_int s;
  cpp_int a;
  cpp_int b;
  cpp_int p;
  cpp_int g;
  cpp_int A;
  cpp_int B;

  Participant(cpp_int _p, cpp_int _g, cpp_int _A) :
    p(_p), g(_g), A(_A) {}


  void init(Participant& B, cpp_int p, cpp_int g, cpp_int A) {
    B.p = p;
    B.g = p;
    B.A = A;
    B.s = powm(B.A, B.b, B.p);
  }

  void ack(Participant& A) {
    A.B = B;
    A.s = powm(A.B, A.a, A.p);
  }

  void send(Participant& dest, const bytearray& message) {

    bytearry key = slice(sha1(s), 0, 16);
    byterray m = aes_cbc_encrypt(message, key, 16, oracle::aes::random_bytes(16));

    //AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv

  }
};


std::string to_str(cpp_int i) {
    std::stringstream ss;
    ss << i;

    std::string ret;
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

int main() {
  DH param;

  bigint s  = powm(param.B,  param.a, param.p);
  bigint _s = powm(param.A, param.b, param.p);
  bytearray A_message("A_message");
  bytearray B_message("B_message");


  bytearray hash = slice(sha1(s), 0, 16);
  aes_cbc_encrypt(A_message, hash, 16, oracle::aes::random_bytes(16));

  cout << hash << endl;

  assert(s == _s);
}
