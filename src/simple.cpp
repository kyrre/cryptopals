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



class Message {
  public:
    bytearray cipher;
    bytearray iv;

    Message(const bytearray& _cipher, const bytearray& _iv) :
      cipher(_cipher), iv(_iv) {}
};



class Participant{
public:

  cpp_int s;
  cpp_int p;
  cpp_int g;
  cpp_int A;
  cpp_int a;
  cpp_int B;
  cpp_int b;

  const size_t block_size = 16;

  Participant(cpp_int _p, cpp_int _g, cpp_int _A, cpp_int _a) :
    p(_p), g(_g), A(_A), a(_a) {}

  Participant() = default;

  Participant(cpp_int _B, cpp_int _b) : B(_B), b(_b) {}

  void init(Participant& B) {
    B.p = p;
    B.g = g;
    B.A = A;
    B.s = powm(B.A, B.b, B.p);
  }

  void ack(Participant& A) {
    A.B = B;
    A.s = powm(A.B, A.a, A.p);
  }

  void send(Participant& dest, const bytearray& message_text) {

    bytearray key = slice(sha1(s), 0, block_size);
    bytearray iv = oracle::aes::random_bytes(block_size);
    bytearray cipher = aes_cbc_encrypt(message_text, key, block_size, iv);

    Message message(cipher, iv);

    dest.recv(message);
  }

  void recv(const Message& message) {
    bytearray key = slice(sha1(s), 0, block_size);

    bytearray plaintext =
      aes_cbc_decrypt(message.cipher, key, block_size, message.iv);


    cout << plaintext << endl;
  }

};



int main() {
  DH param;

  bigint s  = powm(param.B,  param.a, param.p);
  bigint _s = powm(param.A, param.b, param.p);
  bytearray A_message("A_message");
  bytearray B_message("B_message");

  bytearray hash = slice(sha1(s), 0, 16);
  aes_cbc_encrypt(A_message, hash, 16, oracle::aes::random_bytes(16));


  assert(s == _s);

  Participant A(param.p, param.g, param.A, param.a);
  Participant B(param.B, param.b);


  A.init(B);
  B.ack(A);

  A.send(B, A_message);

}
