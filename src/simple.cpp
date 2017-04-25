#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include "fs.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "hex.h"
#include "sha1.h"

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

  Message(const bytearray& _cipher, const bytearray& _iv)
      : cipher(_cipher), iv(_iv) {}
};

class Entity {
 public:
  const size_t block_size = 16;

  cpp_int s;
  cpp_int p;
  cpp_int g;
  cpp_int A;
  cpp_int a;
  cpp_int external_A;

  void initialize_exchange(Entity& dest) {
    initialize_exchange(dest, p, g, A);
  }

  void initialize_exchange(Entity& dest, cpp_int _p, cpp_int _g, cpp_int _A) {
    dest.p = _p;
    dest.g = _g;
    dest.external_A = _A;
  }

  void set_param() {
    s = powm(external_A, a, p);
  }


  //Message encode_message(const bytearray& message_text) {
  //}

  Message send(const bytearray& message_text) {
    bytearray key = slice(sha1(s), 0, block_size);
    bytearray iv = oracle::aes::random_bytes(block_size);
    bytearray cipher = aes_cbc_encrypt(message_text, key, block_size, iv);

    Message message(cipher, iv);

    return message;
  }

  void recv(const Message& message) {
    bytearray key = slice(sha1(s), 0, block_size);

    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));

    cout << plaintext << endl;

  }

  void relay(Entity& dest, const Message& message) {

    bytearray key = slice(sha1(s), 0, block_size);

   // bytearray plaintext = strip_pkcs(
   //     aes_cbc_decrypt(message.cipher, key, block_size, message.iv));



    dest.recv(message);
  }
};

class Participant : public Entity {
 public:
  Participant(cpp_int p, cpp_int g, cpp_int A, cpp_int a) {
    this->p = p;
    this->g = g;
    this->A = A;
    this->a = a;
  }

  Participant(cpp_int A, cpp_int a) {
    this->A = A;
    this->a = a;
  }

  Participant() = default;

  void ack(Participant& dest) {
    ack(dest, this->A);
  }

  void ack(Participant& dest, cpp_int A) {
    dest.external_A = A;
  }

};

int main() {
  DH param;

  Participant A(param.p, param.g, param.A, param.a);
  Participant B(param.B, param.b);

  bytearray a_message("A test");
  bytearray b_message("B test");


  Participant M;

  A.initialize_exchange(M);
  M.set_param();

  M.initialize_exchange(B, M.p, M.g, M.p);
  B.set_param();

  B.ack(M);

  M.ack(A, M.p);
  A.set_param();

  Message m = A.send(a_message);
  M.relay(B, m);

  Message mb = B.send(b_message);
  M.relay(A, mb);

}
