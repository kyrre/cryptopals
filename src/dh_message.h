#pragma once

#include <iostream>

#include "methods/aes.h"
#include "methods/padding.h"

#include "bigint.h"
#include "dh.h"

using namespace std;

class Message {
 public:
  bytearray cipher;
  bytearray iv;

  Message(const bytearray& _cipher, const bytearray& _iv)
      : cipher(_cipher), iv(_iv) {}
};


class Participant {
public:

  static int participant_count;
  int id;

  const size_t block_size = 16;
  virtual ~Participant() {}
  virtual void connect(Participant& p) = 0;
  virtual void init(Participant& dest, const DH& params) = 0;
  virtual void respond(Participant& p) = 0;
  virtual void recv(const Message& message) = 0;
  virtual Message send(const bytearray& text) = 0;


  Participant() {
      id = participant_count++;
  }

  Message build_message(cpp_int s, const bytearray& text) {

    bytearray key = slice(sha1(s), 0, block_size);
    bytearray iv = oracle::aes::random_bytes(block_size);
    bytearray cipher = aes_cbc_encrypt(text, key, block_size, iv);

    Message message(cipher, iv);
    return message;
  }

};

int Participant::participant_count = 0;


class NormalParticipant : public Participant{
public:
  DH params;
  DH remote;

  cpp_int s;

  void connect(Participant& dest) override {
    dest.init(*this, params);
  }

  void respond(Participant& dest) override {
    dest.init(*this, params);
  }

  void init(Participant& dest, const DH& params) override {
    remote = params;
  }

  Message send(const bytearray& text) override {
    s = powm(remote.A, params.a, params.p);
    return build_message(s, text);
  }

  void recv(const Message& message) override {
    s = powm(remote.A, params.a, params.p);

    bytearray key = slice(sha1(s), 0, block_size);
    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));
    cout << plaintext << endl;
  }


};


class Middleman : public Participant {
public:


  vector<bytearray> messages;

  int id_1;
  int id_2;

  DH params;
  DH remote1;
  DH remote2;

  cpp_int s1;
  cpp_int s2;

  void connect(Participant& dest) override {

    id_2 = dest.id;

    DH fake_params;
    fake_params.A = params.p;

    dest.init(*this, fake_params);
  }

  void init(Participant& dest, const DH& params) override {
    if (dest.id == id_2) {
      remote2 = params;
    } else {
      id_1 = dest.id;
      remote1 = params;
    }
  }

  void respond(Participant& dest) override {
    DH fake_params;
    fake_params.A = params.p;
    dest.init(*this, fake_params);
  }

  void recv(const Message& message) override {}

  Message send(const bytearray& text) override {
  }

  void decrypt_intercepted_message(const Message& message) {
    s1 = powm(remote1.p, remote2.a, remote1.p);

    bytearray key = slice(sha1(s1), 0, block_size);
    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));

    messages.push_back(plaintext);
  }

  Message relay(const Message& message) {
    decrypt_intercepted_message(message);
    return message;
  }


};
