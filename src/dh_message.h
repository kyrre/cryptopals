#pragma once

#include <iostream>

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"

#include "bigint.h"
#include "dh.h"
#include "utils.h"

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
  virtual void init(Participant& dest, const DiffieHellman::DH& params) = 0;
  virtual void respond(Participant& p) = 0;
  virtual bytearray recv(const Message& message) = 0;
  virtual Message send(const bytearray& text) = 0;

  Participant() {
    id = participant_count++;
  }

  Message build_message(bigint s, const bytearray& text) {
    bytearray key = slice(sha1(s), 0, block_size);
    bytearray iv = oracle::aes::random_bytes(block_size);
    bytearray cipher = aes_cbc_encrypt(text, key, block_size, iv);

    Message message(cipher, iv);
    return message;
  }
};

int Participant::participant_count = 0;

class NormalParticipant : public Participant {
 public:
  DiffieHellman::DH params;
  DiffieHellman::DH remote;

  bigint s;

  void connect(Participant& dest) override {
    dest.init(*this, params);
  }

  void respond(Participant& dest) override {
    dest.init(*this, params);
  }

  void init(Participant& dest, const DiffieHellman::DH& _remote) override {
    params = DiffieHellman::DH(_remote.p, _remote.g);
    remote = _remote;
  }

  Message send(const bytearray& text) override {
    s = powm(remote.A, params.a, params.p);
    return build_message(s, text);
  }

  bytearray recv(const Message& message) override {
    s = powm(remote.A, params.a, params.p);

    bytearray key = slice(sha1(s), 0, block_size);
    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));

    return plaintext;
  }
};

class Middleman : public Participant {
 public:
  vector<bytearray> messages;

  bool uninit = true;
  int id_1;
  int id_2;

  DiffieHellman::DH params;
  DiffieHellman::DH remote1;
  DiffieHellman::DH remote2;

  bigint s1;
  bigint s2;

  void connect(Participant& dest) override {
    id_2 = dest.id;

    DiffieHellman::DH fake_params;
    fake_params.A = params.p;

    dest.init(*this, fake_params);
  }

  void init(Participant& dest, const DiffieHellman::DH& new_params) override {
    // the sentinel value can be refactored away
    if (uninit) {
      id_1 = dest.id;
      uninit = false;
    }

    if (dest.id == id_1) {
      remote1 = new_params;
    } else {
      remote2 = new_params;
    }
  }

  void respond(Participant& dest) override {
    DiffieHellman::DH fake_params;
    fake_params.A = params.p;
    dest.init(*this, fake_params);
  }

  bytearray recv(const Message& message) override {
    return decrypt_intercepted_message(message);
  }

  Message send(const bytearray& text) override {}

  virtual bytearray decrypt_intercepted_message(const Message& message) {
    s1 = powm(remote1.p, remote2.a, remote1.p);

    bytearray key = slice(sha1(s1), 0, block_size);
    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));

    messages.push_back(plaintext);

    return plaintext;
  }

  virtual Message relay(const Message& message) {
    decrypt_intercepted_message(message);
    return message;
  }
};

class MiddlemanGroup : public Middleman {
 public:
  bigint fake_g;

  MiddlemanGroup(bigint g = 1) : fake_g(g) {}

  void connect(Participant& dest) override {
    id_2 = dest.id;

    DiffieHellman::DH fake_params = remote1;
    fake_params.g = fake_g;

    dest.init(*this, fake_params);
  }

  void respond(Participant& dest) override {
    DiffieHellman::DH fake_params = remote2;
    fake_params.g = params.g;

    dest.init(*this, fake_params);
  }

  bigint reconstruct_key() {
    s1 = 1;

    if (fake_g == 1) {
      s1 = bigint("1");
    } else if (fake_g == (params.p - 1)) {
      s1 = bigint("1");
    } else if (fake_g == params.p) {
      s1 = 0;
    }

    return s1;
  }

  bytearray decrypt_intercepted_message(const Message& message) override {
    s1 = reconstruct_key();

    bytearray key = slice(sha1(s1), 0, block_size);
    bytearray plaintext = strip_pkcs(
        aes_cbc_decrypt(message.cipher, key, block_size, message.iv));

    messages.push_back(plaintext);

    return plaintext;
  }
};
