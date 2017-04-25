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
  const size_t block_size = 16;
  virtual ~Participant() {}
};


class NormalParticipant {
public:
  DH params;
  DH remote;

  cpp_int s;
};


class Middleman : public Participant {
public:
  DH params;
  DH remote1;
  DH remote2;

  cpp_int s1;
  cpp_int s2;



};
