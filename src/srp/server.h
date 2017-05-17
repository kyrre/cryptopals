#pragma once

#include <memory>

#include "bigint.h"
#include "common.h"

class Client;

class Server : public CommonParameters {
 public:
  bigint b;
  bigint salt;
  bigint v;

  Client* client;

  Server();
  void login(string& _I, bigint _B);
  void connect(Client* c);
  void passwd(const string& hmac);
};
