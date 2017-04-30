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

  shared_ptr<Client> client;

  Server();
  void login(string& _I, cpp_int _B);
  void connect(const Client& c);
};
