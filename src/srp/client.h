#pragma once

#include <memory>

#include "bigint.h"
#include "common.h"

class Server;

class Client : public CommonParameters {
 public:
  shared_ptr<Server> server;
  bigint salt;
  bigint a;
  bigint v;


  Client();
  Client& connect(const Server& s);
  void login();
  void set_param(bigint _salt, bigint _B);
};
