#pragma once

#include <memory>

#include "bigint.h"
#include "common.h"

class Server;

class Client : public CommonParameters {
 public:
  Server *server;
  bigint salt;
  bigint a;
  bigint v;
  string status;



  Client();

  Client(string I, string P);

  Client& connect(Server *s);
  Client& login();
  void set_param(bigint _salt, bigint _B);

  Client& passwd();
};
