#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <memory>
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

#include "bigint.h"
#include "dh.h"
#include "dh_message.h"
#include "srp/client.h"
#include "srp/server.h"

int main() {
  Server server;
  Client client;

  client.connect(&server).login();
  client.passwd();

}
