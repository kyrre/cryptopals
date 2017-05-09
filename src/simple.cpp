#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <thread>
#include <unordered_map>

#include "fs.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"
#include "methods/rsa.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "hex.h"
#include "sha1.h"

#include "bigint.h"

#include "dh.h"

int main() {
  rsa::RSA keys1;

  string plaintext = "{\"name\":\"Tom\"}";
  bigint C = keys1.encrypt(plaintext);

  cout << no_padding_attack(C, keys1) << endl;
}
