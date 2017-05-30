#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <streambuf>

#include <algorithm>
#include <cmath>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <thread>
#include <unordered_map>

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/dsa.h"
#include "methods/padding.h"
#include "methods/rsa.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "dh.h"
#include "fs.h"

#include "bigint.h"
#include "hex.h"
#include "sha1.h"

#include <boost/format.hpp>
#include <cppcodec/base64_default_rfc4648.hpp>

bytearray cbc_mac(const bytearray& plaintext,
                  const bytearray& key,
                  const bytearray& IV,
                  const size_t block_size = 16) {
  bytearray cipher = aes_cbc_encrypt(plaintext, key, block_size, IV);
  vector<bytearray> blocks = chunk(cipher, block_size);
  bytearray last_block = blocks.back();

  return last_block;
}

class SharedParameters {
 public:
  const bytearray key = bytearray("YELLOW SUBMARINE");
  const size_t block_size = 16;
};

class BankServer : public SharedParameters {
 public:
  bool handle_request(bytearray& request) {
    size_t req_length = request.size();

    bytearray message = slice(request, 0, request.size() - 2 * block_size);
    bytearray IV = slice(request, message.size(), block_size);
    bytearray mac = slice(request, message.size() + block_size, block_size);

    bytearray real_mac = cbc_mac(message, key, IV);
    bool valid_mac = real_mac == mac;

    return valid_mac;
  }
};

class BankClient : public SharedParameters {
 public:
  bytearray build_message(const string from_id,
                          const string to_id,
                          const string amount) {
    auto fmt =
        boost::format("from=%1%&to=%2%&amount=%3%") % from_id % to_id % amount;
    return fmt.str();
  }

  bytearray build_request(const bytearray& message,
                          const bytearray& IV = bytearray(16, 0x00)) {
    bytearray req = message;
    req = req + IV;
    req = req + cbc_mac(message, key, IV);

    return req;
  }
};

class BankClientMultipleTransactions : public SharedParameters {
 public:
  string build_transaction_list(const map<string, string>& transactions) {
    string ret;
    int num_tx = 0;
    for (auto& kv : transactions) {
      if (num_tx != 0) {
        ret += ";";
      }

      ret += kv.first + ":" + kv.second;

      ++num_tx;
    }

    return ret;
  }

  bytearray build_message(const string from_id,
                          const map<string, string>& transactions) {
    auto tx_list = build_transaction_list(transactions);
    auto fmt = boost::format("from=%1%&tx_list=%2%") % from_id % tx_list;
    return fmt.str();
  }

  bytearray build_request(const bytearray& message,
                          const bytearray& IV = bytearray(16, 0x00)) {
    bytearray req = message;
    req = req + IV;
    req = req + cbc_mac(message, key, IV);

    return req;
  }
};

bool forge_attack() {
  const size_t block_size = 16;
  bytearray IV(16, 0x00);

  BankServer server;
  BankClient client;

  // transfer 1M between your own accounts
  auto message = client.build_message("m", "m", "1M");
  auto request = client.build_request(message, IV);

  const size_t m_size = request.size() - 2 * block_size;
  bytearray mac = slice(request, m_size + block_size, block_size);

  bytearray altered_message = client.build_message("a", "m", "1M");
  IV[5] ^= 'm' ^ 'a';

  bytearray forged = altered_message;
  forged = forged + IV;
  forged = forged + mac;

  return server.handle_request(forged);
}

bool forge_extension() {
  const size_t block_size = 16;
  bytearray IV(16, 0x00);

  BankServer server;
  BankClientMultipleTransactions client;

  map<string, string> tx_list = {
      {"a", "5"}, {"b", "6"}, {"c", "8"}, {"daa", "5"},
  };

  auto message = client.build_message("m", tx_list);
  auto request = client.build_request(message, IV);

  const size_t m_size = request.size() - 2 * block_size;
  bytearray mac = slice(request, message.size() + block_size, block_size);

  bytearray appendix(";a:1M&g=" + string(8, 'A'));

  bytearray mod = mac ^ appendix;
  auto new_mac = cbc_mac(mod, client.key, IV);

  bytearray new_message = pkcs(message);
  new_message = new_message + appendix;
  bytearray new_request = new_message;
  new_request = new_request + IV;
  new_request = new_request + new_mac;

  return server.handle_request(new_request);
}

bool hashing() {
  bytearray IV(16, 0x00);
  bytearray key("YELLOW SUBMARINE");
  bytearray js("alert('MZA who was that?');\n");

  bytearray target_mac = cbc_mac(js, key, IV);

  bytearray collision("alert('Ayo, the Wu is back!'); //");
  bytearray collision_mac = cbc_mac(collision, key, IV);

  collision_mac = collision_mac ^ slice(js, 0, 16);

  bytearray new_message = pkcs(collision);
  new_message = new_message + collision_mac;
  new_message = new_message + slice(js, 16, js.size());

  return cbc_mac(new_message, key, IV) == target_mac;
}

int main() {
  assert(forge_attack());
  assert(forge_extension());
  assert(hashing());

  return 0;
}
