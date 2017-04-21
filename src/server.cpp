#include "bytearray.h"
#include "crow.h"
#include "sha1.h"

#include <boost/lexical_cast.hpp>
#include <sstream>

string hash_func(string message) {
  SHA1 s;
  s.update(message);
  return s.final();
}

string hmac(const string& _key, const string& message) {
  bytearray key(_key);

  const size_t block_size = 16;

  if (key.size() > block_size) {
    key = bytearray(hash_func(key.to_str()));
  }
  if (key.size() < block_size) {
    key = key + bytearray(0x00, block_size - key.size());
  }

  bytearray o_key_pad = bytearray(0x5c, block_size) ^ key;
  bytearray i_key_pad = bytearray(0x36, block_size) ^ key;

  return hash_func(o_key_pad.to_str() +
                   hash_func(i_key_pad.to_str() + message));
}

bool insecure_compare(const string& a, const string& b) {
  cout << a << endl;
  cout << b << endl;

  bool valid = true;
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) {
      valid = false;
      break;
    }
    this_thread::sleep_for(5ms);
  }

  return valid;
}

int main() {
  crow::SimpleApp app;

  CROW_ROUTE(app, "/test")
  ([](const crow::request& req) {
    const string key = "AAAA";
    if (req.url_params.get("file") != nullptr &&
        req.url_params.get("signature") != nullptr) {
      const string file =
          boost::lexical_cast<string>(req.url_params.get("file"));
      const string signature =
          boost::lexical_cast<string>(req.url_params.get("signature"));

      if (insecure_compare(hmac(key, file), signature)) {
        return crow::response(200);
      } else {
        return crow::response(500);
      }
    }
    return crow::response(200);
  });

  app.port(9000).multithreaded().run();
}
