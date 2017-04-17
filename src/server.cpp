#include "crow.h"

#include "bytearray.h"
#include "sha1.h"

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

	return hash_func(o_key_pad.to_str() + hash_func(i_key_pad.to_str() + message));
}



int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
        return "Hello world";
    });

    app.port(8888).multithreaded().run();
}
