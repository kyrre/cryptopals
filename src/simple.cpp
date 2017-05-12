#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <thread>
#include <unordered_map>
#include <algorithm>

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


/*
 *
 *
 *
 * '00' || BT || PS || X'00' D where:
 *
 *
 */

map<string, bytearray> asin_values = {{"sha1", hex::decode("3021300906052b0e03021a05000414")}};
bytearray create_block(const string& message, const int block_size = 64) {

  bytearray hash_value = sha1(message);
  bytearray D = asin_values["sha1"] + hash_value;

  
  bytearray BT(1, 0x01);
  bytearray PS(max(0, block_size -  static_cast<int>(D.size()) - 3), 0xff);

  bytearray format(1, 0x00);
  format = format + BT + PS + bytearray(1, 0x00) + D;

  return format;
}

bigint create_fake_block(const string& message) {

    string fake_block = "0001ff003021300906052b0e03021a05000414" + hex::encode(sha1(message).to_str());
    fake_block = fake_block + string(128UL - fake_block.size(), '0');
    fake_block = hex::decode(fake_block).to_str();

    bigint s = string_to_bigint(fake_block);
    auto status = cbrt_close(s);
    if (!status.second ) {
      s = s + (cube(status.first) - s);
    } 

    return s;
}

int main() {

  rsa::RSA key;

  const string message = "hi mom";;
  string block = hex::encode(create_block(message).to_str());
  bigint sig = key.encrypt(block);
  string pt = key.decrypt(sig);


  bigint fake = create_fake_block(message);

  cout << key.decrypt(fake) << endl;

}
