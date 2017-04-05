#pragma once

#include <unordered_map>
#include <vector>

#include "bytearray.h"
#include "methods/aes.h"
#include "oracle/aes.h"
#include "utils.h"

namespace oracle {
namespace aes {

using namespace std;

using keyvalue = unordered_map<string, string>;
const bytearray rkey = random_aes_key();

struct Profile {
  string email;
  int uid;
  string role;

  Profile(unordered_map<string, string>&& kv)
      : email{kv["email"]}, uid{stoi(kv["uid"])}, role{kv["role"]} {}
};

Profile parse_profile(const string& query_str);
string profile_for(const string& s);

bytearray encrypt_profile(const bytearray& key, string p);
Profile decrypt_profile(const bytearray& cipher, const bytearray& key);

bytearray create_block(const bytearray& key,
                       const string& role = "admin",
                       size_t block_size = 16);

Profile change_profile_role(const string& email = "foo@bar",
                            const string& role = "admin",
                            size_t block_size = 16);
}
}
