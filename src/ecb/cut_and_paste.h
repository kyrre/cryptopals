#pragma once

#include <unordered_map>
#include <vector>

#include "aes.h"
#include "bytearray.h"
#include "utils.h"

namespace ECB {

using std::vector;
using std::unordered_map;
using std::tie;
using std::tie;

using keyvalue = unordered_map<string, string>;
const bytearray rkey = random_aes_key();

struct Profile {
  string email;
  int uid;
  string role;

  Profile(unordered_map<string, string>&& kv)
      : email{kv["email"]}, uid{stoi(kv["uid"])}, role{kv["role"]} {}
};

Profile parse_profile(const string& query_str) {
  return Profile(parse_query_string(query_str));
}

string profile_for(const string& s) {
  const vector<string> meta_characters = {"&", "="};

  string clean = s;
  for (const auto& meta : meta_characters) {
    boost::erase_all(clean, meta);
  }

  return "email=" + clean + "&uid=10&role=user";
}

bytearray encrypt_profile(const bytearray& key, string p) {
  return aes_ebc_encrypt(p, key);
}

Profile decrypt_profile(const bytearray& cipher, const bytearray& key) {
  bytearray pt = aes_ebc_decrypt(cipher, key);
  return parse_profile(pt.to_str());
}

bytearray create_block(const bytearray& key,
                       const string& role = "admin",
                       size_t block_size = 16) {

  assert(role.size() <= block_size);

  // create [email=\x04..., {role}\x04] blocks
  size_t pad_size = block_size - strlen("email=");
  string input = string(pad_size, '\x04') + role +
                 string(block_size - role.size(), '\x04');
  bytearray cipher = encrypt_profile(key, profile_for(input));

  return nth_block(cipher, block_size, 1);
}

Profile change_profile_role(const bytearray& key,
                            const string& email = "foo@bar",
                            const string& role = "admin",
                            size_t block_size = 16) {
  const int field_size = 13;
  const int email_size = static_cast<int>(email.size());
  const int padding_size = max(field_size - email_size, 0);

  string input = email + string(padding_size, '\x00');
  input = input.substr(0, field_size);

  // swap last block with the custom 'role' block
  bytearray cipher = encrypt_profile(key, profile_for(input));
  bytearray modified = slice(cipher, 0, cipher.size() - block_size);

  modified = modified + create_block(key, role);
  return decrypt_profile(modified, key);
}
}
