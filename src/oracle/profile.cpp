#include <unordered_map>
#include <vector>

#include "../bytearray.h"
#include "methods/aes.h"
#include "profile.h"
#include "utils.h"

namespace oracle {
namespace aes {

using namespace std;

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
                       const string& role,
                       size_t block_size) {
  assert(role.size() <= block_size);

  // create [email=padpad..., {role}padpad] blocks
  size_t email_pad_size = block_size - strlen("email=");
  size_t role_pad_size = block_size - role.size();

  string input = string(email_pad_size, email_pad_size) + role +
                 string(role_pad_size, role_pad_size);
  bytearray cipher = encrypt_profile(key, profile_for(input));

  const size_t block_num = 1;
  return nth_block(cipher, block_size, block_num);
}

Profile change_profile_role(const string& email,
                            const string& role,
                            size_t block_size) {
  auto key = rkey;
  const int field_size = 13;
  const int email_size = static_cast<int>(email.size());
  const int padding_size = max(field_size - email_size, 0);

  string input = email + string(padding_size, padding_size);
  input = input.substr(0, field_size);

  // swap last block with the custom 'role' block
  bytearray cipher = encrypt_profile(key, profile_for(input));
  bytearray modified = slice(cipher, 0, cipher.size() - block_size);

  modified = modified + create_block(key, role);
  return decrypt_profile(modified, key);
}
}
}
