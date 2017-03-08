#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <iostream>
#include <unordered_map>
#include <algorithm>

#include "aes.h"
#include "bytearray.h"
#include "encryption.h"
#include "frequency_analysis.h"
#include "fs.h"
#include "hex.h"
#include "oracle.h"

using namespace std;


using keyvalue = unordered_map<string, string>;

struct Profile {
  string email;
  int uid;
  string role;

  Profile(unordered_map<string, string> &kv)
    : email{kv["email"]},
      uid{stoi(kv["uid"])},
      role{kv["role"]}
    {}

};

using profile = unordered_map<string, string>;

vector<string> split(const string& s, const string& sep) {
  vector<string> lines;
  boost::split(lines, s, boost::is_any_of(sep));

  return lines;
}

pair<string, string> key_value(const string& s) {
  vector<string> kv = split(s, "=");

  return make_pair(kv[0], kv[1]);
}

profile parse_profile(const string& query_str) {

  profile kv;
  for (auto& token : split(query_str, "&")) {
    string key, value;
    tie(key, value) = key_value(token);

    kv[key] = value;
  }

  return kv;
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

profile decrypt_profile(const bytearray& cipher, const bytearray& key) {
  bytearray pt = aes_ebc_decrypt(cipher, key);
  cout << pt << endl;
  return parse_profile(pt.to_str());
}

bytearray create_admin_block(const bytearray& key, size_t block_size = 16) {

  // create [emain=\x04..., admin\x04] blocks
  string input = string(10, '\x04') + "admin" + string(11, '\x04');
  bytearray cipher = encrypt_profile(key, profile_for(input));

  return nth_block(cipher, block_size, 1);
}


bytearray forge_admin_profile(const bytearray& key, 
    const string& email="foo@bar",
    size_t block_size = 16) {

  bytearray admin = create_admin_block(key);


  int field_size  = 13;
  int email_size = static_cast<int>(email.size());

  size_t padding_size = max(field_size - email_size, 0);

  string input = email + string(padding_size, '\x00');
  input = input.substr(0, field_size);

  bytearray cipher = encrypt_profile(key, profile_for(input));
  bytearray modified = slice(cipher, 0, cipher.size() - block_size);

  modified = modified + admin;
  profile p = decrypt_profile(modified, key);


  return admin;
}

int main() {

  const bytearray key = random_aes_key();

  forge_admin_profile(key, "emailieuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu");


  //cout << profile_for(input).size() << endl;
  
  //size_t block_size = 16;
  //size_t n_blocks = cipher.size() / block_size;
  //bytearray second_block = create_admin_block(key);
  //bytearray last_block = nth_block(cipher, block_size, n_blocks-1);

  //bytearray modified_cipher= slice(cipher, 0, cipher.size() - block_size);
  //modified_cipher = modified_cipher + second_block;
  //profile p = decrypt_profile(modified_cipher, key);

  //cout << p["role"] << endl;
  //cout << cipher;

}
