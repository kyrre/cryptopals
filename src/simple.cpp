#include <algorithm>
#include <chrono>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include "fs.h"
#include "mt19937.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

using namespace std;
using namespace oracle::aes;

bytearray edit(const bytearray& ciphertext,
               const bytearray& key,
               size_t offset,
               const bytearray& new_text) {
  const size_t size = ciphertext.size();
  const size_t new_size = new_text.size();

  bytearray plaintext = aes_ctr(ciphertext, key);
  bytearray pre = slice(plaintext, 0, offset);
  bytearray post =
      slice(plaintext, offset + new_size, size - offset - new_size);

  return aes_ctr(pre + new_text + post, key);
}

bytearray encryption_oracle_ctr(const string& chosen_plaintext) {
  const vector<string> meta_characters = {"=", ";"};

  const string pre = "comment1=cooking%20MCs;userdata=";
  const string post = ";comment2=%20like%20a%20pound%20of%20bacon";

  string plaintext = pre + chosen_plaintext + post;

  for (const auto& meta : meta_characters) {
    boost::replace_all(plaintext, meta, "\"" + meta + "\"");
  }

  auto cipher = aes_ctr(plaintext, key);
  return cipher;
}

bool decrypt_oracle_ctr(const bytearray& cipher) {
  string plaintext = aes_ctr(cipher, key).to_str();
  bool found = plaintext.find(";admin=true;") != string::npos;
  return found;
}

int main() {
  // edit
  // const bytearray ecb_key("YELLOW SUBMARINE");
  // const string filename =
  // "/home/kyrre/projects/cryptopals/tests/data/25.txt";
  // bytearray plaintext = aes_ebc_decrypt(read_base64(filename), ecb_key);

  // bytearray ciphertext = aes_ctr(plaintext, key, 0);

  // bytearray new_text = bytearray(ciphertext.size(), 'A');
  // bytearray keystream = edit(ciphertext, key, 0, new_text) ^ new_text;

  // assert((ciphertext ^ keystream) == plaintext);

  // bit-flipping
  //string wanted = ";admin=true;";
  //string c(wanted.size(), 'A');

  //bytearray cipher = encryption_oracle_ctr(c);
  //bytearray keystream = slice(cipher, 38, c.size()) ^ c;
  //bytearray diff = keystream ^ bytearray(wanted);

  //bytearray new_message = slice(cipher, 0, 38);
  //new_message =
  //    new_message + diff +
  //    slice(cipher, 38 + diff.size(), cipher.size() - 38 - diff.size());

  //assert(decrypt_oracle_ctr(new_message));
}
