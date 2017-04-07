#include <cppcodec/base64_default_rfc4648.hpp>
#include <random>
#include <vector>

#include "analysis/aes.h"
#include "methods/aes.h"
#include "methods/padding.h"

#include "bytearray.h"
#include "oracle/aes.h"
#include "utils.h"

namespace oracle {
namespace aes {

const bytearray key = random_aes_key();
const bytearray random_pre_padding = random_bytes(random_padding_size());

bytearray random_bytes(size_t size) {
  bytearray bytes;
  for (size_t i = 0; i < size; ++i) {
    BYTE random_byte = rd();
    bytes.push_back(random_byte);
  }

  return bytes;
}

int random_padding_size() {
  return r_pad(rng);
}

bytearray random_aes_key(const size_t key_size) {
  bytearray key = random_bytes(key_size);

  return key;
}

bytearray encryption_oracle_mode(const bytearray& plaintext,
                                 const size_t block_size) {
  bernoulli_distribution ebc_mode(0.5);

  bytearray key = random_aes_key();

  size_t pre_padding = random_padding_size();
  size_t post_padding = random_padding_size();

  bytearray pt = random_bytes(pre_padding);
  pt = pt + plaintext + random_bytes(post_padding);

  bytearray ciphertext;
  if (ebc_mode(rng)) {
    ciphertext = aes_ebc_encrypt(pt, key);
  } else {
    auto iv = random_bytes(block_size);
    ciphertext = aes_cbc_encrypt(pt, key, block_size, iv);
  }

  return ciphertext;
}

bytearray encryption_oracle(const bytearray& plaintext) {
  bytearray padding = base64::decode(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g"
      "YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg"
      "eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

  bytearray pt = plaintext;
  pt = pt + padding;

  bytearray ciphertext = aes_ebc_encrypt(pt, key);

  return ciphertext;
}

bytearray encryption_oracle_prepad(const bytearray& plaintext) {
  bytearray target_bytes = base64::decode(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g"
      "YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg"
      "eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

  bytearray pt = random_pre_padding;
  pt = pt + plaintext + target_bytes;

  bytearray ciphertext = aes_ebc_encrypt(pt, key);

  return ciphertext;
}

bytearray encryption_oracle_cbc(const string& chosen_plaintext) {
  const vector<string> meta_characters = {"=", ";"};

  const string pre = "comment1=cooking%20MCs;userdata=";
  const string post = ";comment2=%20like%20a%20pound%20of%20bacon";

  string plaintext = pre + chosen_plaintext + post;

  for (const auto& meta : meta_characters) {
    boost::replace_all(plaintext, meta, "\"" + meta + "\"");
  }

  auto cipher = aes_cbc_encrypt(plaintext, key);
  return cipher;
}

bool decrypt_oracle_cbc(const bytearray& cipher) {
  string plaintext = aes_cbc_decrypt(cipher, key).to_str();
  bool found = plaintext.find(";admin=true;") != string::npos;
  return found;
}

bytearray bit_flipping_cbc(const string& wanted) {
  assert(wanted.size() <= 16);

  const size_t padding = 22;
  const string plaintext = string(padding, ' ');

  bytearray cipher = encryption_oracle_cbc(plaintext);
  for (size_t i = 0; i < wanted.size(); ++i) {
    cipher[32 + i] ^= plaintext[i] ^ wanted[i];
  }

  return cipher;
}

bytearray encrypt_random_line() {
  const vector<string> lines = {
      "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
      "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBp"
      "bic=",
      "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
      "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
      "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
      "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
      "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
      "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
      "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
      "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};

  bytearray random_line = bytearray(base64::decode(choice(lines)));
  auto cipher = aes_cbc_encrypt(random_line, key);

  return cipher;
}

bool padding_oracle(const bytearray& cipher,
                    size_t start_position,
                    size_t block_size) {
  auto pt = aes_cbc_decrypt(cipher, key);
  bool valid = valid_padding(slice(pt, start_position, block_size));

  return valid;
}

bytearray cbc_attack_block(const bytearray& c,
                           size_t n_block,
                           size_t block_size) {
  assert(n_block > 0);

  bytearray plaintext;
  size_t start_position = n_block * block_size;

  for (size_t i = 0; i < block_size; ++i) {
    size_t pad = i + 1;
    size_t n_byte = start_position - i - 1;

    for (BYTE z = 0x1; z < 0xff; ++z) {
      bytearray cipher = c;

      for (size_t j = 0; j < i; ++j) {
        size_t prev_byte = start_position - j - 1;
        cipher[prev_byte] ^= plaintext[j] ^ pad;
      }

      cipher[n_byte] ^= z ^ pad;

      bool valid = padding_oracle(cipher, start_position);

      if (valid) {
        plaintext.push_back(z);
        break;
      }
    }
  }

  assert(plaintext.size() == block_size);
  return plaintext.reverse();
}
}
}
