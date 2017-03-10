#pragma once

#include "analysis/aes.h"
#include "bytearray.h"
#include "methods/aes.h"
#include "utils.h"
#include <functional>

namespace oracle {
namespace aes {

random_device rd;
mt19937 rng(rd());
uniform_int_distribution<int> r_pad(5, 10);

using encryption_mode = int;
const encryption_mode ECB = 0;
const encryption_mode CBC = 1;

bytearray oracle_func(const bytearray& plaintext);
using encryption_func = std::function<decltype(oracle_func)>;

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

bytearray random_aes_key() {
  const size_t key_size = 16;
  bytearray key = random_bytes(key_size);

  return key;
}

bytearray encryption_oracle_mode(const bytearray& plaintext,
                                 const size_t block_size = 16) {
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

const bytearray key = random_aes_key();
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

const bytearray random_pre_padding = random_bytes(random_padding_size());

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
}
}
