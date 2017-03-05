#pragma once

#include <cassert>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <random>

#include "bytearray.h"
#include "frequency_analysis.h"

random_device rd;
mt19937 rng(rd());
uniform_int_distribution<int> r_pad(5, 10);


bytearray &pkcs_padding(bytearray &b, size_t size,
                        const BYTE pad_byte = '\x04') {
  while (b.size() < size) {
    b.push_back(pad_byte);
  }

  assert(b.size() == size);
  return b;
}

bytearray aes_decrypt_block(const bytearray &block, const bytearray &key) {

  const size_t block_size = 16;
  assert(block.size() == block_size);

  bytearray plaintext(block_size);

  AES_KEY dec_key;
  AES_set_decrypt_key(key.const_ptr(), 128, &dec_key);
  AES_decrypt(block.const_ptr(), plaintext.ptr(), &dec_key);

  return plaintext;
}

bytearray aes_encrypt_block(const bytearray &block, const bytearray &key,
                            const size_t block_size = 16) {

  assert(block.size() == block_size);

  bytearray cipher(block_size);

  AES_KEY enc_key;
  AES_set_encrypt_key(key.const_ptr(), 128, &enc_key);
  AES_encrypt(block.const_ptr(), cipher.ptr(), &enc_key);

  return cipher;
}

bytearray aes_ebc_decrypt(const bytearray &cipher, const bytearray &key,
                          const size_t block_size = 16) {
  bytearray plaintext;
  for (auto &block : chunk(cipher, block_size)) {
    plaintext = plaintext + aes_decrypt_block(block, key);
  }

  return plaintext;
}

bytearray aes_ebc_encrypt(const bytearray &plaintext, const bytearray &key,
                          const size_t block_size = 16) {

  bytearray cipher;


  for (auto &block : chunk(plaintext, block_size)) {
    pkcs_padding(block, block_size);

    cipher = cipher + aes_encrypt_block(block, key);
  }

  return cipher;
}


bytearray aes_cbc_decrypt(const bytearray &cipher, const bytearray &key) {
  const size_t block_size = 16;
  bytearray plaintext;

  bytearray iv(string(block_size, '\x00'));
  bytearray &prev_block = iv;
  for (auto &block : chunk(cipher, block_size)) {
    pkcs_padding(block, block_size);
    plaintext = plaintext + (aes_ebc_decrypt(block, key) ^ prev_block);

    prev_block = block;
  }

  return plaintext;
}

bytearray aes_cbc_encrypt(const bytearray &plaintext, const bytearray &key,
                          const size_t block_size = 16,
                          bytearray iv = bytearray(string(16, '\x00'))) {

  assert(block_size == iv.size());

  bytearray cipher;
  bytearray &prev_block = iv;
  for (auto &block : chunk(plaintext, block_size)) {
    pkcs_padding(block, block_size);
    prev_block = aes_ebc_encrypt(block ^ prev_block, key);
    cipher = cipher + prev_block;
  }

  return cipher;
}

bytearray random_bytes(size_t size) {

  bytearray bytes;
  for (size_t i = 0; i < size; ++i) {
    BYTE random_byte = rd();
    bytes.push_back(random_byte);
  }

  return bytes;
}

int random_padding_size() { return r_pad(rng); }

bytearray random_aes_key() {

  const size_t key_size = 16;
  bytearray key = random_bytes(key_size);

  return key;
}

bytearray encryption_oracle(const bytearray &plaintext) {
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
    auto iv = random_bytes(16);
    ciphertext = aes_cbc_encrypt(pt, key, 16, iv);
  }

  return ciphertext;
}
