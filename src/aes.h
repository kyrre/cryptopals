#pragma once

#include <cassert>
#include <random>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/conf.h>

#include "bytearray.h"
#include "frequency_analysis.h"

bytearray aes_decrypt_block(const bytearray &block, const bytearray &key) {

  const size_t block_size = 16;
  assert(block.size() == block_size);

  bytearray plaintext(block_size);

  AES_KEY dec_key;
  AES_set_decrypt_key(key.const_ptr(), 128, &dec_key);
  AES_decrypt(block.const_ptr(), plaintext.ptr(), &dec_key);

  return plaintext;
}

bytearray aes_encrypt_block(const bytearray &block, const bytearray &key, const size_t block_size = 16) {

  assert(block.size() == block_size);

  bytearray cipher(block_size);

  AES_KEY enc_key;
  AES_set_encrypt_key(key.const_ptr(), 128, &enc_key);
  AES_encrypt(block.const_ptr(), cipher.ptr(), &enc_key);

  return cipher;
}

bytearray aes_ebc_decrypt(const bytearray &cipher, const bytearray &key, const size_t block_size = 16) {
  bytearray plaintext;
  for (auto &block : chunk(cipher, block_size)) {
    plaintext.extend(aes_decrypt_block(block, key));
  }

  return plaintext;
}

bytearray aes_ebc_encrypt(const bytearray &plaintext, const bytearray &key, const size_t block_size = 16) {


  bytearray cipher;

  for (auto &block : chunk(plaintext, block_size)) {
    cipher.extend(aes_encrypt_block(block, key));
  }

  return cipher;
}

bytearray &pkcs_padding(bytearray &b, size_t size, const BYTE pad_byte = '\x04') {
  while (b.size() < size) {
    b.push_back(pad_byte);
  }
  return b;
}

bytearray aes_cbc_decrypt(const bytearray &cipher, const bytearray &key) {
  const size_t block_size = 16;
  bytearray plaintext;

  bytearray iv(string(block_size, '\x00'));
  bytearray &prev_block = iv;
  for (auto &block : chunk(cipher, block_size)) {
    pkcs_padding(block, block_size);
    plaintext.extend(aes_ebc_decrypt(block, key) ^ prev_block);

    prev_block = block;
  }

  return plaintext;
}


bytearray random_bytes(size_t size) {
  std::random_device engine;

  bytearray bytes;
  for(size_t i = 0; i < size; ++i) {
    BYTE random_byte = engine();
    bytes.push_back(random_byte);
  }

  return bytes;

}

bytearray random_aes_key() {

  const size_t key_size = 16;
  bytearray key = random_bytes(key_size);

  return key;
}


bool encryption_oracle(const bytearray& cipher) {
  bytearray key = random_aes_key();

  return true;

}
