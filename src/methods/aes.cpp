#include <cassert>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <random>

#include "bytearray.h"
#include "methods/aes.h"
#include "methods/padding.h"
#include "utils.h"

using namespace std;

bytearray aes_decrypt_block(const bytearray& block, const bytearray& key) {
  const size_t block_size = 16;
  assert(block.size() == block_size);
  size_t key_size = key.size() * 8;

  bytearray plaintext(block_size);

  AES_KEY dec_key;
  AES_set_decrypt_key(key.const_ptr(), key_size, &dec_key);
  AES_decrypt(block.const_ptr(), plaintext.ptr(), &dec_key);

  return plaintext;
}

bytearray aes_encrypt_block(const bytearray& block,
                            const bytearray& key,
                            const size_t block_size) {
  assert(block.size() == block_size);
  size_t key_size = key.size() * 8;

  bytearray cipher(block_size);

  AES_KEY enc_key;
  AES_set_encrypt_key(key.const_ptr(), key_size, &enc_key);
  AES_encrypt(block.const_ptr(), cipher.ptr(), &enc_key);

  return cipher;
}

bytearray aes_ebc_decrypt(const bytearray& cipher,
                          const bytearray& key,
                          const size_t block_size) {
  bytearray plaintext;
  for (auto& block : chunk(cipher, block_size)) {
    plaintext = plaintext + aes_decrypt_block(block, key);
  }

  return plaintext;
}

bytearray aes_ebc_encrypt(const bytearray& plaintext,
                          const bytearray& key,
                          const size_t block_size) {
  bytearray cipher;
  for (auto& block : chunk(pkcs(plaintext), block_size)) {
    cipher = cipher + aes_encrypt_block(block, key);
  }

  return cipher;
}

bytearray aes_cbc_decrypt(const bytearray& cipher,
                          const bytearray& key,
                          const size_t block_size,
                          bytearray iv) {
  bytearray plaintext;

  bytearray& prev_block = iv;
  for (auto& block : chunk(cipher, block_size)) {
    plaintext = plaintext + (aes_decrypt_block(block, key) ^ prev_block);

    prev_block = block;
  }

  return plaintext;
}

bytearray aes_cbc_encrypt(const bytearray& plaintext,
                          const bytearray& key,
                          const size_t block_size,
                          bytearray iv) {
  assert(block_size == iv.size());

  bytearray cipher;
  bytearray& prev_block = iv;
  for (auto& block : chunk(pkcs(plaintext), block_size)) {
    prev_block = aes_encrypt_block(block ^ prev_block, key);
    cipher = cipher + prev_block;
  }

  return cipher;
}
