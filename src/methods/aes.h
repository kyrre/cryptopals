#pragma once

#include "bytearray.h"

bytearray aes_decrypt_block(const bytearray& block, const bytearray& key);

bytearray aes_encrypt_block(const bytearray& block,
                            const bytearray& key,
                            const size_t block_size = 16);

bytearray aes_ebc_decrypt(const bytearray& cipher,
                          const bytearray& key,
                          const size_t block_size = 16);

bytearray aes_ebc_encrypt(const bytearray& plaintext,
                          const bytearray& key,
                          const size_t block_size = 16);

bytearray aes_cbc_decrypt(const bytearray& cipher,
                          const bytearray& key,
                          const size_t block_size = 16,
                          bytearray iv = bytearray(16, '\x00'));

bytearray aes_cbc_encrypt(const bytearray& plaintext,
                          const bytearray& key,
                          const size_t block_size = 16,
                          bytearray iv = bytearray(16, '\x00'));

bytearray aes_ctr(const bytearray& cipher,
                  const bytearray& key,
                  unsigned long nonce = 0,
                  unsigned long counter = 0,
                  const size_t block_size = 16);
