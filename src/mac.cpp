#include "mac.h"
#include "methods/aes.h"
#include "utils.h"

bytearray cbc_mac(const bytearray& plaintext,
                  const bytearray& key,
                  const bytearray& IV,
                  const size_t block_size) {
  bytearray cipher = aes_cbc_encrypt(plaintext, key, block_size, IV);
  vector<bytearray> blocks = chunk(cipher, block_size);
  bytearray last_block = blocks.back();

  return last_block;
}
