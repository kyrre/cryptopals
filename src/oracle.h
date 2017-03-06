#pragma once

#include "bytearray.h"

using encryption_mode = int;
const encryption_mode ECB = 0;
const encryption_mode CBC = 1;

// replace this with proper function type
// instead of decltype abuse!
bytearray blackbox(const bytearray &plaintext);
using encryption_func = decltype(blackbox);

// pad until next block is detected
size_t find_padding_length(encryption_func &encrypt, size_t padding_size = 1) {
  for (;; ++padding_size) {

    bytearray pt(string(padding_size, 'A'));
    bytearray pt_next(string(padding_size + 1, 'A'));

    bytearray ct = encrypt(pt);
    bytearray ct_next = encrypt(pt_next);

    if (ct.size() != ct_next.size()) {
      break;
    }
  }

  return padding_size;
}

/* pad until new block then pad again from new block to find block size. */
size_t find_block_size(encryption_func &encrypt) {
  size_t padding = find_padding_length(encrypt);
  return find_padding_length(encrypt, padding + 1) - padding;
}

// this is a probabilistic, but very unlikely to break!
encryption_mode detect_encryption_mode(encryption_func &blackbox) {

  const bytearray chosen_plaintext(string(16 * 100, 'A'));
  bytearray ciphertext = blackbox(chosen_plaintext);

  int repeated_blocks = 0;
  for (const auto &item : count_unique_blocks(ciphertext)) {
    if (item.second > 2)
      repeated_blocks += item.second;
  }

  encryption_mode mode = CBC;
  if (repeated_blocks > 2) {
    mode = ECB;
  }

  return mode;
}
