#pragma once

#include <functional>
#include "bytearray.h"
#include "encryption.h"

using encryption_mode = int;
const encryption_mode ECB = 0;
const encryption_mode CBC = 1;

bytearray blackbox(const bytearray& plaintext);
//using encryption_func = decltype(blackbox);
using encryption_func = std::function<decltype(blackbox)>;


// pad until next block is detected
size_t find_padding_length(encryption_func& encrypt, size_t padding_size = 1) {
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

size_t find_prepad_length(encryption_func func, const size_t block_size = 16) {
  bytearray chosen_plaintext(3 * block_size, 'A');
  bytearray chosen_block = find_duplicated_block(func(chosen_plaintext));

  size_t pad = 0;
  bool found_padding = false;
  for (pad = 0; pad < block_size && !found_padding; ++pad) {
    bytearray pt(block_size + pad, 'A');
    auto cipher = func(pt);
    auto blocks = chunk(cipher, block_size);

    for (const auto& block : blocks) {
      if (block == chosen_block) {
        found_padding = true;
        break;
      }
    }
  }

  return max((block_size - pad + 1UL), 0UL);
}

/* pad until new block then pad again from new block to find block size. */
size_t find_block_size(encryption_func encrypt) {
  size_t padding = find_padding_length(encrypt);
  return find_padding_length(encrypt, padding + 1) - padding;
}

// this is a probabilistic test, but very unlikely to break!
encryption_mode detect_encryption_mode(encryption_func blackbox,
                                       const size_t block_size = 16) {
  const bytearray chosen_plaintext(block_size * 100, 'A');
  bytearray cipher = blackbox(chosen_plaintext);

  encryption_mode mode = CBC;
  if (duplicate_blocks(cipher, block_size)) {
    mode = ECB;
  }

  return mode;
}

auto create_lookup_table(const bytearray& decrypted,
                         size_t offset,
                         size_t block_num,
                         size_t block_size,
                         encryption_func blackbox) {
  const size_t padding_size = block_size - offset;
  unordered_map<bytearray, BYTE, boost::hash<bytearray>> table;

  for (BYTE byte = 0; byte < 0xff; ++byte) {
    bytearray plaintext(padding_size, 'A');
    plaintext = plaintext + decrypted;
    plaintext.push_back(byte);

    bytearray cipher = blackbox(plaintext);
    bytearray block = nth_block(cipher, block_size, block_num);

    table[block] = byte;
  }

  return table;
}

BYTE decrypt_byte(const bytearray& decrypted,
                  size_t offset,
                  size_t block_num,
                  size_t block_size,
                  encryption_func blackbox) {
  size_t padding_size = block_size - offset;

  BYTE byte;
  bytearray plaintext(padding_size, 'A');
  bytearray cipher = blackbox(plaintext);

  auto candidates =
      create_lookup_table(decrypted, offset, block_num, block_size, blackbox);
  const bytearray block = nth_block(cipher, block_size, block_num);

  byte = candidates[block];

  return byte;
}

bytearray& decrypt_block(bytearray& decrypted,
                         size_t block_num,
                         size_t block_size,
                         encryption_func blackbox) {
  for (size_t offset = 1; offset <= block_size; ++offset) {
    BYTE byte =
        decrypt_byte(decrypted, offset, block_num, block_size, blackbox);
    decrypted.push_back(byte);
  }

  return decrypted;
}

bytearray decrypt(encryption_func blackbox, size_t start_block=0) {
  size_t block_size = find_block_size(blackbox);
  encryption_mode mode = detect_encryption_mode(blackbox);

  if (mode != ECB) {
  }

  bytearray empty;
  size_t num_blocks = blackbox(empty).size() / block_size;

  bytearray decrypted;
  for (size_t block_num = start_block; block_num < num_blocks; ++block_num) {
    decrypt_block(decrypted, block_num, block_size, blackbox);
  }

  return decrypted;
}


bytearray decrypt_prepad(encryption_func oracle) {
  const size_t block_size = find_block_size(encryption_oracle_prepad);
  const size_t pad = block_size - find_prepad_length(encryption_oracle_prepad);
  const size_t start_block = 1;

  auto wrapper = [pad, oracle](const bytearray& pt) {
    bytearray _pt(pad, 'A');
    _pt = _pt + pt;

    return oracle(_pt);
  };

  return decrypt(wrapper, start_block);
}



