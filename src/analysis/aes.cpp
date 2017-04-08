#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/aes.h"
#include "analysis/frequency_analysis.h"
#include "bytearray.h"
#include "hex.h"
#include "utils.h"

namespace aes {

using namespace std;

bytearray find_ecb_encrypted_line(const vector<string>& lines) {
  string encrypted_line;

  for (const string& line : lines) {
    if (line == "")
      continue;

    block_counter blocks = unique_block_counts(hex::decode(line));

    for (auto& b : blocks) {
      if (b.second != 1) {
        encrypted_line = line;
      }
    }
  }

  return hex::decode(encrypted_line);
}

// pad until next block is detected
size_t find_padding_length(encryption_func& encrypt, size_t padding_size) {
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

size_t find_prepad_length(encryption_func func, const size_t block_size) {
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
encryption_mode detect_encryption_mode(encryption_func oracle,
                                       const size_t block_size) {
  const bytearray chosen_plaintext(block_size * 100, 'A');
  bytearray cipher = oracle(chosen_plaintext);

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
                         encryption_func oracle) {
  const size_t padding_size = block_size - offset;
  unordered_map<bytearray, BYTE, boost::hash<bytearray>> table;

  for (BYTE byte = 0; byte < 0xff; ++byte) {
    bytearray plaintext(padding_size, 'A');
    plaintext = plaintext + decrypted;
    plaintext.push_back(byte);

    bytearray cipher = oracle(plaintext);
    bytearray block = nth_block(cipher, block_size, block_num);

    table[block] = byte;
  }

  return table;
}

BYTE decrypt_byte(const bytearray& decrypted,
                  size_t offset,
                  size_t block_num,
                  size_t block_size,
                  encryption_func oracle) {
  size_t padding_size = block_size - offset;

  BYTE byte;
  bytearray plaintext(padding_size, 'A');
  bytearray cipher = oracle(plaintext);

  auto candidates =
      create_lookup_table(decrypted, offset, block_num, block_size, oracle);
  const bytearray block = nth_block(cipher, block_size, block_num);

  byte = candidates[block];

  return byte;
}

bytearray& decrypt_block(bytearray& decrypted,
                         size_t block_num,
                         size_t block_size,
                         encryption_func oracle) {
  for (size_t offset = 1; offset <= block_size; ++offset) {
    BYTE byte = decrypt_byte(decrypted, offset, block_num, block_size, oracle);
    decrypted.push_back(byte);
  }

  return decrypted;
}

bytearray decrypt(encryption_func oracle, size_t start_block) {
  size_t block_size = find_block_size(oracle);
  encryption_mode mode = detect_encryption_mode(oracle);

  if (mode != ECB) {
  }

  bytearray empty;
  size_t num_blocks = oracle(empty).size() / block_size;

  bytearray decrypted;
  for (size_t block_num = start_block; block_num < num_blocks; ++block_num) {
    decrypt_block(decrypted, block_num, block_size, oracle);
  }

  return decrypted;
}

bytearray decrypt_prepad(encryption_func oracle) {
  const size_t block_size = find_block_size(oracle);
  const size_t pad = block_size - find_prepad_length(oracle);
  const size_t start_block = 1;

  auto wrapper = [pad, oracle](const bytearray& pt) {
    bytearray _pt(pad, 'A');
    _pt = _pt + pt;

    return oracle(_pt);
  };

  return decrypt(wrapper, start_block);
}


size_t shortest_size(const vector<bytearray>& ciphers) {
  size_t min_length = numeric_limits<size_t>::max();

  for (const auto& cipher : ciphers) {
    min_length = min(min_length, cipher.size());
  }

  return min_length;
}

vector<bytearray> construct_pseudo_sentences(const vector<bytearray>& ciphers) {
  vector<bytearray> sentences(ciphers.size());
  for (const auto& cipher : ciphers) {
    for (size_t i = 0; i < ciphers.size(); ++i) {
      sentences[i].push_back(cipher[i]);
    }
  }

  return sentences;
}

bytearray brute_force_keystream(const vector<bytearray>& ciphers) {
  auto sentences = construct_pseudo_sentences(ciphers);

  bytearray keystream;
  for (auto& sentence : sentences) {
    auto current_keystream_byte = frequency_analysis(sentence).key;
    keystream.push_back(current_keystream_byte);
  }
  return keystream;
}

}
