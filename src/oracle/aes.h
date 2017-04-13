#pragma once
#include <functional>
#include <random>

#include "bytearray.h"

namespace oracle {
namespace aes {

static random_device rd;
static mt19937 rng(rd());
static uniform_int_distribution<int> r_pad(5, 10);

using encryption_mode = int;
const encryption_mode ECB = 0;
const encryption_mode CBC = 1;

bytearray oracle_func(const bytearray& plaintext);
using encryption_func = std::function<decltype(oracle_func)>;

bytearray random_bytes(size_t size);
int random_padding_size();

bytearray random_aes_key(const size_t key_size = 16);

bytearray encryption_oracle_mode(const bytearray& plaintext,
                                 const size_t block_size = 16);
bytearray encryption_oracle(const bytearray& plaintext);
bytearray encryption_oracle_prepad(const bytearray& plaintext);
bytearray encryption_oracle_cbc(const string& chosen_plaintext);

bool decrypt_oracle_cbc(const bytearray& cipher);

bytearray bit_flipping_cbc(const string& wanted = ";admin=true;");

template <typename T>
T choice(const vector<T>& v) {
  std::random_device random_device;
  std::mt19937 engine{random_device()};
  std::uniform_int_distribution<int> dist(0, v.size() - 1);

  return v[dist(engine)];
}

bytearray encrypt_random_line();

bool padding_oracle(const bytearray& cipher,
                    size_t start_position,
                    size_t block_size = 16);

bytearray cbc_attack_block(const bytearray& c,
                           size_t n_block,
                           size_t block_size = 16);

bytearray encryption_oracle_ctr(const string& chosen_plaintext);
bool decrypt_oracle_ctr(const bytearray& cipher);

bytearray edit(const bytearray& ciphertext,
               const bytearray& key,
               size_t offset,
               const bytearray& new_text);


extern const bytearray key;
extern const bytearray random_pre_padding;
}
}
