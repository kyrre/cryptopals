#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "bytearray.h"

namespace aes {

using namespace std;

using encryption_mode = int;
const encryption_mode ECB = 0;
const encryption_mode CBC = 1;

bytearray oracle_func(const bytearray& plaintext);
using encryption_func = std::function<decltype(oracle_func)>;

using block_counter =
    std::unordered_map<bytearray, size_t, boost::hash<bytearray>>;

bytearray find_ecb_encrypted_line(const vector<string>& lines);

// pad until next block is detected
size_t find_padding_length(encryption_func& encrypt, size_t padding_size = 1);

size_t find_prepad_length(encryption_func func, const size_t block_size = 16);

/* pad until new block then pad again from new block to find block size. */
size_t find_block_size(encryption_func encrypt);

// this is a probabilistic test, but very unlikely to break!
encryption_mode detect_encryption_mode(encryption_func oracle,
                                       const size_t block_size = 16);
auto create_lookup_table(const bytearray& decrypted,
                         size_t offset,
                         size_t block_num,
                         size_t block_size,
                         encryption_func oracle);

BYTE decrypt_byte(const bytearray& decrypted,
                  size_t offset,
                  size_t block_num,
                  size_t block_size,
                  encryption_func oracle);

bytearray& decrypt_block(bytearray& decrypted,
                         size_t block_num,
                         size_t block_size,
                         encryption_func oracle);

bytearray decrypt(encryption_func oracle, size_t start_block = 0);
bytearray decrypt_prepad(encryption_func oracle);

bytearray brute_force_keystream(const vector<bytearray>& ciphers);
vector<bytearray> read_challenge_files(const string& filename);



}
