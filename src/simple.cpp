#include <iostream>
#include <map>

#include "aes.h"
#include "bytearray.h"
#include "encryption.h"
#include "frequency_analysis.h"
#include "fs.h"
#include "hex.h"
#include "oracle.h"

using namespace std;

int main() {

  auto &blackbox = cipher_source;
  size_t block_size = find_block_size(blackbox);
  encryption_mode mode = detect_encryption_mode(blackbox);

  bytearray plaintext(block_size - 1, 'A');
  bytearray cipher = blackbox(plaintext);

  vector<pair<BYTE, bytearray>> candidates;
  for (BYTE byte = 0; byte < 0xff; ++byte) {

    bytearray pt(string(block_size - 1, 'A'));
    pt.push_back(byte);

    auto cipher = blackbox(pt);
    bytearray first_chunk = first(cipher, block_size);

    candidates.push_back(make_pair(byte, first_chunk));
  }

  auto first_block = first(cipher, block_size);

  for (auto &candidate : candidates) {
    if (candidate.second == first_block) {
      cout << candidate.first << endl;
    }
  }
}
