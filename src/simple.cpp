#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <functional>
#include <iostream>
#include <unordered_map>

#include "aes.h"
#include "oracle.h"

using namespace std;


int main() {

  using namespace std::placeholders;

  const size_t block_size = find_block_size(encryption_oracle_prepad);
  const size_t pad = block_size - find_prepad_length(encryption_oracle_prepad);

  auto w = [pad](const bytearray& pt) {
    bytearray _pt(pad, 'A');
    _pt = _pt + pt;

    return encryption_oracle_prepad(_pt);
  };

  cout << decrypt(w, 1) << endl;
}
