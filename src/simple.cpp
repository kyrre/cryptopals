#include <algorithm>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <unordered_map>

#include "analysis/aes.h"
#include "fs.h"
#include "methods/aes.h"
#include "methods/padding.h"
#include "oracle/aes.h"
#include "oracle/profile.h"

using namespace std;
using namespace oracle::aes;


int main() {

  bytearray cipher(base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="));
  bytearray key("YELLOW SUBMARINE");

	cout << aes_ctr(cipher, key) << endl;

}
