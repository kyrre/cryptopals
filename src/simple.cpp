#include <iostream>
#include <unordered_map>

#include "aes.h"
#include "bytearray.h"
#include "encryption.h"
#include "frequency_analysis.h"
#include "fs.h"
#include "hex.h"
#include "oracle.h"

using namespace std;

int main() {
  bytearray decrypted = decryption_oracle(cipher_source);
  cout << decrypted;
}
