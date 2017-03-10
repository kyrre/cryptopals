#include <algorithm>
#include <iostream>
#include <unordered_map>

#include "analysis/aes.h"
#include "oracle/aes.h"

using namespace std;

int main() {
  cout << aes::decrypt(oracle::aes::encryption_oracle);
}
