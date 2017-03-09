#include <algorithm>
#include <iostream>
#include <unordered_map>

#include "aes.h"
#include "oracle.h"

using namespace std;


int main() {

  cout << decrypt_prepad(encryption_oracle_prepad) << endl;
}
