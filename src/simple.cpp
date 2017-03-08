#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <iostream>
#include <unordered_map>

#include "ecb/cut_and_paste.h"

using namespace std;

int main() {
  ECB::Profile p = ECB::change_profile_role(key, "john@gmail.com");

  cout << p.role << endl;
}
