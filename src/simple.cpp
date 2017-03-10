#include <algorithm>
#include <iostream>
#include <unordered_map>

#include "analysis/aes.h"
#include "oracle/aes.h"
#include "oracle/profile.h"

using namespace std;
using namespace oracle::aes;


int main() {
  using namespace oracle::aes;
  Profile p = change_profile_role("foo@bar", "admin");

  cout << p.role << endl;

}
