#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <streambuf>

#include <algorithm>
#include <cmath>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <thread>
#include <unordered_map>

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/dsa.h"
#include "methods/padding.h"
#include "methods/rsa.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "dh.h"
#include "fs.h"

#include "bigint.h"
#include "compression.h"
#include "hex.h"
#include "mac.h"
#include "sha1.h"

#include <boost/format.hpp>
#include <cppcodec/base64_default_rfc4648.hpp>

string format_request(const string& payload) {
  auto request =
      boost::format(
          "POST / HTTP/1.1\n"
          "Host: hapless.com\n"
          "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
          "Content-Length: %1%\n"
          "%2%\n") %
      payload.size() % payload;

  return request.str();
}

size_t compression_oracle(const string& payload) {
  bytearray key("YELLOW SUBMARINE");
  return aes_ctr(compress_string(format_request(payload)), key).size();
}

int main() {
  string payload = "test";

  cout << compression_oracle(payload) << endl;

  return EXIT_SUCCESS;
}
