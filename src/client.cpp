#include <algorithm>
#include <chrono>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include <cppcodec/base64_default_rfc4648.hpp>

#include "fs.h"
#include "mt19937.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "hex.h"
#include "sha1.h"

#include <curl/curl.h>

using std::vector;
using std::cout;
using std::endl;

using namespace oracle::aes;
using namespace chrono;

size_t write_data(void* buffer, size_t size, size_t nmemb, void* userp) {
  return size * nmemb;
}

class HTTPClient {
 public:
  CURL* curl;

  HTTPClient() {
    curl = curl_easy_init();
  }

  bool get(const string& url) const {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    return http_code == 200;
  }

  ~HTTPClient() {
    curl_easy_cleanup(curl);
  }
};

double measure(const HTTPClient& client, const string& signature) {
  const string url =
      "http://localhost:9000/test?file=file&signature=" + signature;

  size_t trials = 1;
  std::chrono::milliseconds duration(0);
  for (size_t i = 0; i < trials; ++i) {
    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    client.get(url);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    duration += duration_cast<milliseconds>(t2 - t1);
  }

  double t = duration.count() / trials;
  return t;
}

string side_channel_attack() {
  HTTPClient client;

  string file = "file";
  string signature;

  for (size_t i = 0; i < 20; ++i) {
    double duration = 0;
    BYTE best;

    for (BYTE b = 0; b < 0xff; ++b) {
      string s = signature + hex::encode(b);
      double current_duration = measure(client, s);

      if (current_duration > duration) {
        duration = current_duration;
        best = b;
      }
    }

    signature = signature + hex::encode(best);
  }

  return signature;
}

int main() {
  cout << side_channel_attack() << endl;
}
