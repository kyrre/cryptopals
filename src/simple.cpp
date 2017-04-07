#include <algorithm>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <random>
#include <unordered_map>

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "fs.h"
#include "methods/aes.h"
#include "methods/padding.h"
#include "oracle/aes.h"
#include "oracle/profile.h"


using namespace std;
using namespace oracle::aes;


int main() {


  const bytearray key = random_aes_key();


  const string filename = "/home/kyrre/projects/cryptopals/tests/data/19.txt";
  const vector<string> lines = read_lines(filename);
  vector<bytearray> ciphers;

  transform(lines.cbegin(), lines.cend(), back_inserter(ciphers),
      [&key] (auto& line) {
        return aes_ctr(base64::decode(line), key);
      }
  );


  vector<bytearray> sentences(lines.size());
  for (auto & cipher : ciphers) {
    for (size_t i = 0; i < cipher.size(); ++i) {
      sentences[i].push_back(cipher[i]);
    }
  }



  vector<bytearray> pt(lines.size());
  for(auto &sentence : sentences) {
    auto __key = frequency_analysis(sentence).key;

    bytearray plaintext = (sentence ^ __key);

    for (size_t i = 0; i < plaintext.size(); ++i) {
      pt[i].push_back(plaintext[i]);
    }


  }

  cout << pt[1] << endl;






}
