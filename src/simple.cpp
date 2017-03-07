#include <iostream>
#include <unordered_map>
#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>


#include "aes.h"
#include "bytearray.h"
#include "encryption.h"
#include "frequency_analysis.h"
#include "fs.h"
#include "hex.h"
#include "oracle.h"

using namespace std;

int main() {
  string input = "foo=bar&baz=qux&zap=zazzle";
  boost::char_separator<char> sep("&");

  using tokenizer = boost::tokenizer<boost::char_separator<char>>;

  for(auto & token: tokenizer(input, sep)) {
    cout << token << endl;

  }


  //vector<string> entries;
  //boost::split(entries, input, boost::is_any_of("&"));

  //for(const auto &entry : entries) {
  //  pair<string, string> e;
  //  boost::split(e, entry, boost::is_any_of("="));
  //}



}
