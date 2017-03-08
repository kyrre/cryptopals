#pragma once

#include <fstream>
#include <streambuf>
#include <string>

#include <boost/algorithm/string.hpp>
#include <cppcodec/base64_default_rfc4648.hpp>

#include "bytearray.h"

using namespace std;

string read(const string& filename) {
  ifstream t(filename);
  string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());

  return str;
}

bytearray read_base64(const string& filename) {
  string str = read(filename);
  boost::replace_all(str, "\n", "");

  return bytearray(base64::decode(str));
}

vector<string> read_lines(const string& filename) {
  ifstream t(filename);

  string content = read(filename);
  vector<string> lines;
  boost::split(lines, content, boost::is_any_of("\n"));

  return lines;
}
