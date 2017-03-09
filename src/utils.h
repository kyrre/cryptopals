#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>

using std::vector;
using std::string;
using std::unordered_map;

vector<string> split(const string& s, const string& sep) {
  vector<string> lines;
  boost::split(lines, s, boost::is_any_of(sep));

  return lines;
}

pair<string, string> key_value(const string& s) {
  vector<string> kv = split(s, "=");

  return make_pair(kv[0], kv[1]);
}

unordered_map<string, string> parse_query_string(const string& query_str) {
  unordered_map<string, string> kv;
  for (auto& token : split(query_str, "&")) {
    string key, value;
    tie(key, value) = key_value(token);

    kv[key] = value;
  }

  return kv;
}
