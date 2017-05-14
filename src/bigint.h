#pragma once

#include <sstream>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>

#include "bigint.h"
#include "bytearray.h"

using namespace std;
using namespace boost::multiprecision;

using bigint = cpp_int;

string to_str(cpp_int i);
bytearray sha1(const string& s);
bytearray sha1(cpp_int i);
string hmac_sha256(bigint _key, bigint message);
bigint string_to_bigint(const string& s);

bigint invmod(bigint a, bigint b);
bigint chinese_remainder(vector<bigint>& n, vector<bigint>& a);
bigint cube(bigint n);
bigint cbrt(bigint n);
pair<bigint, bool> cbrt_close(bigint n);
string sha256(const string& a);
