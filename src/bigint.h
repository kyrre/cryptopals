#pragma once

#include <sstream>
#include <string>

#include "bytearray.h"
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

using bigint = cpp_int;

string to_str(cpp_int i);
bytearray sha1(const string& s);
bytearray sha1(cpp_int i);
