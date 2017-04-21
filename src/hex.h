#pragma once
#include "bytearray.h"

namespace hex {
bytearray decode(const string& s);
string encode(const string& input);
string encode(unsigned char c);
}
