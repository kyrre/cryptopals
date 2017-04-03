#pragma once

#include "bytearray.h"
#include <string>
#include <vector>

using namespace std;

string read(const string& filename);
bytearray read_base64(const string& filename);
vector<string> read_lines(const string& filename);
