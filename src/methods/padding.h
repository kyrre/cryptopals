#pragma once

#include "bytearray.h"

bytearray pkcs(const bytearray& b, size_t block_size=16);
bytearray strip_pkcs(const bytearray& b);
bool valid_padding(const bytearray& b);
