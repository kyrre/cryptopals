#pragma once

#include "bytearray.h"

bytearray cbc_mac(const bytearray& plaintext,
                  const bytearray& key,
                  const bytearray& IV,
                  const size_t block_size = 16);
