#include "oracle/aes.h"

namespace oracle {
namespace aes  {

bytearray random_bytes(size_t size) {
  bytearray bytes;
  for (size_t i = 0; i < size; ++i) {
    BYTE random_byte = rd();
    bytes.push_back(random_byte);
  }

  return bytes;
}

}}
