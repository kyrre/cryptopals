/*
    sha1.hpp - header of

    ============
    SHA-1 in C++
    ============

    100% Public Domain.

    Original C Code
        -- Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        -- Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        -- Volker Grabsch <vog@notjusthosting.com>
    Safety fixes
        -- Eugene Hopkinson <slowriot at voxelstorm dot com>
*/

#pragma once

#include "bytearray.h"
#include <vector>

#include <cstdint>
#include <iostream>
#include <string>

class SHA1 {
 public:
  SHA1();
  SHA1(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);

  void update(const std::string& s);
  void update(std::istream& is);
  std::string final();
  static std::string from_file(const std::string& filename);
  std::string get_digest();

  uint32_t digest[5];
  std::string buffer;
  uint64_t transforms;
};

std::vector<uint32_t> sha1_state(const bytearray& m);
std::string get_pad(std::string const& input, const size_t extra = 0);
std::string pad(std::string const& input, const size_t extra = 0);

string compute_mac_value(const string& data, const string secret_key = "AAAA");
bool authenticate(const string& message, const string& mac);

SHA1 clone(const string& hash_value);
pair<string, string> forge_message(const string& hash_value,
                                   const string& original_message,
                                   const size_t secret_key_size = 4);
