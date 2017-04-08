#pragma once

#include <algorithm>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include <boost/functional/hash.hpp>

using namespace std;

using BYTE = uint8_t;
using BYTES = vector<uint8_t>;

class bytearray {
 private:
  BYTES bytes;

 public:
  using iterator = decltype(bytes)::iterator;
  using const_iterator = decltype(bytes)::const_iterator;

  bytearray() {}
  bytearray(const string& s);
  bytearray(const BYTES& v);

  bytearray(BYTES&& v) : bytes(v) {}
  bytearray(const size_t n) : bytes(n) {}
  bytearray(const size_t n, const BYTE b);

  bytearray(const_iterator start, const_iterator end) : bytes(start, end) {}

  bytearray(bytearray&& rhs);
  bytearray(const bytearray& rhs) : bytes(rhs.bytes) {}
  bytearray& operator=(bytearray&& rhs);
  bytearray& operator=(bytearray& rhs) = default;

  iterator begin() {
    return bytes.begin();
  }

  iterator end() {
    return bytes.end();
  }

  auto rbegin() {
    return bytes.rbegin();
  }

  auto rend() const {
    return bytes.crend();
  }

  auto rbegin() const {
    return bytes.crbegin();
  }

  auto rend() {
    return bytes.rend();
  }

  const_iterator begin() const {
    return bytes.begin();
  }
  const_iterator end() const {
    return bytes.end();
  }

  bytearray& operator=(const string& s);
  bool operator==(const bytearray& rhs);
  bool operator==(const bytearray& rhs) const;

  bytearray operator^(const bytearray& rhs) const;
  bytearray operator^(const BYTE rhs) const;
  BYTE operator[](size_t index) const;
  BYTE& operator[](size_t index) {
    return bytes[index];
  }

  unsigned char* ptr() {
    return static_cast<unsigned char*>(&bytes[0]);
  }

  // this is... not good
  unsigned char* const_ptr() const {
    return const_cast<unsigned char*>(
        reinterpret_cast<const unsigned char*>(&bytes[0]));
  }

  friend size_t hash_value(const bytearray& b) {
    size_t seed = 0;

    for (const BYTE& v : b.bytes) {
      boost::hash_combine(seed, v);
    }

    return seed;
  }

  friend ostream& operator<<(ostream& os, const bytearray& b) {
    for (const auto& byte : b.bytes) {
      os << byte;
    }

    return os;
  }

  friend bytearray& operator+(bytearray& lhs, const bytearray&& rhs) {
    return lhs.extend(rhs);
  }

  friend bytearray& operator+(bytearray& lhs, const bytearray& rhs) {
    return lhs.extend(rhs);
  }

  size_t size() const;
  string to_base64() const;
  void resize(size_t size) {
    bytes.resize(size);
  }

  string to_str() {
    string s;
    copy(bytes.begin(), bytes.end(), back_inserter(s));

    return s;
  }
  void push_back(BYTE b);
  bytearray& extend(const bytearray& rhs);

  bytearray reverse() {
    BYTES b(bytes);
    std::reverse(b.begin(), b.end());

    return bytearray(b);
  }
};

bool is_ascii(const bytearray& bytes);
