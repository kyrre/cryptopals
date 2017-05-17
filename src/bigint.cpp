#include <algorithm>
#include <sstream>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>

#include "bigint.h"
#include "hex.h"
#include "picosha2.h"
#include "sha1.h"

string to_str(bigint i) {
  stringstream ss;
  ss << std::hex << i;

  string ret;
  ss >> ret;

  std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);

  return ret;
}

bytearray sha1(const string& s) {
  SHA1 h;
  h.update(s);

  return hex::decode(h.final());
}

bytearray sha1(bigint i) {
  return sha1(to_str(i));
}

string sha256(const string& a) {
  return picosha2::hash256_hex_string(a);
}

string sha256(bigint a) {
  return sha256(hex::decode(to_str(a)).to_str());
}

string hmac_sha256(bigint _key, bigint _message) {
  bytearray key(to_str(_key));
  string message = hex::decode(to_str(_message)).to_str();

  const size_t block_size = 16;

  if (key.size() > block_size) {
    key = bytearray(sha256(key.to_str()));
  }
  if (key.size() < block_size) {
    key = key + bytearray(0x00, block_size - key.size());
  }

  bytearray o_key_pad = bytearray(0x5c, block_size) ^ key;
  bytearray i_key_pad = bytearray(0x36, block_size) ^ key;

  return sha256(o_key_pad.to_str() + sha256(i_key_pad.to_str() + message));
}

// skal det vaere encode her!?
bigint string_to_bigint(const string& s) {
  return bigint("0x" + hex::encode(s));
}

bigint invmod(bigint a, bigint b) {
  bigint b0 = b, t, q;
  bigint x0 = 0, x1 = 1;

  if (b == 1) {
    return 1;
  }

  while (a > 1) {
    q = a / b;
    t = b, b = a % b, a = t;
    t = x0, x0 = x1 - q * x0, x1 = t;
  }

  if (x1 < 0) {
    x1 += b0;
  }

  return x1;
}

bigint chinese_remainder(vector<bigint>& n, vector<bigint>& a) {
  bigint p, prod = 1, sum = 0;

  size_t i = 0;
  for (i = 0; i < n.size(); i++) {
    prod *= n[i];
  }

  for (i = 0; i < n.size(); i++) {
    p = prod / n[i];
    sum += a[i] * invmod(p, n[i]) * p;
  }

  return sum % prod;
}

bigint cube(bigint n) {
  return n * n * n;
}

bigint cbrt(bigint n) {
  bigint start = 0, end = n;

  bigint last = 0;
  while (true) {
    bigint mid = (start + end) / 2;
    bigint c = cube(mid);

    if (mid == last) {
      return 0;
    } else {
      last = mid;
    }

    if (c == n) {
      return mid;
    }

    if (c > n) {
      end = mid;
    } else {
      start = mid;
    }
  }
}

pair<bigint, bool> cbrt_close(bigint n) {
  bigint start = 0, end = n;

  bigint last = 0;
  while (true) {
    bigint mid = (start + end) / 2;
    bigint c = cube(mid);

    if (mid == last) {
      return make_pair(mid, false);
    } else {
      last = mid;
    }

    if (c == n) {
      return make_pair(mid, true);
    }

    if (c > n) {
      end = mid;
    } else {
      start = mid;
    }
  }
}

bigint subm(bigint a, bigint b, bigint m) {
  bigint r = (a - b);

  if (r < 0) {
    r = m - r;
  }

  r = r % m;
  return r;
}
