#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>
#include <random>

#include "bigint.h"

namespace DiffieHellman {

using namespace boost::multiprecision;

using generator_type =
    boost::random::independent_bits_engine<std::mt19937, 256, bigint>;

extern generator_type gen;

class DH {
 public:
  bigint g;
  bigint p;
  bigint a;
  bigint A;

  DH(bigint _p = bigint(
         "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
         "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
         "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
         "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
         "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
         "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
         "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
         "fffffffffffff"),
     bigint _g = bigint(2));

  DH(const DH& r) = default;
  DH& operator=(const DH& r) = default;
};
}
