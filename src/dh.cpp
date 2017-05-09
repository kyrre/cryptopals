#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>
#include <random>

#include "dh.h"

DiffieHellman::generator_type DiffieHellman::gen;

DiffieHellman::DH::DH(bigint _p, bigint _g) : p(_p), g(_g) {
  a = DiffieHellman::gen() % _p;
  A = powm(_g, a, _p);
}
