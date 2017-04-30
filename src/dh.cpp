#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>
#include <random>

#include "dh.h"

generator_type gen;

DH::DH(bigint _p, bigint _g) : p(_p), g(_g) {
  a = gen() % _p;
  A = powm(_g, a, _p);
}
