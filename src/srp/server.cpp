#include <memory>

#include "bigint.h"
#include "dh.h"
#include "hex.h"
#include "picosha2.h"

#include <boost/multiprecision/cpp_int.hpp>

#include "srp/client.h"
#include "srp/server.h"

Server::Server() {
  salt = DiffieHellman::gen();

  string xH = picosha2::hash256_hex_string(
      hex::decode(to_str(salt) + hex::encode(P)).to_str());

  x = cpp_int("0x" + xH);

  b = DiffieHellman::gen() % N;
  v = powm(g, x, N);
}

void Server::login(string& _I, cpp_int _A) {
  A = _A;

  B = powm(g, b, N);
  B = (k * v) + B;

  //(k * v + pow(g, b, N)) % N

  string uH = picosha2::hash256_hex_string(hex::decode(to_str(A) + to_str(B)));

  u = bigint("0x" + uH) % N;

  bigint tmp_1 = powm(v, u, N);
  S = powm(A * tmp_1, b, N);
  K = bigint("0x" + hex::encode(sha1(S).to_str()));

  cout << S << endl;
  client->set_param(salt, B);
}

void Server::connect(Client* c) {
  client = c;
}

void Server::passwd(const string& hmac) {
  string _hmac = hmac_sha256(K, salt);
  if (hmac == _hmac) {
    client->status = "OK";
  } else {
    client->status = "ERROR";
  }
}
