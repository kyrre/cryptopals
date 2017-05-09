#include <memory>

#include "bigint.h"
#include "dh.h"
#include "hex.h"

#include "picosha2.h"
#include "srp/client.h"
#include "srp/server.h"

void Client::set_param(bigint _salt, bigint _B) {
  salt = _salt;
  B = _B;

  string uH = picosha2::hash256_hex_string(hex::decode(to_str(A) + to_str(B)));

  u = bigint("0x" + uH);

  string xH = picosha2::hash256_hex_string(
      hex::decode(to_str(salt) + hex::encode(P)).to_str());
  x = cpp_int("0x" + xH);

  v = powm(g, x, N);

  // pow(B - k * pow(g, x, N), a + u * x, N)
  cpp_int tmp_1 = (B - k * v);
  bigint tmp_2 = (a + u * x) % N;

  cout << A << endl;
  if (A == 0) {
    S = 0;
  } else {
    S = powm(tmp_1, tmp_2, N);
  }

  cout << S << endl;

  K = bigint("0x" + hex::encode(sha1(S).to_str()));
}

Client::Client() {
  a = DiffieHellman::gen() % N;
  A = powm(g, a, N);
}

Client& Client::connect(Server* s) {
  server = s;
  server->connect(this);

  return *this;
}

Client& Client::login() {
  server->login(I, A);

  return *this;
}

Client& Client::passwd() {
  string hmac = hmac_sha256(K, salt);
  server->passwd(hmac);

  return *this;
}

Client::Client(string _I, string _P) {
  I = _I;
  P = _P;

  a = DiffieHellman::gen() % N;
  A = powm(g, a, N);
}

Client::Client(string _I, string _P, bigint _N) {
  N = _N;

  I = _I;
  P = _P;

  a = DiffieHellman::gen() % N;
  A = powm(g, a, N);
}
