#include <memory>

#include "dh.h"
#include "bigint.h"
#include "hex.h"

#include "picosha2.h"
#include "srp/client.h"
#include "srp/server.h"


void Client::set_param(bigint _salt, bigint _B) {
  salt = _salt;
  B = _B;

  string uH = picosha2::hash256_hex_string(
      hex::decode(to_str(A) + to_str(B)));

  u = bigint("0x" + uH);

  string xH = picosha2::hash256_hex_string(
      hex::decode(to_str(salt) + hex::encode(P)).to_str());
  x = cpp_int("0x" + xH);

  v = powm(g, x, N);


  //pow(B - k * pow(g, x, N), a + u * x, N)
  cpp_int tmp_1 = (B - k * v);
  bigint tmp_2 = (a + u * x) % N;

  S = powm(tmp_1, tmp_2, N);

  K = bigint("0x" + hex::encode(sha1(S).to_str()));

  cout << K << endl;

}

Client::Client() {
  a = gen() % N;
  A = powm(g, a, N);
}

Client& Client::connect(const Server& s) {
  server = make_shared<Server>(s);
  server->connect(*this);

  return *this;
}

void Client::login() {
  server->login(I, A);
}
