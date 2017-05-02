#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/independent_bits.hpp>
#include <memory>

#include "bigint.h"
#include "hex.h"
#include "picosha2.h"

namespace Simple {

const bigint n = bigint(
    "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff");

const bigint g = 2;
const bigint k = 3;

using generator_type =
    boost::random::independent_bits_engine<std::mt19937, 128, bigint>;

generator_type gen;

bigint SHA256(bigint salt, string value) {
  const string H = picosha2::hash256_hex_string(
      hex::decode(to_str(salt) + hex::encode(value)).to_str());

  return bigint("0x" + H);
}

class CommonParameters {
 public:
  bigint A;
  bigint B;
  bigint v;
  bigint x;
  bigint u;
  bigint salt;
  bigint S;
  bigint K;
};

class Client;

class Server : public CommonParameters {
 public:
  Client* client = nullptr;

  bigint b;

  string username = "username";
  string password = "password";

  string client_username;
  string hmac;

  Server() {
    salt = gen();
    u = gen();

    b = gen() % n;
    x = SHA256(salt, password);
    v = powm(g, x, n);
    B = powm(g, b, n);
  }

  void set_param(string _username, bigint _A) {
    client_username = _username;
    A = _A;

    bigint tmp = powm(v, u, n);

    S = powm(A * tmp, b, n);
    K = bigint("0x" + hex::encode(sha1(S).to_str()));
  }

  Server& listen(Client* c);
  Server& send_param();

  bool validate_hmac(const string& client_hmac) {
    hmac = client_hmac;
    return client_hmac == hmac_sha256(K, salt);
  }

  string crack_hmac() {
    const vector<string> dictionary = {"the", "man", "castle", "passwor"};

    string password;
    for (const auto& candidate : dictionary) {
      bigint x = SHA256(salt, candidate);
      bigint v = powm(g, x, n);

      bigint tmp = powm(v, u, n);
      bigint S = powm(A * tmp, b, n);
      bigint K = bigint("0x" + hex::encode(sha1(S).to_str()));

      if (hmac_sha256(K, salt) == hmac) {
        password = candidate;
        break;
      }
    }

    return password;
  }
};

class Client : public CommonParameters {
 public:
  Server* server;

  bigint a;
  string username;
  string password;

  Client(string _username, string _password) {
    username = _username;
    password = _password;
    a = gen() % n;
    A = powm(g, a, n);
  }

  void set_param(bigint _salt, bigint _B, bigint _u) {
    salt = _salt;
    B = _B;
    u = _u;

    x = SHA256(salt, password);

    S = powm(B, (a + u * x), n);
    K = bigint("0x" + hex::encode(sha1(S).to_str()));
  }

  void send_param() {
    server->set_param(username, A);
  }

  void set_server(Server* s) {
    server = s;
  }

  string send_hmac() {
    string hmac = hmac_sha256(K, salt);
    bool valid = server->validate_hmac(hmac);

    string status = "ERROR";
    if (valid) {
      status = "OK";
    }

    return status;
  }
};

Server& Server::send_param() {
  client->set_param(salt, B, u);
  return *this;
}

Server& Server::listen(Client* c) {
  client = c;
  client->set_server(this);
  return *this;
}
}
