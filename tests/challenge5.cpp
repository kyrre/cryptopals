#include <catch.hpp>

#include "bytearray.h"
#include "dh.h"
#include "dh_message.h"
#include "methods/rsa.h"
#include "srp_simple/simple.h"
#include "utils.h"

TEST_CASE("Diffie-Hellman") {
  DiffieHellman::DH param_1;
  DiffieHellman::DH param_2;

  bigint s = powm(param_2.A, param_1.a, param_1.p);
  bigint _s = powm(param_1.A, param_2.a, param_2.p);

  REQUIRE(s == _s);
}

TEST_CASE("Diffie-Hellman MITM") {
  NormalParticipant alice;
  NormalParticipant bob;
  Middleman mallory;

  alice.connect(mallory);
  mallory.connect(bob);

  bob.respond(mallory);
  mallory.respond(alice);

  bytearray message("text");

  Participant& src = bob;
  Participant& dest = alice;

  Message intercept = src.send(message);

  REQUIRE(mallory.recv(intercept) == message);

  bytearray recv_message = dest.recv(mallory.relay(intercept));

  REQUIRE(recv_message == message);
}

TEST_CASE("DH Chosen Group") {
  NormalParticipant alice;
  NormalParticipant bob;

  MiddlemanGroup mallory(1);

  alice.connect(mallory);
  mallory.connect(bob);

  bob.respond(mallory);
  mallory.respond(alice);

  bytearray message("text");

  Participant& src = alice;
  Participant& dest = bob;

  Message intercept = src.send(message);

  REQUIRE(mallory.recv(intercept) == message);
}

TEST_CASE("Simple SRP Dictionary Attack") {
  Simple::Server server;
  Simple::Client client("username", "passwor");

  server.listen(&client);

  // I, A = g**a % n
  client.send_param();

  // salt, B = g**b % n, u = 128 bit random number
  server.send_param();

  REQUIRE(client.send_hmac() == "ERROR");
  REQUIRE(server.crack_hmac() == "passwor");
}

TEST_CASE("RSA") {
  rsa::PrimeGenerator generator;

  bigint p = generator();
  bigint q = generator();
  bigint n = p * q;

  bigint et = (p - 1) * (q - 1);
  bigint e = 3;
  bigint d = invmod(e, et);

  string plaintext = "test";
  bigint c = rsa::encrypt(plaintext, e, n);
  string pt = rsa::decrypt(c, d, n);

  REQUIRE(plaintext == pt);
}

TEST_CASE("RSA e=3") {
  rsa::RSA keys1;
  rsa::RSA keys2;
  rsa::RSA keys3;

  string plaintext = "test";

  bigint cipher_1 = keys1.encrypt(plaintext);
  bigint cipher_2 = keys2.encrypt(plaintext);
  bigint cipher_3 = keys3.encrypt(plaintext);

  vector<bigint> n = {keys1.n, keys2.n, keys3.n};
  vector<bigint> a = {cipher_1, cipher_2, cipher_3};

  bigint p = cbrt(chinese_remainder(n, a));

  REQUIRE(rsa::bigint_to_string(p) == plaintext);
}

TEST_CASE("No padding RSA") {
  rsa::RSA keys1;

  string plaintext = "{\"name\":\"Tom\"}";
  bigint C = keys1.encrypt(plaintext);

  REQUIRE(no_padding_attack(C, keys1) == plaintext);
}
