#include <catch.hpp>

#include "bytearray.h"
#include "utils.h"
#include "dh_message.h"
#include "dh.h"
#include "srp_simple/simple.h"


TEST_CASE("Diffie-Hellman") {
  DH param_1;
  DH param_2;

  bigint s  = powm(param_2.A, param_1.a, param_1.p);
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
