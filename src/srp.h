#pragma once


#include "bigint.h"
#include "picosha2.h"


class Server {
public:

   bigint N =
      bigint(
      "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
      "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
      "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
      "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
      "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
      "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
      "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
      "fffffffffffff");

   bigint g = 2;
   bigint k = 3;

   bigint salt;
   bigint v;

   Server() {

     string I = "email";
     string P = "password";

     salt = gen();

     string xH = picosha2::hash256_hex_string(
         hex::decode(to_str(salt) + hex::encode(P)).to_str());

     bigint x = cpp_int("0x" + xH);

     v = powm(g, x, N);
  }

};

class Client {
  public:
  Server& server;

  void connect(Server& s) {
    server = s;
  }

};
