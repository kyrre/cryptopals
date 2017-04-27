#include <algorithm>
#include <chrono>
#include <sstream>

#include <iostream>
#include <random>
#include <thread>
#include <unordered_map>

#include "fs.h"

#include "analysis/aes.h"
#include "analysis/frequency.h"

#include "methods/aes.h"
#include "methods/padding.h"

#include "oracle/aes.h"
#include "oracle/profile.h"

#include "hex.h"
#include "sha1.h"

#include "dh.h"
#include "dh_message.h"

#include "picosha2.h"

int main() {


  bigint p =
      bigint(
      "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
      "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
      "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
      "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
      "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
      "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
      "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
      "fffffffffffff");

   cpp_int g = 2;
   cpp_int k =3;

   string I = "email";
   string P = "password";

   cpp_int salt = gen();



   string input = picosha2::hash256_hex_string(hex::decode(to_str(salt) + hex::encode(P)).to_str());

   cout << input << endl;



   //cpp_int xH = cpp_int("0x" + 
   //string s = sha1_str(to_str(salt) + P).to_str();

   //cout << s << endl;
   //xH=SHA256(salt|password)
   // Generate salt as random integer
     
}
