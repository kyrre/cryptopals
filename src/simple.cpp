#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <random>

#include "fs.h"
//#include "analysis/aes.h"
//#include "methods/padding.h"
//#include "methods/aes.h"
//#include "oracle/aes.h"
//#include "oracle/profile.h"

using namespace std;
//using namespace oracle::aes;

//template<typename T> T choice(const vector<T>& v) {
//	std::random_device random_device;
//	std::mt19937 engine{random_device()};
//	std::uniform_int_distribution<int> dist(0, v.size() - 1);
//
//	return v[dist(engine)];
//}



//const bytearray _key = random_aes_key();
//
//// should returne pair(cipher, iv)
//bytearray encrypt_random_line() {
//
//	const vector<string> lines = {"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
//															  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
//															  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
//															  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
//															  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
//															  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
//															  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
//															  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
//															  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
//															  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};
//
//  auto cipher = aes_cbc_encrypt(base64::decode(lines[1]), _key);
//
//	return cipher;
//}


int main() {


	//const bytearray c = encrypt_random_line();

	//bytearray d;
	//for(size_t i = 1; i <= 16; ++i) {
	//	for(BYTE z = 0x1; z < 0xff; ++z ) {

	//		bytearray cipher = c;

	//		size_t pad = d.size() + 1;
	//		size_t j;

	//		// ah. fucker opp her
	//		for(j = 0; j < i-1; ++j) {
	//			cipher[16 - j - 1] ^= d[j] ^ pad;
	//		}

	//		cipher[16 - j - 1] ^= z ^ pad;

	//		auto pt = aes_cbc_decrypt(cipher, _key);
	//		bool valid = valid_padding(slice(pt, 16, 16));

	//		//cout << slice(pt, 16, 16) << endl;
	//		if (valid) {
	//		  cout << "VALID z=" << static_cast<int>(z) << endl;
	//			d.push_back(z);
	//			break;
	//		}
	//	}
	//}

	//cout << d << endl;
}
