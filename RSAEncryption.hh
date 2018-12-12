#pragma once
#include "BigInteger.hh"
#include "SHA256/SHA256.hh"
#include <string>
#include <iostream>
#include<sstream>
#include <math.h>
#include <assert.h>
#include <bitset>
#include <vector>
#include <new>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <future>
#include <pthread.h>

using namespace std;

class RSAEncryption
{
private:
	BigUnsigned myE;
	BigUnsigned myN;
	BigUnsigned myP;
	BigUnsigned myQ;
	BigUnsigned myD;
	int maxEncryptableCharacters;
	static bool isPrime(BigUnsigned SizeInBits); 
	static BigUnsigned generatePrime(int SizeInBits);
	BigUnsigned encryptBytes(BigUnsigned encryptText);
	BigUnsigned decryptBytes(BigUnsigned Data);
	void createRSAKeys(int bits);
	bool AttemptToLoadKeys();
	void calculateDAndE();
	void WritePrimes();
	void writePublicKey();
	void writePrivateKey();
	void PrintError(); 
public:
	void signFile(string FileLocation);
	bool verifyFile(std::string myFileToCheck, std::string mySignature);
	void part1OfProject();
	


	
	//string encryptBytes(string myInputStream);
	//string decryptBytes(string myInputStream, string myOutputStream);



	RSAEncryption();
	~RSAEncryption();
};


