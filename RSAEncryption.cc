#include "RSAEncryption.hh"
#include "BigIntegerAlgorithms.hh"
#include "BigIntegerUtils.hh"
#include "BigUnsignedInABase.hh"
#include <thread>
#include <time.h>
#include <random>
#include <stdio.h>
RSAEncryption::RSAEncryption()
{


}


RSAEncryption::~RSAEncryption()
{


}

bool RSAEncryption::verifyFile(std::string myFileToCheck, std::string mySignature)
{
	struct stat myStat;
	if (stat(myFileToCheck.c_str(), &myStat) != 0)
	{
		cout << "File: " << myFileToCheck << endl;
	}

	ifstream mySignedFile(mySignature, ios::binary);
	string EncryptedText;
	getline(mySignedFile, EncryptedText);
	cout << EncryptedText << "NO RETURN";

	if (!AttemptToLoadKeys())
	{
		cout << "Attempted to open key files failed!" << endl;
		return false;
	};
	mySignedFile.close();
	BigUnsigned myDecryptedSHA = stringToBigUnsigned(EncryptedText);
	myDecryptedSHA = encryptBytes(myDecryptedSHA);

	ifstream input(myFileToCheck, ios::binary);
	input.seekg(0, input.end);
	size_t mySize = input.tellg();
	char *myCharacter = new char[mySize];
	input.seekg(0, input.beg);
	input.read(myCharacter, mySize);
	input.close();
	std::string mySha = sha256(myCharacter, mySize);
	delete myCharacter;
	BigUnsigned Converted = BigUnsignedInABase(mySha, 16);
	//cout << "myCOnvertedBase =" << Converted << endl;
	//cout << "myDecryptedSHA =" << myDecryptedSHA;
	if (Converted == myDecryptedSHA)
	{
		cout << endl << endl << "File Verified!" << endl << endl;
		return true;
	}
	else {

		cout << "Failed to verify file!" << endl;;
		PrintError();
		return false;
	}
}



void RSAEncryption::signFile(string FileLocation)
{
	
	if (!AttemptToLoadKeys())
	{
		cout << "Error: could not find keys!" << endl;
		return;
	}
	struct stat myStuff;
	if (stat(FileLocation.c_str(), &myStuff) != 0)
	{
		FileLocation = ".\\" + FileLocation;
		if (stat(FileLocation.c_str(), &myStuff) != 0)
		{
			cout << "Failed to find file: " + FileLocation;
			return;
		}
	}
	std::ifstream input(FileLocation, ios::binary);
	input.seekg(0, input.end);
	size_t mySize = input.tellg();
	char *myCharacter = new char[mySize + 1];
	input.seekg(0, input.beg);
	input.read(myCharacter, mySize);
	input.close();
	string mySHA = sha256(myCharacter, mySize);
	BigUnsigned myConverted = BigUnsignedInABase(mySHA, 16);
	cout << "SHA that we signed: " << myConverted << endl << endl;
	myConverted = decryptBytes(myConverted);//shortend, might break;
	std::ofstream output(FileLocation + ".signed", std::ios::binary);
	output << myConverted;
	output.flush();
	output.close();
	delete myCharacter;
}



void RSAEncryption::createRSAKeys(int bits)
{
	vector<std::future<BigUnsigned>> MyFutures;
	int myKeySize = bits / 2;
	unsigned concurrentThreadsSupported = std::thread::hardware_concurrency();
	cout << "Generating 2 keys of size " << myKeySize << " bits using " << concurrentThreadsSupported << "threads:";

	clock_t encryptionTimeCompletionTime = clock();
	if (concurrentThreadsSupported < 2)
	{
		myQ = generatePrime(myKeySize);
		myP = generatePrime(myKeySize);
	}
	else {
		for (int i = 0; i < concurrentThreadsSupported; i++)
		{
			std::packaged_task<BigUnsigned(int)> Calculate(generatePrime);
			MyFutures.push_back(Calculate.get_future());
			thread myPrimePCalculator(std::move(Calculate), myKeySize);
			myPrimePCalculator.detach();
		}
	}
	if (MyFutures.size() != 0)
	{
		int FoundPrimes = 0;
		std::chrono::milliseconds span(1);
		FoundPrimes = 0;
		while (FoundPrimes < 2)
		{
				for (auto i = MyFutures.begin(); i != MyFutures.end(); i++)
				{
					if ((*i).wait_for(span) == std::future_status::ready)
					{
						if (myP == 0)
						{
							myP = (*i).get();
						}
						else
						{
							myQ = (*i).get();
						}
						FoundPrimes++;
						i = MyFutures.erase(i);
						//TO prevent passing the future it.
						if (i == MyFutures.end())
						{
							i--;
							continue;
						}
					}
				}
		}
	}
	assert(myP != myQ);

	cout << "..";
	cout << ".." << endl;
	encryptionTimeCompletionTime = clock() - encryptionTimeCompletionTime;
	float ms = double(encryptionTimeCompletionTime) / CLOCKS_PER_SEC * 1000;

	cout << endl << endl << "Time to complete in MS" << ms << endl;

	maxEncryptableCharacters = ceil(bits / 8);
	cout << "Max encryptable bits: " << maxEncryptableCharacters << endl;
	cout << "Now calculating D and E: " << endl;
	calculateDAndE();
	cout << "Writing to File: " << endl << endl;
	writePublicKey();
	writePrivateKey();
	WritePrimes();
}

bool RSAEncryption::AttemptToLoadKeys()
{
	struct stat buffer;
	if (stat("d_n.txt", &buffer) != 0)
	{
		return false;
	}
	if (stat("e_n.txt", &buffer) != 0)
	{
		return false;
	}
	std::ifstream input("d_n.txt", ios::binary);
	string lineOne;
	getline(input, lineOne);
	myD = stringToBigUnsigned(lineOne);
	getline(input, lineOne);
	myN = stringToBigUnsigned(lineOne);
	input.close();
	std::ifstream input2("e_n.txt", ios::binary);
	getline(input2, lineOne);
	myE = stringToBigUnsigned(lineOne);
	input2.close();
	return true;
}

void RSAEncryption::PrintError()
{
	cout << "My E: " << endl << bigUnsignedToString(myE) << endl << endl;
	cout << "My D: " << endl << bigUnsignedToString(myD) << endl << endl;
	cout << "My N: " << endl << bigUnsignedToString(myN) << endl << endl;
}

void RSAEncryption::calculateDAndE()
{
	myN = (myP)*(myQ);
	BigUnsigned totient = (myP - 1)*(myQ - 1);
	BigInteger myG;
	BigInteger myR;
	BigInteger MyTemp;
	BigInteger MyTempD;
	for (BigUnsigned i = rand() % 1000000; i < myN; i++)
	{//rs = x y
		extendedEuclidean(i, totient, myG, MyTempD, MyTemp);
		if ((myG) == 1)
		{
			myE = i;
			myD = modinv(myE, totient);
			break;
		}

	}
}

bool RSAEncryption::isPrime(BigUnsigned n)
{
	int testCount = 3;
	for (BigUnsigned i = 5; i < n; i++)
	{
 		if (gcd(i, n) == 1) //if our i is co prime
		{
			testCount--;
			//cout << i;
			BigUnsigned RetVal = modexp(i, (n - 1), n);
			//cout << "Retval for " << n << " equals " << RetVal << endl;
			if (RetVal != 1) return false;
			if (testCount == 0) break;
		}
	}
	return true;
}

BigUnsigned RSAEncryption::generatePrime(int SizeInBits)
{
	std::random_device rd;
	std::uniform_int_distribution<int> distribution(0, 10);

	BigUnsigned A;
	std::string myString;
	A = 2;
	do
	{
		myString = "";
		for (int i = 0; i < ceil(log10(pow(2, SizeInBits))); i++)
		{
			myString.append(to_string(distribution(rd)));
		}
		A = stringToBigUnsigned(myString);
		//cout << A << endl << endl;
	} while (!isPrime(A));// || A > (2 ^ SizeInBits) - 1);
	//cout << "IS PRIME TEST: " << isPrime(A) << endl;
	return A;
}

void RSAEncryption::part1OfProject()
{
	createRSAKeys(1024);
	WritePrimes();
	writePrivateKey();
	writePublicKey();
}

BigUnsigned RSAEncryption::encryptBytes(BigUnsigned encryptText)
{
	cout << "Clear Text: " << encryptText << endl << endl;
	BigUnsigned Encrypted = modexp(encryptText, myE, myN);
	cout << "Encrypted Text: " << Encrypted << endl << endl;
	return Encrypted;
}



BigUnsigned RSAEncryption::decryptBytes(BigUnsigned Data)
{
	cout << "Encrypted Text: " << Data << endl << endl;
	BigUnsigned myReturnedString = modexp(Data, myD, myN);
	cout << "Clear Text: " << myReturnedString << endl << endl;
	return myReturnedString;
}

void RSAEncryption::WritePrimes()
{
	ofstream myPrimeStream("p_q.txt", iostream::binary);
	if (myPrimeStream.fail())
	{
		cout << "Failed to write primes in file!";
	}
	std::string myPString = bigUnsignedToString(myP);
	myPString += "\n";
	myPrimeStream.write(myPString.c_str(), myPString.length());
	std::string myQString = bigUnsignedToString(myQ);
	myPrimeStream.write(myQString.c_str(), myQString.length());
	myPrimeStream.flush();
	myPrimeStream.close();
}

void RSAEncryption::writePrivateKey()
{

	ofstream myPrimeStream("d_n.txt", iostream::binary);
	if (myPrimeStream.fail())
	{
		cout << "Failed to write d_n in file!";
	}
	std::string myPString = bigIntegerToString(myD);
	myPString += "\n";
	myPrimeStream.write(myPString.c_str(), myPString.length());
	std::string myQString = bigUnsignedToString(myN);
	myPrimeStream.write(myQString.c_str(), myQString.length());
	myPrimeStream.flush();
	myPrimeStream.close();
}

void RSAEncryption::writePublicKey()
{
	ofstream myPrimeStream("e_n.txt", iostream::binary);
	if (myPrimeStream.fail())
	{
		cout << "Failed to write e_n in file!";
	}
	std::string myPString = bigUnsignedToString(myE);
	myPString += "\n";
	myPrimeStream.write(myPString.c_str(), myPString.length());
	std::string myQString = bigUnsignedToString(myN);
	myPrimeStream.write(myQString.c_str(), myQString.length());
	myPrimeStream.flush();
	myPrimeStream.close();
}
