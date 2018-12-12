#include <iostream>
#include <fstream>
#include "RSAEncryption.hh"
int main(int argc, char *argv[])
{
	//BIN TEST
	RSAEncryption *myEncryptionClass = new RSAEncryption();
	ofstream output;
	if (argc-1 == 0)
	{
		myEncryptionClass->part1OfProject();
	}
	else if (argc - 1 == 2)
	{
		myEncryptionClass->signFile(argv[argc - 1]);
	}
	else if (argc - 1 == 3)
	{
		myEncryptionClass->verifyFile(argv[argc - 2], argv[argc - 1]);
	}
//	myEncryptionClass->part1OfProject();

}
