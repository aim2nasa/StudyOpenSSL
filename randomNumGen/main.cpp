#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

int main(int argc, char* argv[])
{
	//set length of random number
	int length = 64;

	//create seed for PRNG
	RAND_screen();

	//create buffer to store random number
	unsigned char * buffer = (unsigned char *)malloc(sizeof(unsigned char) *(length));

	//perform PRNG
	if (RAND_bytes(buffer, length) <= 0)
	{
		cout << "Error in generating random number" << endl;
		return -1;
	}

	cout << "Random number : " << endl;
	for (int i = 0; i < length; i++) cout << hex << (int)buffer[i] << " ";
	cout << endl;
	return 0;
}