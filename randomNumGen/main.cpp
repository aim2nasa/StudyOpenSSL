#include <iostream>
#include <iomanip>
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

	cout << showbase		// show the 0x prefix
		 << internal		// fill between the prefix and the number
		 << setfill('0');	// fill with 0s

	for (int i = 0; i < length; i++) cout <<hex<<setw(4)<<(int)buffer[i] << " ";
	cout << endl;
	return 0;
}