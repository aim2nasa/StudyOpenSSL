#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

int main(int argc, char* argv[])
{
	int retVal = 0;

	// ���� ���� ���̴� 64�� �Ѵ�.
	int length = 64;

	// PRNG�� ������ Seed ����
	RAND_screen();

	// ���� �� ���� �� ���� ��ŭ�� ���� ����
	unsigned char * buffer = (unsigned char *)malloc(sizeof(unsigned char) *(length));

	// PRNG ����
	retVal = RAND_bytes(buffer, length);
	if (retVal <= 0)
	{ // ������ �߻��� ���
		printf("������ ������ ������ �߻��߽��ϴ�.");
		return 0;
	}

	// �������� ȭ�鿡 ǥ�� �Ѵ�. 
	printf("�������� = ");
	for (int i = 0; i<length; i++)
		printf("%c", buffer[i]);

	return 0;
}