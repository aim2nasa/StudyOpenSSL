#include <iostream>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

int main(int argc, char* argv[])
{
	int retVal = 0;

	// 랜덤 수의 길이는 64로 한다.
	int length = 64;

	// PRNG에 공급할 Seed 생성
	RAND_screen();

	// 생성 할 랜덤 수 길이 만큼의 버퍼 생성
	unsigned char * buffer = (unsigned char *)malloc(sizeof(unsigned char) *(length));

	// PRNG 실행
	retVal = RAND_bytes(buffer, length);
	if (retVal <= 0)
	{ // 에러가 발생한 경우
		printf("랜덤수 생성시 에러가 발생했습니다.");
		return 0;
	}

	// 랜덤수를 화면에 표시 한다. 
	printf("랜덤수는 = ");
	for (int i = 0; i<length; i++)
		printf("%c", buffer[i]);

	return 0;
}