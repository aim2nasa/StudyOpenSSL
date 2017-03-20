#include <iostream>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

using namespace std;

int main(int argc, char* argv[])
{
	// Salt 를 저장, 길이는 8
	unsigned char salt[8];
	// 암호화 구조체 EVP_CIPHER의 포인터 변수 생성
	const EVP_CIPHER *cipher = NULL;
	// 패스워드를 저장할 포인터, 패스워드는 "aaaa"로 넣음
	char * password = "aaaa";
	// 키와 IV가 저장될 변수를 정의,길이는 OpenSSL에서 알아서 정함.
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

	int ret = 0;
	// PRNG를 통해 랜덤수를 만들고 그 값을 Salt에 저장. 길이는 8
	ret = RAND_pseudo_bytes(salt, 8);

	// PRNG에서 에러가 발생할 경우 에러 메시지 출력하고 프로그램을 종료.
	if (ret< 0)
	{
		printf("랜덤 수를 생성 할 수 없습니다.");
		exit(1);
	}

	// 암호화 구조체의 인스턴스를 생성. 여기서는 DES의 ECB모드의 암호화 구조체 생성
	cipher = EVP_des_ecb();

	// 키와,IV를 생성함. 인자는 암호화 구조체,다이제스트 구조체,Salt값,패스워드
	// 카운트, 생성될 키와 IV를 저장할 변수
	// 다이제스트 구조체는 EVP_md5()함수를 통해 생성. 카운트는 한번
	EVP_BytesToKey(cipher, EVP_md5(), salt,
		(unsigned char *)password,
		(int)strlen(password), 1, key, iv);

	// Salt값을 화면에 표시
	printf("salt=");
	for (int i = 0; i<sizeof salt; i++)
	{
		printf("%02X", salt[i]);
	}
	printf("\n");
	// 키값을 화면에 표시
	if (cipher->key_len > 0)
	{
		printf("key=");
		for (int i = 0; i<cipher->key_len; i++)
		{
			printf("%02X", key[i]);
		}
		printf("\n");
	}
	// IV값을 화면에 표시
	if (cipher->iv_len > 0)
	{
		printf("iv =");
		for (int i = 0; i<cipher->iv_len; i++)
		{
			printf("%02X", iv[i]);
		}
		printf("\n");
	}
	return 0;
}