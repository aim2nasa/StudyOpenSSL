#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char* argv[])
{
	// 메시지 다이제스트 구조체를 생성.
	EVP_MD_CTX mdctx;

	// 암호화 구조체를 저장할 변수 정의.
	const EVP_MD *md;

	// 다이제스트할 평문을 직접 변수에 넣음.
	char message1[] = "테스트 메시지 입니다.\n";
	char message2[] = "안녕하세요\n";

	// 생성된 압축 해시값을 저장할 변수 정의. 길이는 OpenSSL에서 정함.
	unsigned char hashValue[EVP_MAX_MD_SIZE];

	// 생성된 압축 해시값의 길이를 저장할 변수 정의.
	unsigned int hashLen, i;


	// 동적인 암호화 구조체 생성을 위해 모든 다이제스트 알고리즘 로딩
	OpenSSL_add_all_digests();

	// MD5 암호화 구조체 생성
	md = EVP_get_digestbyname("sha");

	// 리턴 값이 0이면 에러. 프로그램 종료
	if (!md) {
		printf("암호화 구조체를 생성 할 수 없습니다.");
		exit(1);
	}
	// 컨텍스트 초기화
	EVP_MD_CTX_init(&mdctx);

	// 메시지 다이제스트 첫 과정. 초기화
	EVP_DigestInit_ex(&mdctx, md, NULL);

	// 첫 메시지 압축
	EVP_DigestUpdate(&mdctx, message1, (unsigned int)strlen(message1));

	// 두 번째 메시지 압축
	EVP_DigestUpdate(&mdctx, message2, (unsigned int)strlen(message2));

	// 해시값 생성
	EVP_DigestFinal_ex(&mdctx, hashValue, &hashLen);

	// 컨텍스트 해제
	EVP_MD_CTX_cleanup(&mdctx);

	// 키 길이 출력
	printf("해시 길이: %i 바이트\n", hashLen);

	// 생성 해시값 화면 출력.
	printf("해시 값  : ");
	for (i = 0; i < hashLen; i++) printf("%02x", hashValue[i]);
	{
		printf("\n");
	}

	return 0;
}