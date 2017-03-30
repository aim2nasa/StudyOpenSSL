#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// 콜벡 함수 정의
static void genrsa_cb(int p, int n, void *arg);

// 메인 함수 시작
int main(int argc, char* argv[])
{
	int keyLenInput = 512; // 키 길이
	char outPublicKeyFile[50];  // 공개키를 저장
	char outPrivateKeyFile[50]; // 개인키를 저장

	bool isPem = true; // PEM 형식으로..

	BIO *publicOut = NULL;   // 공개키가 저장되는 파일 BIO
	BIO *privateOut = NULL;  // 개인키가 저장되는 파일 BIO
	BIO *bio_stdout = NULL;  // 화면에 출력할 stdout BIO

	RSA *rsa = NULL;   // RSA 구조체

	printf("키 길이 입력 : ");  // 키 길이 입력
	scanf("%d", &keyLenInput);

	printf("저장할 공개키 파일 이름 입력 : ");  // 공개키를 저장 할 파일명 입력
	scanf("%s", outPublicKeyFile);

	printf("저장할 개인키 파일 이름 입력 : ");  // 개인키를 저장 할 파일명 입력
	scanf("%s", outPrivateKeyFile);


	// 표준 화면 출력 BIO 생성
	if ((bio_stdout = BIO_new(BIO_s_file())) != NULL)
	{
		BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
	}
	// 공개키를 저장할 파일 BIO 생성
	if ((publicOut = BIO_new(BIO_s_file())) == NULL)
	{
		printf("BIO 생성 에러. %s", outPublicKeyFile);
		exit(1);
	}
	// 개인키를 저장할 파일 BIO 생성
	if ((privateOut = BIO_new(BIO_s_file())) == NULL)
	{
		printf("BIO 생성 에러. %s", outPublicKeyFile);
		exit(1);
	}
	// 파일 BIO와 해당 공개키 저장할 파일 연결
	if (BIO_write_filename(publicOut, outPublicKeyFile) <= 0)
	{
		printf("BIO 생성 에러. %s", outPublicKeyFile);
		exit(1);
	}
	// 파일 BIO와 해당 개인키 저장할 파일 연결
	if (BIO_write_filename(privateOut, outPrivateKeyFile) <= 0)
	{
		printf("BIO 생성 에러. %s", outPrivateKeyFile);
		exit(1);
	}

	RAND_screen();  // seed 생성, 공급

	// 키 생성
	rsa = RSA_generate_key(keyLenInput, RSA_F4, genrsa_cb, NULL);

	if (isPem)
	{
		// PEM 포맷으로 표준 화면 출력 BIO에 공개키 출력
		if (!PEM_write_bio_RSA_PUBKEY(bio_stdout, rsa))
		{
			printf("PEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}
		printf("\n\n");
		// PEM 포맷으로 표준 화면 출력 BIO에 개인키 출력
		if (!PEM_write_bio_RSAPrivateKey(bio_stdout, rsa, NULL, NULL, 0, NULL, NULL))
		{
			printf("PEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}
		// PEM 포맷으로 파일 BIO에 공개키 출력
		if (!PEM_write_bio_RSA_PUBKEY(publicOut, rsa))
		{
			printf("PEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}
		// PEM 포맷으로 파일 BIO에 개인키 출력
		if (!PEM_write_bio_RSAPrivateKey(privateOut, rsa, NULL, NULL, 0, NULL, NULL))
		{
			printf("PEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}
	}
	else  // 만약 DEM 포맷으로 키 쌍을 출력 한다면
	{
		printf("DER PUBLIC KEY\n");

		// DEM 포맷으로 표준 화면 출력 BIO에 공개키 출력
		if (!i2d_RSA_PUBKEY_bio(bio_stdout, rsa))
		{
			printf("DEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}

		printf("\n\n");
		printf("DER PRIVATE KEY\n");
		printf("\n");

		// DEM 포맷으로 표준 화면 출력 BIO에 개인키 출력
		if (!i2d_RSAPrivateKey_bio(bio_stdout, rsa))
		{
			printf("DEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}

		// DEM 포맷으로 파일 BIO에 공개키 출력
		if (!i2d_RSA_PUBKEY_bio(publicOut, rsa))
		{
			printf("DEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}

		// DEM 포맷으로 파일 BIO에 개인키 출력
		if (!i2d_RSAPrivateKey_bio(privateOut, rsa))
		{
			printf("DEM 파일 생성 에러 %s", outPrivateKeyFile);
			exit(1);
		}
	}

	// RSA 구조체 메모리에서 삭제
	if (rsa != NULL) RSA_free(rsa);
	// BIO를 메모리에서 삭제
	if (publicOut != NULL) BIO_free_all(publicOut);
	if (privateOut != NULL) BIO_free_all(privateOut);

	return 0;

}

// 콜벡 함수 
static void genrsa_cb(int p, int n, void *arg)
{
	char c = '*';
	// prime number e의 생성 과정을 표시
	if (p == 0) c = '.';
	if (p == 1) c = '+';
	if (p == 2) c = '*';
	if (p == 3) c = '\n';
	printf("%c", c);
}