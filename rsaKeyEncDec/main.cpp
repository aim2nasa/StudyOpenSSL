#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int main(int argc, char* argv[])
{
	// 변수 정의
	BIO *keyBIO = NULL;
	BIO *errBIO = NULL;
	RSA *rsa = NULL;

	char keyFile[100];
	char KeyFormat[10];
	char encType[10];
	char keyType[10];

	char inFile[100];
	char outFile[100];

	BIO *inBIO = NULL;
	BIO *outBIO = NULL;

	// 표준 화면 출력 BIO 생성
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// 암호화를 할건지 복호화를 할 건지 선택
	printf("암호화, 복호화 선택 (e,d) : ");
	scanf("%s", encType);
	// 키를 공개키를 사용 할 건지, 개인키를 사용 할 건지 선택
	printf("공개키, 개인키 선택 (pri,pub) : ");
	scanf("%s", keyType);

	// 키 파일명 입력
	printf("키 파일을 입력 하세요 : ");
	scanf("%s", keyFile);

	// 키 파일 형식 입력
	printf("키 파일의 형식을 입력 하세요 (PEM,DER) : ");
	scanf("%s", KeyFormat);

	// 입력 파일명 입력
	printf("입력 파일명을 입력 하세요 : ");
	scanf("%s", inFile);

	// 촐력 파일명 입력
	printf("출력 파일명을 입력 하세요 : ");
	scanf("%s", outFile);

	// 키 파일 BIO생성
	keyBIO = BIO_new(BIO_s_file());
	if (keyBIO == NULL)
	{
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 키 파일 읽음
	if (BIO_read_filename(keyBIO, keyFile) <= 0)
	{
		BIO_printf(errBIO, "키 파일 [%s] 을 여는데 에러가 발생 했습니다.", keyFile);
		ERR_print_errors(errBIO);
		exit(1);
	}

	// DER 형식이면, 키 파일 BIO에서 키 내용을 읽어서 rsa 구조체 형식으로 변환
	if (strcmp(KeyFormat, "DER") == 0)
	{
		// 개인키와 공개키에 따라서 다른 함수 사용
		if (strcmp(keyType, "pub") == 0)
			rsa = d2i_RSAPublicKey_bio(keyBIO, NULL);
		else
			rsa = d2i_RSAPrivateKey_bio(keyBIO, NULL);

	}
	// PEM 형식이면, 키 파일 BIO에서 키 내용을 읽어서 rsa 구조체 형식으로 변환
	else if (strcmp(KeyFormat, "PEM") == 0)
	{
		// 개인키와 공개키에 따라서 다른 함수 사용
		if (strcmp(keyType, "pub") == 0)
			rsa = PEM_read_bio_RSA_PUBKEY(keyBIO, NULL, NULL, NULL);
		else
			rsa = PEM_read_bio_RSAPrivateKey(keyBIO, NULL, NULL, NULL);
	}
	else
	{
		BIO_printf(errBIO, "알 수 없는 포맷 [%s] 입니다.", KeyFormat);
	}

	// 키를 로드 하는데 에러 발생
	if (rsa == NULL)
	{
		BIO_printf(errBIO, "키를 로드 할 수 없습니다.");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 입력 파일에서 BIO 생성
	inBIO = BIO_new_file(inFile, "rb");
	if (!inBIO)
	{
		BIO_printf(errBIO, "입력 파일 [%s] 을 여는데 에러가 발생 했습니다.", inFile);
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 출력 파일에서 BIO 생성
	outBIO = BIO_new_file(outFile, "wb");
	if (!outBIO)
	{
		BIO_printf(errBIO, "출력 파일 [%s] 을 생성 하는데 에러가 발생 했습니다.", outFile);
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 읽은 키의 길이를 얻음
	int keySize = RSA_size(rsa);

	// 입력문 내용이 들어갈 버퍼와, 출력문 내용이 들어갈 버퍼 생성
	// 입력 버퍼의 길이는 키 길이의 두배, 출력 버퍼는 키 길이와 동일
	unsigned char * inBuffer = (unsigned char *)malloc(keySize * 2);
	unsigned char * outBuffer = (unsigned char *)malloc(keySize);

	// 패딩  정의, 일반적인 패딩으로 사용
	unsigned char pad = RSA_PKCS1_PADDING;

	// 입력문 파일에서 내용 읽어 버퍼에 저장
	int inLength = BIO_read(inBIO, inBuffer, keySize * 2);

	int outLength = 0;
	// 공개키로 암호화 할때. 입력 버퍼의 내용을 암호화 해서 출력 버퍼에 넣음
	if ((strcmp(encType, "e") == 0) && (strcmp(keyType, "pub") == 0))
		outLength = RSA_public_encrypt(inLength, inBuffer, outBuffer, rsa, pad);
	// 개인키로 암호화 할때. 입력 버퍼의 내용을 암호화 해서 출력 버퍼에 넣음
	else if ((strcmp(encType, "e") == 0) && (strcmp(keyType, "pri") == 0))
		outLength = RSA_private_encrypt(inLength, inBuffer, outBuffer, rsa, pad);
	// 공개키로 복호화 할때. 입력 버퍼의 내용을 복호화 해서 출력 버퍼에 넣음
	else if ((strcmp(encType, "d") == 0) && (strcmp(keyType, "pub") == 0))
		outLength = RSA_public_decrypt(inLength, inBuffer, outBuffer, rsa, pad);
	// 개인키로 복호화 할때. 입력 버퍼의 내용을 복호화 해서 출력 버퍼에 넣음
	else if ((strcmp(encType, "d") == 0) && (strcmp(keyType, "pri") == 0))
		outLength = RSA_private_decrypt(inLength, inBuffer, outBuffer, rsa, pad);

	// 암호화 혹은 복호화시 에러 발생 체크
	if (outLength <= 0)
	{
		BIO_printf(errBIO, "RSA 암호화시 에러 발생");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 출력 파일에 출력 버퍼의 내용 저장
	BIO_write(outBIO, outBuffer, outLength);

	BIO_printf(errBIO, "완료 되었습니다.");

	// 객체 제거
	if (keyBIO != NULL)
		BIO_free(keyBIO);
	if (rsa != NULL)
		RSA_free(rsa);
	free(inBuffer);
	free(outBuffer);

	return 0;
}
