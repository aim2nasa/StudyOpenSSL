#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define IN_FILE  "plain.txt"
#define OUT_FILE  "encrypt.bin"
#define CIPHER  "des-ecb"

unsigned char * readFile(char * file, int *readLen);
unsigned char * addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen);

int main(int argc, char* argv[])
{
	BIO *errBIO = NULL;
	BIO *outBIO = NULL;
	BIO *encBIO = NULL;

	const EVP_CIPHER *cipher = NULL;
	char password[100];
	// Salt 를 저장, 길이는 8
	unsigned char salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	// 키와 IV가 저장될 변수를 정의,길이는 OpenSSL에서 알아서 정함.
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

	// 에러 발생의 경우 해당 에러 스트링 출력을 위해 미리 에러 스트링들을 로딩.
	ERR_load_crypto_strings();
	//OpenSSL_add_all_algorithms();
	// 동적인 EVP_CIPHER 생성을 위해 비밀키 알고리즘을 내부에 로드
	OpenSSL_add_all_ciphers();
	// 동적인 EVP_CIPHER 생성
	cipher = EVP_get_cipherbyname(CIPHER);

	// 패스워드 입력
	printf("키 생성을 위한 패스워드를 입력 하세요 : ");
	scanf("%s", password);

	// 표준 화면 출력 BIO 생성
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// 파일 출력 BIO 생성
	outBIO = BIO_new_file(OUT_FILE, "wb");
	if (!outBIO)
	{ // 에러가 발생한 경우
		BIO_printf(errBIO, "파일 [%s] 을 생성 하는데 에러가 발생 했습니다.", OUT_FILE);
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 비밀키 암호화 BIO 생성
	encBIO = BIO_new(BIO_f_cipher());
	if (encBIO == NULL)
	{ // 에러가 발생한 경우
		BIO_printf(errBIO, "비밀키 암호화 BIO 생성 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 패스워드를 사용해서 키와 IV 생성
	EVP_BytesToKey(cipher, EVP_md5(), salt, (unsigned char *)password, (int)strlen(password), 1, key, iv);

	// 비밀키 암호화 BIO에 EVP_CIPHER와 키, IV 연결, 
	BIO_set_cipher(encBIO, cipher, key, iv, 1);  //1 이면 암호화 0이면 복호화

	// 파일에서 읽는다
	int len;
	unsigned char * readBuffer = readFile(IN_FILE, &len);

	// 파일 출력 BIO위에 암호화 BIO를 연결 한다.
	encBIO = BIO_push(encBIO, outBIO);

	// 체인 BIO에 암호문을 출력 한다.  
	BIO_write(encBIO, (char *)readBuffer, len);

	// 모든 내용을 출력후 BIO를 비운다.
	BIO_flush(encBIO);

	BIO_printf(errBIO, "파일 [%s] 에 암호문이 저장 되었습니다.", OUT_FILE);
	// 객체 제거 - 모든 체인의 BIO가 제거 된다.
	BIO_free(encBIO);

	return 0;
}


unsigned char * readFile(char * file, int *readLen)
{
	unsigned char * retBuffer = NULL;
	unsigned char * buffer = NULL;
	int length = 0;
	// 파일 BIO 정의
	BIO *fileBIO = NULL;
	// 인자로 넘어온 파일을 열고, 파일 BIO 생성
	fileBIO = BIO_new_file(file, "rb");
	if (!fileBIO)
	{ // 파일을 여는데 에러가 발생한 경우
		printf("입력 파일 [%s] 을 여는데 에러가 발생 했습니다.", file);
		exit(1);
	}
	// 임시로 1000바이트 만큼의 읽은 데이터를 저장할 버퍼 생성
	buffer = (unsigned char *)malloc(1001);
	*readLen = 0;

	while (true)
	{
		// 파일 BIO에서 1000 바이트 만큼 읽어서 buffer에 저장 한다.
		length = BIO_read(fileBIO, buffer, 1000);
		// 안전을 위해 버퍼의 끝은 NULL로 채운다.
		buffer[length] = 0;
		// 임시로 읽은 1000바이트의 데이터 리턴 버퍼에 더한다.
		retBuffer = addString(retBuffer, *readLen, buffer, length);
		// 지금 까지 읽은 데이터의 길이를 더한다.
		*readLen = *readLen + length;

		// 만약 지금 파일에서 읽은 데이터의 길이가 꼭 1000바이트 라면 앞으로 더 읽을
		// 데이터가 있을 것이다. 하지만 1000 바이트 보다 작다면 더 이상 읽을 데이터가
		// 없을 것이므로 종료 한다.
		if (length == 1000)
			// 파일 포인터를 1000바이트 뒤로 옮긴다.
			BIO_seek(fileBIO, 1000);     else
			break;
	}
	// 객체 삭제
	BIO_free(fileBIO);
	free(buffer);

	return retBuffer;

}

unsigned char *addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen)
{
	// 리턴 할 버퍼 정의
	unsigned char * retString;
	// 만약 덧붙일 대상 버퍼가 NULL, 이거나 길이가 0이면 덧붙일 대상버퍼가 없는 경우 
	// 이므로 새로 생성 하고, 덧붙일 버퍼의 내용을 복사 한다.
	int i;

	if ((destString == NULL) || (destLen == 0))
	{
		// 덧붙일 버퍼의 길이 만큼의 버퍼 생성
		retString = (unsigned char *)malloc(sizeof(unsigned char)* (addLen + 1));
		// 덧붙일 버퍼의 내용을 새로운 버퍼에 복사
		for (i = 0; i<addLen; i++)
		{
			retString[i] = addString[i];
		}
		// 안전을 위해 버퍼의 마지막에 NULL 바이트를 붙인다.
		retString[i] = NULL;
		// 덧붙일 대상 버퍼가 있는 경우 이므로 덧붙일 대상 버퍼의 길이와 덧붙일 버퍼의 길이를 
		// 더한 만큼의 버퍼를 새로 생성하고, 두 버퍼의 내용을 새로운 버퍼에 복사 한다.
	}
	else{
		// 대상 버퍼의 길이와 덧붙일 버퍼의 길이를 더한 만큼의 버퍼 생성
		retString = (unsigned char *)malloc(sizeof(unsigned char)* (destLen + addLen + 1));
		// 덧붙일 대상 버퍼 내용을 새로운 버퍼에 복사
		for (i = 0; i<destLen; i++)
		{
			retString[i] = destString[i];
		}
		// 덧붙일 버퍼의 내용을 새로운 버퍼에 복사
		for (i = 0; i< addLen; i++)
		{
			retString[i + destLen] = addString[i];
		}
		// 안전을 위해 버퍼의 마지막에 NULL 바이트를 붙인다.
		retString[i + destLen] = NULL;
	}
	// 메모리에서 삭제
	free(destString);

	return retString;
}
