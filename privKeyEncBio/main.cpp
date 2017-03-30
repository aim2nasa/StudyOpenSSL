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
	// Salt �� ����, ���̴� 8
	unsigned char salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	// Ű�� IV�� ����� ������ ����,���̴� OpenSSL���� �˾Ƽ� ����.
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

	// ���� �߻��� ��� �ش� ���� ��Ʈ�� ����� ���� �̸� ���� ��Ʈ������ �ε�.
	ERR_load_crypto_strings();
	//OpenSSL_add_all_algorithms();
	// ������ EVP_CIPHER ������ ���� ���Ű �˰����� ���ο� �ε�
	OpenSSL_add_all_ciphers();
	// ������ EVP_CIPHER ����
	cipher = EVP_get_cipherbyname(CIPHER);

	// �н����� �Է�
	printf("Ű ������ ���� �н����带 �Է� �ϼ��� : ");
	scanf("%s", password);

	// ǥ�� ȭ�� ��� BIO ����
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// ���� ��� BIO ����
	outBIO = BIO_new_file(OUT_FILE, "wb");
	if (!outBIO)
	{ // ������ �߻��� ���
		BIO_printf(errBIO, "���� [%s] �� ���� �ϴµ� ������ �߻� �߽��ϴ�.", OUT_FILE);
		ERR_print_errors(errBIO);
		exit(1);
	}
	// ���Ű ��ȣȭ BIO ����
	encBIO = BIO_new(BIO_f_cipher());
	if (encBIO == NULL)
	{ // ������ �߻��� ���
		BIO_printf(errBIO, "���Ű ��ȣȭ BIO ���� ����");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// �н����带 ����ؼ� Ű�� IV ����
	EVP_BytesToKey(cipher, EVP_md5(), salt, (unsigned char *)password, (int)strlen(password), 1, key, iv);

	// ���Ű ��ȣȭ BIO�� EVP_CIPHER�� Ű, IV ����, 
	BIO_set_cipher(encBIO, cipher, key, iv, 1);  //1 �̸� ��ȣȭ 0�̸� ��ȣȭ

	// ���Ͽ��� �д´�
	int len;
	unsigned char * readBuffer = readFile(IN_FILE, &len);

	// ���� ��� BIO���� ��ȣȭ BIO�� ���� �Ѵ�.
	encBIO = BIO_push(encBIO, outBIO);

	// ü�� BIO�� ��ȣ���� ��� �Ѵ�.  
	BIO_write(encBIO, (char *)readBuffer, len);

	// ��� ������ ����� BIO�� ����.
	BIO_flush(encBIO);

	BIO_printf(errBIO, "���� [%s] �� ��ȣ���� ���� �Ǿ����ϴ�.", OUT_FILE);
	// ��ü ���� - ��� ü���� BIO�� ���� �ȴ�.
	BIO_free(encBIO);

	return 0;
}


unsigned char * readFile(char * file, int *readLen)
{
	unsigned char * retBuffer = NULL;
	unsigned char * buffer = NULL;
	int length = 0;
	// ���� BIO ����
	BIO *fileBIO = NULL;
	// ���ڷ� �Ѿ�� ������ ����, ���� BIO ����
	fileBIO = BIO_new_file(file, "rb");
	if (!fileBIO)
	{ // ������ ���µ� ������ �߻��� ���
		printf("�Է� ���� [%s] �� ���µ� ������ �߻� �߽��ϴ�.", file);
		exit(1);
	}
	// �ӽ÷� 1000����Ʈ ��ŭ�� ���� �����͸� ������ ���� ����
	buffer = (unsigned char *)malloc(1001);
	*readLen = 0;

	while (true)
	{
		// ���� BIO���� 1000 ����Ʈ ��ŭ �о buffer�� ���� �Ѵ�.
		length = BIO_read(fileBIO, buffer, 1000);
		// ������ ���� ������ ���� NULL�� ä���.
		buffer[length] = 0;
		// �ӽ÷� ���� 1000����Ʈ�� ������ ���� ���ۿ� ���Ѵ�.
		retBuffer = addString(retBuffer, *readLen, buffer, length);
		// ���� ���� ���� �������� ���̸� ���Ѵ�.
		*readLen = *readLen + length;

		// ���� ���� ���Ͽ��� ���� �������� ���̰� �� 1000����Ʈ ��� ������ �� ����
		// �����Ͱ� ���� ���̴�. ������ 1000 ����Ʈ ���� �۴ٸ� �� �̻� ���� �����Ͱ�
		// ���� ���̹Ƿ� ���� �Ѵ�.
		if (length == 1000)
			// ���� �����͸� 1000����Ʈ �ڷ� �ű��.
			BIO_seek(fileBIO, 1000);     else
			break;
	}
	// ��ü ����
	BIO_free(fileBIO);
	free(buffer);

	return retBuffer;

}

unsigned char *addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen)
{
	// ���� �� ���� ����
	unsigned char * retString;
	// ���� ������ ��� ���۰� NULL, �̰ų� ���̰� 0�̸� ������ �����۰� ���� ��� 
	// �̹Ƿ� ���� ���� �ϰ�, ������ ������ ������ ���� �Ѵ�.
	int i;

	if ((destString == NULL) || (destLen == 0))
	{
		// ������ ������ ���� ��ŭ�� ���� ����
		retString = (unsigned char *)malloc(sizeof(unsigned char)* (addLen + 1));
		// ������ ������ ������ ���ο� ���ۿ� ����
		for (i = 0; i<addLen; i++)
		{
			retString[i] = addString[i];
		}
		// ������ ���� ������ �������� NULL ����Ʈ�� ���δ�.
		retString[i] = NULL;
		// ������ ��� ���۰� �ִ� ��� �̹Ƿ� ������ ��� ������ ���̿� ������ ������ ���̸� 
		// ���� ��ŭ�� ���۸� ���� �����ϰ�, �� ������ ������ ���ο� ���ۿ� ���� �Ѵ�.
	}
	else{
		// ��� ������ ���̿� ������ ������ ���̸� ���� ��ŭ�� ���� ����
		retString = (unsigned char *)malloc(sizeof(unsigned char)* (destLen + addLen + 1));
		// ������ ��� ���� ������ ���ο� ���ۿ� ����
		for (i = 0; i<destLen; i++)
		{
			retString[i] = destString[i];
		}
		// ������ ������ ������ ���ο� ���ۿ� ����
		for (i = 0; i< addLen; i++)
		{
			retString[i + destLen] = addString[i];
		}
		// ������ ���� ������ �������� NULL ����Ʈ�� ���δ�.
		retString[i + destLen] = NULL;
	}
	// �޸𸮿��� ����
	free(destString);

	return retString;
}
