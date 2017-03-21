#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define IN_FILE  "plain.txt" //�� ����
#define OUT_FILE  "encrypt.bin" // ��ȣ���� ����� ����

unsigned char * readFile(char * file, int *readLen);
unsigned char * readFileBio(BIO * fileBIO, int *readLen);
unsigned char * addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen);

int main(int argc, char* argv[])
{
	// Ű�� IV���� ���Ǹ� ���� ���� �����     
	unsigned char key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	unsigned char iv[] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	BIO *errBIO = NULL;
	BIO *outBIO = NULL;

	// ���� �߻��� ��� �ش� ���� ��Ʈ�� ����� ���� �̸� ���� ��Ʈ������ �ε�.
	ERR_load_crypto_strings();

	// ǥ�� ȭ�� ��� BIO ����
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// ���� ��� BIO ����
	outBIO = BIO_new_file(OUT_FILE, "wb");
	if (!outBIO)
	{ // ������ �߻��� ���
		BIO_printf(errBIO, "���� [%s] �� ���� �ϴµ� ������ �߻� �߽��ϴ�.", OUT_FILE);
		ERR_print_errors(errBIO);
		return -1;
	}

	// ���Ͽ��� �д´�
	int len;
	unsigned char * readBuffer = readFile(IN_FILE, &len);

	// ��ȣȭ ���ؽ�Ʈ EVP_CIPHER_CTX ����,�ʱ�ȭ
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	// �ʱ�ȭ
	EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv);

	// �ʱ�ȭ�� �����Ŀ� �ؾ� �Ѵ�. ��ȣ�� ������ ���� ����
	unsigned char * outbuf = (unsigned char *)malloc(sizeof(unsigned char)* (len + EVP_CIPHER_CTX_block_size(&ctx)));
	int outlen, tmplen;
	//������Ʈ, ������ ����� ���� �ϰ� ��� ��ȣȭ
	if (!EVP_EncryptUpdate(&ctx, outbuf, &outlen, readBuffer, (int)strlen((char *)readBuffer)))
	{
		return 0;
	}

	// ����. ������ ����� ��ȣȭ
	if (!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
	{
		return 0;
	}

	// ��ȣ�� ���̴� ������Ʈ, ���� �������� ���� ����� ��
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

	BIO_printf(errBIO, "��ȣ�� ������ �Ϸ� �Ǿ����ϴ�.\n[%s] ���Ͽ� ��ȣ���� ���� �Ǿ����ϴ�.", OUT_FILE);
	//printf("%s",outbuf);

	// ���Ͽ� ���� ������ ��� �Ѵ�.
	BIO_write(outBIO, outbuf, outlen);

	// ��ü ����
	BIO_free(outBIO);

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

unsigned char * readFileBio(BIO * fileBIO, int *readLen)
{
	unsigned char * retBuffer = NULL;
	// �ӽ÷� 1000����Ʈ ��ŭ�� ���� �����͸� ������ ���� ����
	unsigned char * buffer = (unsigned char *)malloc(1001);
	int length = 0;

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
			BIO_seek(fileBIO, 1000);
		else
			break;
	}
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