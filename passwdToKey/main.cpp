#include <iostream>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

using namespace std;

int main(int argc, char* argv[])
{
	// Salt �� ����, ���̴� 8
	unsigned char salt[8];
	// ��ȣȭ ����ü EVP_CIPHER�� ������ ���� ����
	const EVP_CIPHER *cipher = NULL;
	// �н����带 ������ ������, �н������ "aaaa"�� ����
	char * password = "aaaa";
	// Ű�� IV�� ����� ������ ����,���̴� OpenSSL���� �˾Ƽ� ����.
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

	int ret = 0;
	// PRNG�� ���� �������� ����� �� ���� Salt�� ����. ���̴� 8
	ret = RAND_pseudo_bytes(salt, 8);

	// PRNG���� ������ �߻��� ��� ���� �޽��� ����ϰ� ���α׷��� ����.
	if (ret< 0)
	{
		printf("���� ���� ���� �� �� �����ϴ�.");
		exit(1);
	}

	// ��ȣȭ ����ü�� �ν��Ͻ��� ����. ���⼭�� DES�� ECB����� ��ȣȭ ����ü ����
	cipher = EVP_des_ecb();

	// Ű��,IV�� ������. ���ڴ� ��ȣȭ ����ü,��������Ʈ ����ü,Salt��,�н�����
	// ī��Ʈ, ������ Ű�� IV�� ������ ����
	// ��������Ʈ ����ü�� EVP_md5()�Լ��� ���� ����. ī��Ʈ�� �ѹ�
	EVP_BytesToKey(cipher, EVP_md5(), salt,
		(unsigned char *)password,
		(int)strlen(password), 1, key, iv);

	// Salt���� ȭ�鿡 ǥ��
	printf("salt=");
	for (int i = 0; i<sizeof salt; i++)
	{
		printf("%02X", salt[i]);
	}
	printf("\n");
	// Ű���� ȭ�鿡 ǥ��
	if (cipher->key_len > 0)
	{
		printf("key=");
		for (int i = 0; i<cipher->key_len; i++)
		{
			printf("%02X", key[i]);
		}
		printf("\n");
	}
	// IV���� ȭ�鿡 ǥ��
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