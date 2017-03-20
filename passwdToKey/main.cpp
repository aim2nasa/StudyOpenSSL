#include <iostream>
#include <iomanip>
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
		return -1;
	}

	// ��ȣȭ ����ü�� �ν��Ͻ��� ����. ���⼭�� DES�� ECB����� ��ȣȭ ����ü ����
	cipher = EVP_des_ecb();

	// Ű��,IV�� ������. ���ڴ� ��ȣȭ ����ü,��������Ʈ ����ü,Salt��,�н�����
	// ī��Ʈ, ������ Ű�� IV�� ������ ����
	// ��������Ʈ ����ü�� EVP_md5()�Լ��� ���� ����. ī��Ʈ�� �ѹ�
	EVP_BytesToKey(cipher, EVP_md5(), salt,
		(unsigned char *)password,
		(int)strlen(password), 1, key, iv);

	cout << showbase		// show the 0x prefix
		<< internal			// fill between the prefix and the number
		<< setfill('0');	// fill with 0s

	// Salt���� ȭ�鿡 ǥ��
	cout << "Salt : " << endl;
	for (int i = 0; i < sizeof salt; i++) cout << hex << setw(4) << (int)salt[i] << " ";
	cout << endl;

	// Ű���� ȭ�鿡 ǥ��
	if (cipher->key_len > 0)
	{
		cout << "Key : " << endl;
		for (int i = 0; i < cipher->key_len; i++) cout << hex << setw(4) << (int)key[i] << " ";
		cout << endl;
	}

	// IV���� ȭ�鿡 ǥ��
	if (cipher->iv_len > 0)
	{
		cout << "IV : " << endl;
		for (int i = 0; i < cipher->iv_len; i++) cout << hex << setw(4) << (int)iv[i] << " ";
		cout << endl;
	}
	return 0;
}