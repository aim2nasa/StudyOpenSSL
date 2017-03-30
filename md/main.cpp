#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char* argv[])
{
	// �޽��� ��������Ʈ ����ü�� ����.
	EVP_MD_CTX mdctx;

	// ��ȣȭ ����ü�� ������ ���� ����.
	const EVP_MD *md;

	// ��������Ʈ�� ���� ���� ������ ����.
	char message1[] = "�׽�Ʈ �޽��� �Դϴ�.\n";
	char message2[] = "�ȳ��ϼ���\n";

	// ������ ���� �ؽð��� ������ ���� ����. ���̴� OpenSSL���� ����.
	unsigned char hashValue[EVP_MAX_MD_SIZE];

	// ������ ���� �ؽð��� ���̸� ������ ���� ����.
	unsigned int hashLen, i;


	// ������ ��ȣȭ ����ü ������ ���� ��� ��������Ʈ �˰��� �ε�
	OpenSSL_add_all_digests();

	// MD5 ��ȣȭ ����ü ����
	md = EVP_get_digestbyname("sha");

	// ���� ���� 0�̸� ����. ���α׷� ����
	if (!md) {
		printf("��ȣȭ ����ü�� ���� �� �� �����ϴ�.");
		exit(1);
	}
	// ���ؽ�Ʈ �ʱ�ȭ
	EVP_MD_CTX_init(&mdctx);

	// �޽��� ��������Ʈ ù ����. �ʱ�ȭ
	EVP_DigestInit_ex(&mdctx, md, NULL);

	// ù �޽��� ����
	EVP_DigestUpdate(&mdctx, message1, (unsigned int)strlen(message1));

	// �� ��° �޽��� ����
	EVP_DigestUpdate(&mdctx, message2, (unsigned int)strlen(message2));

	// �ؽð� ����
	EVP_DigestFinal_ex(&mdctx, hashValue, &hashLen);

	// ���ؽ�Ʈ ����
	EVP_MD_CTX_cleanup(&mdctx);

	// Ű ���� ���
	printf("�ؽ� ����: %i ����Ʈ\n", hashLen);

	// ���� �ؽð� ȭ�� ���.
	printf("�ؽ� ��  : ");
	for (i = 0; i < hashLen; i++) printf("%02x", hashValue[i]);
	{
		printf("\n");
	}

	return 0;
}