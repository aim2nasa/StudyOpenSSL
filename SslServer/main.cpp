#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#define PORT 7921
#define SERVER_ADDRESS "127.0.0.1"

// ���� �������� ����Ű ���� ����
#define CERT_FILE "rootcert.pem"
#define PRIVKEY_FILE "rootkey.pem"

// SSL �ڵ彦��ũ �޽�����ȯ ������ �˷��ִ� �ݺ��Լ�
void  ssl_info_callback(const SSL *s, int where, int ret);

// ȭ�鿡 ǥ�� �ϱ� ���� ���� BIO����
BIO * errBIO;

int main(int argc, char* argv[])
{
	unsigned short port = PORT;
	char * serverAddress = SERVER_ADDRESS;
	// ������ ���� Ÿ���� TCP ���� �������̴�.
	int socket_type = SOCK_STREAM;
	struct sockaddr_in server_add, client_add;
	SOCKET server_socket, client_socket;

	WSADATA wsaData;
	socket_type = SOCK_STREAM;

	// SSL ����ü ����
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL*     ssl;

	int retval;
	// ���� DLL�� �ʱ�ȭ �ϰ�, ���� ���� 2.2�� ��� �Ѵٴ� ���� �˸���.
	if ((retval = WSAStartup(0x202, &wsaData)) != 0) {
		fprintf(stderr, "WSAStartup �Լ����� ���� �߻�.");
		WSACleanup();
		exit(1);
	}
	// ������ 2.2�� �ƴϸ� �����Ѵ�.
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		exit(1);
	}
	// ȭ�� ��� BIO����
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// ��� ���� ��Ʈ�� �ε�
	SSL_load_error_strings();
	// ��� �˰��� �ε�
	SSLeay_add_ssl_algorithms();

	// SSL ����3 �������� ���
	meth = SSLv3_method();
	// SSL ���ؽ�Ʈ ����
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		BIO_printf(errBIO, "SSL_CTX ���� ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// SSL �ڵ彦��ũ �޽�����ȯ ������ �˷��ִ� �ݺ��Լ��� ����
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
	// �ڽ��� �������� ���Ͽ��� �ε��Ѵ�.
	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors(errBIO);
		exit(1);
	}
	// �ڽ��� ����Ű�� ���Ͽ��� �ε��Ѵ�.
	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors(errBIO);
		exit(1);
	}
	// ���� �������� ����Ű�� �´��� Ȯ�� �Ѵ�.
	if (!SSL_CTX_check_private_key(ctx)) {
		BIO_printf(errBIO, "�������� ����Ű�� ���� �ʽ��ϴ�.\n");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// sockaddr_in ����ü�� �ּ�ü�踦 ���ͳ� �ּ�ü��� �Ѵ�.
	server_add.sin_family = AF_INET;
	// ������ �ּҸ� ���ͳ�32��Ʈ �ּҷ� ��ȯ�Ͽ� sockaddr_in�� �ִ´�.
	server_add.sin_addr.s_addr = inet_addr(serverAddress);
	// ��Ʈ��ũ �������� ��Ʈ��ȣ�� ��ȯ �Ͽ� sockaddr_in�� �ִ´�.
	server_add.sin_port = htons(port);
	// ������ ������ ���� �Ѵ�.
	server_socket = socket(AF_INET, socket_type, 0); // TCP socket
	if (server_socket == INVALID_SOCKET){
		fprintf(stderr, "���� ���� ����, ���� �ڵ�:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// bind �� ���� �Ͽ� ���� ���ϰ� ���� �ּҸ� ���� �Ѵ�.
	retval = bind(server_socket, (struct sockaddr*)&server_add, sizeof(server_add));
	if (retval == SOCKET_ERROR) {
		fprintf(stderr, "bind  ����, ���� �ڵ�: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// listen �Լ��� ���� �Ͽ� Ŭ���̾�Ʈ�� ���� �� �� �ִ� �ִ� ���ۼ��� 5�� ���Ѵ�.
	retval = listen(server_socket, 5);
	if (retval == SOCKET_ERROR) {
		fprintf(stderr, "listen ���� , ���� �ڵ�: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}

	printf("�ּ� %s , ��Ʈ %d ���� Ŭ���̾�Ʈ�� ���� ��ٸ�.\n", serverAddress, port);

	int client_addlen = sizeof(client_add);
	// accept�Լ��� ���� �Ͽ� Ŭ���̾�Ʈ�κ����� ������ ��ٸ���.
	client_socket = accept(server_socket, (struct sockaddr*)&client_add, &client_addlen);
	if (client_socket == INVALID_SOCKET) {
		fprintf(stderr, "accept ����, ���� �ڵ�: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// Ŭ���̾�Ʈ�� ������ ����, ����
	printf("Ŭ���̾�Ʈ ����, �ּ�: %s, ��Ʈ: %d\n", inet_ntoa(client_add.sin_addr), htons(client_add.sin_port));

	// SSL ����ü ����
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		BIO_printf(errBIO, "SSL ���� ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// ����� ���ϰ� SSL���� ����
	SSL_set_fd(ssl, (int)client_socket);
	// ���� �߿��� �Լ�, Ŭ���̾�Ʈ���� �ʱ� �������, �� �ڵ彦��ũ ������ ����
	retval = SSL_accept(ssl);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL accept ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// ���� Ŭ���̾�Ʈ�� ���ǵ� ��ȣȭ �Ķ���������� ����
	const char * currentChipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
	//printf("SSL ����, ��� �˰��� �Ķ����: [%s]\n",SSL_get_cipher(ssl));
	printf("SSL ����, ��� �˰��� �Ķ����: [%s]\n", currentChipher);


	char inbuffer[1000];
	// Ŭ���̾�Ʈ�� ���� SSL ����� ���� �޽��� ����
	retval = SSL_read(ssl, inbuffer, sizeof(inbuffer)-1);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL read ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// ���� �����͸� ȭ�鿡 ǥ��
	inbuffer[retval] = '\0';
	printf("Ŭ���̾�Ʈ�� ���� ������ ���� :[%s], ����:%d\n", inbuffer, retval);

	char message[100] = "�̰��� ������ ������ ���� �޽��� �Դϴ�.";

	// Ŭ���̾�Ʈ���� SSL ����� ���� �޽��� ����
	retval = SSL_write(ssl, message, (int)strlen(message));
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL write ����");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// ���� ���� �� ��ü ����
	printf("���� ����\n");
	closesocket(client_socket);
	SSL_free(ssl);
	SSL_CTX_free(ctx);


	Sleep(20000);
}

// SSL �ڵ彦��ũ �޽�����ȯ ������ �˷��ִ� �ݺ��Լ�
void  ssl_info_callback(const SSL *s, int where, int ret)
{
	char * writeString;
	int w;
	// ���� � �޽��� ��ȯ ���������� ��Ÿ��
	w = where & ~SSL_ST_MASK;

	// Ŭ���̾�Ʈ�� ���� ���� ��
	if (w & SSL_ST_CONNECT)
		writeString = "SSL_connect";
	// ������ ������ �޾��� ��
	else if (w & SSL_ST_ACCEPT)
		writeString = "SSL_accept";
	// �� �� ���� ���
	else
		writeString = "undefined";

	// �Ϲ����� �ڵ彦��ũ �������� �޽����� ���
	if (where & SSL_CB_LOOP)
	{
		// SSL_state_string_long(s) �Լ��� ���� ���� ����Ǵ� �޽����� �������� ǥ��
		BIO_printf(errBIO, "%s:%s\n", writeString, SSL_state_string_long(s));
	}
	else if (where & SSL_CB_ALERT)
	{ // alert ���������� ���
		writeString = (where & SSL_CB_READ) ? "read" : "write";
		BIO_printf(errBIO, "SSL3 alert %s:%s:%s\n", writeString, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
	}
	else if (where & SSL_CB_EXIT)
	{ // ���� ������ ���
		if (ret == 0)
			BIO_printf(errBIO, "%s:failed in %s\n", writeString, SSL_state_string_long(s));
		else if (ret < 0)
		{
			BIO_printf(errBIO, "%s:error in %s\n", writeString, SSL_state_string_long(s));
		}
	}
}