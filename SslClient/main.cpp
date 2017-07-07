#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#define PORT 7921
#define SERVER_ADDRESS "127.0.0.1"

int main(int argc, char* argv[])
{
	char * server_name = SERVER_ADDRESS;
	unsigned short port = PORT;

	unsigned int addr;
	struct sockaddr_in server_add;
	struct hostent *host;

	WSADATA wsaData;
	SOCKET  conn_socket;

	int socket_type = SOCK_STREAM;
	int retval;

	// SSL ����ü ����
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;

	BIO * errBIO;

	if ((retval = WSAStartup(0x202, &wsaData)) != 0) {
		fprintf(stderr, "WSAStartup �Լ����� ���� �߻�.");
		WSACleanup();
		exit(1);
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		exit(1);
	}


	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	meth = SSLv3_method();
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		BIO_printf(errBIO, "SSL_CTX ���� ����");
		ERR_print_errors(errBIO);
		exit(1);
	}


	// ���� �̸��� ���ĺ���DNS�� �Ǿ� ���� ���
	if (isalpha(server_name[0])) {
		host = gethostbyname(server_name);
	}
	// ���� �̸��� IP�� �Ǿ� ���� ���
	else  {
		addr = inet_addr(server_name);
		host = gethostbyaddr((char *)&addr, 4, AF_INET);
	}
	if (host == NULL) {
		fprintf(stderr, "�� �� ���� �ּ�[%s] �Դϴ�, ���� �ڵ�: %d\n", server_name, WSAGetLastError());
		WSACleanup();
		exit(1);
	}


	memset(&server_add, 0, sizeof(server_add));
	memcpy(&(server_add.sin_addr), host->h_addr, host->h_length);
	server_add.sin_family = host->h_addrtype;
	server_add.sin_port = htons(port);

	conn_socket = socket(AF_INET, socket_type, 0);
	if (conn_socket <0) {
		fprintf(stderr, "���� ���� ����, ���� �ڵ�:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}

	printf("[%s] ������ ������..\n", server_name);
	if (connect(conn_socket, (struct sockaddr*)&server_add, sizeof(server_add)) == SOCKET_ERROR) {
		fprintf(stderr, "connect ����, ���� �ڵ�:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// ����Ű�� ����� ���� ���� �� �� ���� Seed����
	printf("���� �� ������....");
	RAND_screen();
	printf("���� �� ���� �Ϸ�.\n");

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		BIO_printf(errBIO, "SSL ���� ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	SSL_set_fd(ssl, (int)conn_socket);
	retval = SSL_connect(ssl);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL accept ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	const char * currentChipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
	printf("SSL ����, ��� �˰��� �Ķ����: [%s]\n", currentChipher);


#if 0
	server_cert = SSL_get_peer_certificate(ssl);
	if (server_cert == NULL) {
		BIO_printf(errBIO, "���� �������� ���� �� ����.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("Server certificate:\n");

	char * retString = NULL;

	// ��ü�� DN�� ���ڿ��� ����
	retString = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	if (retString == NULL) {
		BIO_printf(errBIO, "���� ���������� ��ü�� DN�� ���� �� ����.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("\t subject: %s\n", retString);
	OPENSSL_free(retString);

	// �߱����� DN�� ���ڿ��� ����
	retString = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	if (retString == NULL) {
		BIO_printf(errBIO, "���� ���������� �߱����� DN�� ���� �� ����.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("\t issuer: %s\n", retString);
	OPENSSL_free(retString);

	X509_free(server_cert);
#endif // 0


	char buffer[1000];

	char message[100] = "�̰��� Ŭ���̾�Ʈ�� ������ �޽��� �Դϴ�.";
	retval = SSL_write(ssl, message, (int)strlen(message));
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL write ����");
		ERR_print_errors(errBIO);
		exit(1);
	}

	retval = SSL_read(ssl, buffer, sizeof(buffer)-1);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL read ����");
		ERR_print_errors(errBIO);
		exit(1);
	}
	buffer[retval] = '\0';
	printf("������ ���� ������ ���� :[%s], ����:%d\n", buffer, retval);
	SSL_shutdown(ssl);

	closesocket(conn_socket);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	WSACleanup();

}