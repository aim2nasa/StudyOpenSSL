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

	// SSL 구조체 생성
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;

	BIO * errBIO;

	if ((retval = WSAStartup(0x202, &wsaData)) != 0) {
		fprintf(stderr, "WSAStartup 함수에서 에러 발생.");
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
		BIO_printf(errBIO, "SSL_CTX 생성 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}


	// 서버 이름이 알파벳인DNS로 되어 있을 경우
	if (isalpha(server_name[0])) {
		host = gethostbyname(server_name);
	}
	// 서버 이름이 IP로 되어 있을 경우
	else  {
		addr = inet_addr(server_name);
		host = gethostbyaddr((char *)&addr, 4, AF_INET);
	}
	if (host == NULL) {
		fprintf(stderr, "알 수 없는 주소[%s] 입니다, 에러 코드: %d\n", server_name, WSAGetLastError());
		WSACleanup();
		exit(1);
	}


	memset(&server_add, 0, sizeof(server_add));
	memcpy(&(server_add.sin_addr), host->h_addr, host->h_length);
	server_add.sin_family = host->h_addrtype;
	server_add.sin_port = htons(port);

	conn_socket = socket(AF_INET, socket_type, 0);
	if (conn_socket <0) {
		fprintf(stderr, "소켓 생성 에러, 에러 코드:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}

	printf("[%s] 서버에 연결중..\n", server_name);
	if (connect(conn_socket, (struct sockaddr*)&server_add, sizeof(server_add)) == SOCKET_ERROR) {
		fprintf(stderr, "connect 에러, 에러 코드:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// 세션키를 만들기 위한 랜덤 수 를 위한 Seed공급
	printf("랜덤 수 생성중....");
	RAND_screen();
	printf("랜덤 수 생성 완료.\n");

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		BIO_printf(errBIO, "SSL 생성 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	SSL_set_fd(ssl, (int)conn_socket);
	retval = SSL_connect(ssl);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL accept 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	const char * currentChipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
	printf("SSL 연결, 사용 알고리즘 파라메터: [%s]\n", currentChipher);


#if 0
	server_cert = SSL_get_peer_certificate(ssl);
	if (server_cert == NULL) {
		BIO_printf(errBIO, "서버 인증서를 받을 수 없음.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("Server certificate:\n");

	char * retString = NULL;

	// 주체의 DN을 문자열로 얻음
	retString = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	if (retString == NULL) {
		BIO_printf(errBIO, "서버 인증서에서 주체의 DN을 읽을 수 없음.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("\t subject: %s\n", retString);
	OPENSSL_free(retString);

	// 발급자의 DN을 문자열로 얻음
	retString = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	if (retString == NULL) {
		BIO_printf(errBIO, "서버 인증서에서 발급자의 DN을 읽을 수 없음.");
		ERR_print_errors(errBIO);
		exit(1);
	}
	printf("\t issuer: %s\n", retString);
	OPENSSL_free(retString);

	X509_free(server_cert);
#endif // 0


	char buffer[1000];

	char message[100] = "이것은 클라이언트가 보내는 메시지 입니다.";
	retval = SSL_write(ssl, message, (int)strlen(message));
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL write 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}

	retval = SSL_read(ssl, buffer, sizeof(buffer)-1);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL read 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	buffer[retval] = '\0';
	printf("서버로 부터 데이터 전송 :[%s], 길이:%d\n", buffer, retval);
	SSL_shutdown(ssl);

	closesocket(conn_socket);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	WSACleanup();

}