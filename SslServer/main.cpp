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

// 서버 인증서와 개인키 파일 정의
#define CERT_FILE "rootcert.pem"
#define PRIVKEY_FILE "rootkey.pem"

// SSL 핸드쉐이크 메시지교환 과정을 알려주는 콜벡함수
void  ssl_info_callback(const SSL *s, int where, int ret);

// 화면에 표시 하기 위한 파일 BIO생성
BIO * errBIO;

int main(int argc, char* argv[])
{
	unsigned short port = PORT;
	char * serverAddress = SERVER_ADDRESS;
	// 서버의 소켓 타입은 TCP 같은 연결형이다.
	int socket_type = SOCK_STREAM;
	struct sockaddr_in server_add, client_add;
	SOCKET server_socket, client_socket;

	WSADATA wsaData;
	socket_type = SOCK_STREAM;

	// SSL 구조체 생성
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL*     ssl;

	int retval;
	// 윈속 DLL을 초기화 하고, 소켓 버전 2.2를 사용 한다는 것을 알린다.
	if ((retval = WSAStartup(0x202, &wsaData)) != 0) {
		fprintf(stderr, "WSAStartup 함수에서 에러 발생.");
		WSACleanup();
		exit(1);
	}
	// 버전이 2.2가 아니면 종료한다.
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		exit(1);
	}
	// 화면 출력 BIO생성
	if ((errBIO = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(errBIO, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	// 모든 에러 스트링 로드
	SSL_load_error_strings();
	// 모든 알고리즘 로드
	SSLeay_add_ssl_algorithms();

	// SSL 버전3 프로토콜 사용
	meth = SSLv3_method();
	// SSL 컨텍스트 생성
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		BIO_printf(errBIO, "SSL_CTX 생성 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// SSL 핸드쉐이크 메시지교환 과정을 알려주는 콜벡함수를 셋팅
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
	// 자신의 인증서를 파일에서 로딩한다.
	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 자신의 개인키를 파일에서 로딩한다.
	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 읽은 인증서와 개인키가 맞는지 확인 한다.
	if (!SSL_CTX_check_private_key(ctx)) {
		BIO_printf(errBIO, "인증서와 개인키가 맞지 않습니다.\n");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// sockaddr_in 구조체의 주소체계를 인터넷 주소체계로 한다.
	server_add.sin_family = AF_INET;
	// 서버의 주소를 인터넷32비트 주소로 변환하여 sockaddr_in에 넣는다.
	server_add.sin_addr.s_addr = inet_addr(serverAddress);
	// 네트워크 형식으로 포트번호를 변환 하여 sockaddr_in에 넣는다.
	server_add.sin_port = htons(port);
	// 서버의 소켓을 생성 한다.
	server_socket = socket(AF_INET, socket_type, 0); // TCP socket
	if (server_socket == INVALID_SOCKET){
		fprintf(stderr, "소켓 생성 에러, 에러 코드:%d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// bind 를 실행 하여 서버 소켓과 서버 주소를 연결 한다.
	retval = bind(server_socket, (struct sockaddr*)&server_add, sizeof(server_add));
	if (retval == SOCKET_ERROR) {
		fprintf(stderr, "bind  에러, 에러 코드: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// listen 함수를 실행 하여 클라이언트가 접속 할 수 있는 최대 버퍼수를 5로 정한다.
	retval = listen(server_socket, 5);
	if (retval == SOCKET_ERROR) {
		fprintf(stderr, "listen 에러 , 에러 코드: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}

	printf("주소 %s , 포트 %d 에서 클라이언트의 연결 기다림.\n", serverAddress, port);

	int client_addlen = sizeof(client_add);
	// accept함수를 실행 하여 클라이언트로부터의 접속을 기다린다.
	client_socket = accept(server_socket, (struct sockaddr*)&client_add, &client_addlen);
	if (client_socket == INVALID_SOCKET) {
		fprintf(stderr, "accept 에러, 에러 코드: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	// 클라이언트로 부터의 접속, 연결
	printf("클라이언트 연결, 주소: %s, 포트: %d\n", inet_ntoa(client_add.sin_addr), htons(client_add.sin_port));

	// SSL 구조체 생성
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		BIO_printf(errBIO, "SSL 생성 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 연결된 소켓과 SSL과의 연결
	SSL_set_fd(ssl, (int)client_socket);
	// 가장 중요한 함수, 클라이언트와의 초기 협상과정, 즉 핸드쉐이크 과정을 수행
	retval = SSL_accept(ssl);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL accept 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 현재 클라이언트와 정의된 암호화 파라메터정보를 얻음
	const char * currentChipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
	//printf("SSL 연결, 사용 알고리즘 파라메터: [%s]\n",SSL_get_cipher(ssl));
	printf("SSL 연결, 사용 알고리즘 파라메터: [%s]\n", currentChipher);


	char inbuffer[1000];
	// 클라이언트로 부터 SSL 통신을 통해 메시지 받음
	retval = SSL_read(ssl, inbuffer, sizeof(inbuffer)-1);
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL read 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}
	// 받은 데이터를 화면에 표시
	inbuffer[retval] = '\0';
	printf("클라이언트로 부터 데이터 전송 :[%s], 길이:%d\n", inbuffer, retval);

	char message[100] = "이것은 서버로 부터의 응답 메시지 입니다.";

	// 클라이언트에게 SSL 통신을 통해 메시지 보냄
	retval = SSL_write(ssl, message, (int)strlen(message));
	if (retval == -1)
	{
		BIO_printf(errBIO, "SSL write 에러");
		ERR_print_errors(errBIO);
		exit(1);
	}

	// 연결 해제 및 객체 제거
	printf("연결 해제\n");
	closesocket(client_socket);
	SSL_free(ssl);
	SSL_CTX_free(ctx);


	Sleep(20000);
}

// SSL 핸드쉐이크 메시지교환 과정을 알려주는 콜벡함수
void  ssl_info_callback(const SSL *s, int where, int ret)
{
	char * writeString;
	int w;
	// 현재 어떤 메시지 교환 과정인지를 나타냄
	w = where & ~SSL_ST_MASK;

	// 클라이언트가 연결 했을 때
	if (w & SSL_ST_CONNECT)
		writeString = "SSL_connect";
	// 서버가 연결을 받았을 때
	else if (w & SSL_ST_ACCEPT)
		writeString = "SSL_accept";
	// 알 수 없는 경우
	else
		writeString = "undefined";

	// 일반적인 핸드쉐이크 프로토콜 메시지일 경우
	if (where & SSL_CB_LOOP)
	{
		// SSL_state_string_long(s) 함수로 부터 현재 진행되는 메시지가 무엇인지 표시
		BIO_printf(errBIO, "%s:%s\n", writeString, SSL_state_string_long(s));
	}
	else if (where & SSL_CB_ALERT)
	{ // alert 프로토콜일 경우
		writeString = (where & SSL_CB_READ) ? "read" : "write";
		BIO_printf(errBIO, "SSL3 alert %s:%s:%s\n", writeString, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
	}
	else if (where & SSL_CB_EXIT)
	{ // 종료 과정일 경우
		if (ret == 0)
			BIO_printf(errBIO, "%s:failed in %s\n", writeString, SSL_state_string_long(s));
		else if (ret < 0)
		{
			BIO_printf(errBIO, "%s:error in %s\n", writeString, SSL_state_string_long(s));
		}
	}
}