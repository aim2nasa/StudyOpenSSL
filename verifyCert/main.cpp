#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define CA_CERT_FILE	"rootcert.pem"
//#define CRL_FILE		"crl.pem"	//01.pem에 대해서 revoke안되어 있음
#define CRL_FILE		"01crl.pem"	//01.pem에 대해서 revoke되어 있음
#define CERT_FILE		"01.pem"

int verifyCallbackfunc(int ok, X509_STORE_CTX *store)
{
	if (!ok)
	{
		X509 * cert = X509_STORE_CTX_get_current_cert(store);
		printf("error:%s\n", X509_verify_cert_error_string(store->error));
	}
	return ok;
}

int main(int argc, char* argv[])
{
	BIO * bio_err;
	int retVal;

	X509 * cert;
	X509_STORE * store;
	X509_LOOKUP * lookup;
	X509_STORE_CTX *storeCtx;

	BIO *certBIO = NULL;

	OpenSSL_add_all_algorithms();

	// 화면 출력용 BIO 생성
	if ((bio_err = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
	// 인증할 인증서 읽기 위한 BIO 생성
	certBIO = BIO_new(BIO_s_file());
	if (BIO_read_filename(certBIO, CERT_FILE) <= 0)
	{
		BIO_printf(bio_err, "인증서 파일 [%s] 을 여는데 에러가 발생 했습니다.", CERT_FILE);
		ERR_print_errors(bio_err);
		exit(1);
	}

	// 인증할 인증서를 파일로 부터 읽어 X509 구조체로 변환
	cert = PEM_read_bio_X509(certBIO, NULL, NULL, NULL);
	if (cert == NULL)
	{
		BIO_printf(bio_err, "CA 인증서를 로드 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}

	// 인증서를 저장할 STORE 구조체 생성
	store = X509_STORE_new();
	if (store == NULL)
	{
		BIO_printf(bio_err, "X509_STORE 를 생성 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// 콜벡 함수 설정
	X509_STORE_set_verify_cb_func(store, verifyCallbackfunc);
	// 파일로 부터 CA 인증서 읽음
	if (!X509_STORE_load_locations(store, CA_CERT_FILE, NULL))
	{
		BIO_printf(bio_err, "CA 인증서를 로드 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// STORE 에 CA 인증서 추가
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (lookup == NULL)
	{
		BIO_printf(bio_err, "X509_LOOKUP 를 생성 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// CRL 읽음
	if (!X509_load_crl_file(lookup, CRL_FILE, X509_FILETYPE_PEM))
	{
		BIO_printf(bio_err, "CRL을 로드 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// CA 인증서, CRL 인증 모두 지원
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	// STORE 컨텍스트 생성
	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL)
	{
		BIO_printf(bio_err, "X509_STORE_CTX 를 생성 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	if (!X509_STORE_CTX_init(storeCtx, store, cert, NULL))
	{
		BIO_printf(bio_err, "X509_STORE_CTX를 초기화 할 수 없습니다.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// 인증서 인증
	retVal = X509_verify_cert(storeCtx);
	if (retVal == 1)
	{
		BIO_printf(bio_err, "인증 되었습니다..");

	}
	else
	{
		BIO_printf(bio_err, "인증을 할 수 없습니다.");
		ERR_print_errors(bio_err);

	}
	return 0;
}