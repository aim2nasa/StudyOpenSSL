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
//#define CRL_FILE		"crl.pem"	//01.pem�� ���ؼ� revoke�ȵǾ� ����
#define CRL_FILE		"01crl.pem"	//01.pem�� ���ؼ� revoke�Ǿ� ����
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

	// ȭ�� ��¿� BIO ����
	if ((bio_err = BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
	// ������ ������ �б� ���� BIO ����
	certBIO = BIO_new(BIO_s_file());
	if (BIO_read_filename(certBIO, CERT_FILE) <= 0)
	{
		BIO_printf(bio_err, "������ ���� [%s] �� ���µ� ������ �߻� �߽��ϴ�.", CERT_FILE);
		ERR_print_errors(bio_err);
		exit(1);
	}

	// ������ �������� ���Ϸ� ���� �о� X509 ����ü�� ��ȯ
	cert = PEM_read_bio_X509(certBIO, NULL, NULL, NULL);
	if (cert == NULL)
	{
		BIO_printf(bio_err, "CA �������� �ε� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}

	// �������� ������ STORE ����ü ����
	store = X509_STORE_new();
	if (store == NULL)
	{
		BIO_printf(bio_err, "X509_STORE �� ���� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// �ݺ� �Լ� ����
	X509_STORE_set_verify_cb_func(store, verifyCallbackfunc);
	// ���Ϸ� ���� CA ������ ����
	if (!X509_STORE_load_locations(store, CA_CERT_FILE, NULL))
	{
		BIO_printf(bio_err, "CA �������� �ε� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// STORE �� CA ������ �߰�
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (lookup == NULL)
	{
		BIO_printf(bio_err, "X509_LOOKUP �� ���� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// CRL ����
	if (!X509_load_crl_file(lookup, CRL_FILE, X509_FILETYPE_PEM))
	{
		BIO_printf(bio_err, "CRL�� �ε� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// CA ������, CRL ���� ��� ����
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	// STORE ���ؽ�Ʈ ����
	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL)
	{
		BIO_printf(bio_err, "X509_STORE_CTX �� ���� �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	if (!X509_STORE_CTX_init(storeCtx, store, cert, NULL))
	{
		BIO_printf(bio_err, "X509_STORE_CTX�� �ʱ�ȭ �� �� �����ϴ�.");
		ERR_print_errors(bio_err);
		exit(1);
	}
	// ������ ����
	retVal = X509_verify_cert(storeCtx);
	if (retVal == 1)
	{
		BIO_printf(bio_err, "���� �Ǿ����ϴ�..");

	}
	else
	{
		BIO_printf(bio_err, "������ �� �� �����ϴ�.");
		ERR_print_errors(bio_err);

	}
	return 0;
}