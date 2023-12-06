/*
 * Copyright (C) 2014 Space Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>

#include <openssl/conf.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "_cgo_export.h"

/*
 * Functions defined in other .c files
 */
extern int go_init_locks();
extern void go_thread_locking_callback(int, int, const char*, int);
extern unsigned long go_thread_id_callback();
static int go_write_bio_puts(BIO *b, const char *str) {
	return go_write_bio_write(b, (char*)str, (int)strlen(str));
}

/*
 ************************************************
 * Tongsuo 8.3.2 or prior
 ************************************************
 */

#ifdef BABASSL_VERSION_NUMBER
const EVP_MD *X_EVP_sm3() {
       return EVP_sm3();
}
#endif

const int X_ED25519_SUPPORT = 1;
int X_EVP_PKEY_ED25519 = EVP_PKEY_ED25519;

int X_EVP_Digest(const void *data, size_t count,
		unsigned char *md, unsigned int *size,
		const EVP_MD *type, ENGINE *impl){
	return EVP_Digest(data, count, md, size, type, impl);
}

int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey){
	return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
		size_t *siglen, const unsigned char *tbs, size_t tbslen) {
	return EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}


int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey){
	return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
		size_t siglen, const unsigned char *tbs, size_t tbslen){
	return EVP_DigestVerify(ctx, sigret, siglen, tbs, tbslen);
}

void X_BIO_set_data(BIO* bio, void* data) {
	BIO_set_data(bio, data);
}

void* X_BIO_get_data(BIO* bio) {
	return BIO_get_data(bio);
}

EVP_MD_CTX* X_EVP_MD_CTX_new() {
	return EVP_MD_CTX_new();
}

int X_EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in) {
	return EVP_MD_CTX_copy_ex(out, in);
}

void X_EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
	EVP_MD_CTX_free(ctx);
}

static int x_bio_create(BIO *b) {
	BIO_set_shutdown(b, 1);
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	BIO_clear_flags(b, ~0);
	return 1;
}

static int x_bio_free(BIO *b) {
	return 1;
}

static BIO_METHOD *writeBioMethod;
static BIO_METHOD *readBioMethod;

BIO_METHOD* BIO_s_readBio() { return readBioMethod; }
BIO_METHOD* BIO_s_writeBio() { return writeBioMethod; }

int x_bio_init_methods() {
	writeBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Write BIO");
	if (!writeBioMethod) {
		return 1;
	}
	if (1 != BIO_meth_set_write(writeBioMethod,
				(int (*)(BIO *, const char *, int))go_write_bio_write)) {
		return 2;
	}
	if (1 != BIO_meth_set_puts(writeBioMethod, go_write_bio_puts)) {
		return 3;
	}
	if (1 != BIO_meth_set_ctrl(writeBioMethod, go_write_bio_ctrl)) {
		return 4;
	}
	if (1 != BIO_meth_set_create(writeBioMethod, x_bio_create)) {
		return 5;
	}
	if (1 != BIO_meth_set_destroy(writeBioMethod, x_bio_free)) {
		return 6;
	}

	readBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Read BIO");
	if (!readBioMethod) {
		return 7;
	}
	if (1 != BIO_meth_set_read(readBioMethod, go_read_bio_read)) {
		return 8;
	}
	if (1 != BIO_meth_set_ctrl(readBioMethod, go_read_bio_ctrl)) {
		return 9;
	}
	if (1 != BIO_meth_set_create(readBioMethod, x_bio_create)) {
		return 10;
	}
	if (1 != BIO_meth_set_destroy(readBioMethod, x_bio_free)) {
		return 11;
	}

	return 0;
}

const EVP_MD *X_EVP_dss() {
	return NULL;
}

const EVP_MD *X_EVP_dss1() {
	return NULL;
}

const EVP_MD *X_EVP_sha() {
	return NULL;
}

int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx) {
	return EVP_CIPHER_CTX_encrypting(ctx);
}

int X_X509_add_ref(X509* x509) {
	return X509_up_ref(x509);
}

const ASN1_TIME *X_X509_get0_notBefore(const X509 *x) {
	return X509_get0_notBefore(x);
}

const ASN1_TIME *X_X509_get0_notAfter(const X509 *x) {
	return X509_get0_notAfter(x);
}

HMAC_CTX *X_HMAC_CTX_new(void) {
	return HMAC_CTX_new();
}

void X_HMAC_CTX_free(HMAC_CTX *ctx) {
	HMAC_CTX_free(ctx);
}

int X_PEM_write_bio_PrivateKey_traditional(BIO *bio, EVP_PKEY *key, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	return PEM_write_bio_PrivateKey_traditional(bio, key, enc, kstr, klen, cb, u);
}

int X_shim_init() {
	int rc = 0;

	OPENSSL_config(NULL);
	ENGINE_load_builtin_engines();
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	//
	// Set up OPENSSL thread safety callbacks.
	rc = go_init_locks();
	if (rc != 0) {
		return rc;
	}
	CRYPTO_set_locking_callback(go_thread_locking_callback);
	CRYPTO_set_id_callback(go_thread_id_callback);

	rc = x_bio_init_methods();
	if (rc != 0) {
		return rc;
	}

	return 0;
}

void * X_OPENSSL_malloc(size_t size) {
	return OPENSSL_malloc(size);
}

void X_OPENSSL_free(void *ref) {
	OPENSSL_free(ref);
}

long X_SSL_set_options(SSL* ssl, long options) {
	return SSL_set_options(ssl, options);
}

long X_SSL_get_options(SSL* ssl) {
	return SSL_get_options(ssl);
}

long X_SSL_clear_options(SSL* ssl, long options) {
	return SSL_clear_options(ssl, options);
}

long X_SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
   return SSL_set_tlsext_host_name(ssl, name);
}

const char *X_SSL_get_cipher_name(const SSL *ssl) {
   return SSL_get_cipher_name(ssl);
}

const char *X_SSL_get_version(const SSL *ssl) {
   return SSL_get_version(ssl);
}

int X_SSL_session_reused(SSL *ssl) {
    return SSL_session_reused(ssl);
}

int X_SSL_new_index() {
	return SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

int X_SSL_verify_cb(int ok, X509_STORE_CTX* store) {
	SSL* ssl = (SSL *)X509_STORE_CTX_get_ex_data(store,
			SSL_get_ex_data_X509_STORE_CTX_idx());
	void* p = SSL_get_ex_data(ssl, get_ssl_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return go_ssl_verify_cb_thunk(p, ok, store);
}

const SSL_METHOD *X_SSLv23_method() {
	return SSLv23_method();
}


const SSL_METHOD *X_SSLv3_method() {
#ifndef OPENSSL_NO_SSL3_METHOD
	return SSLv3_method();
#else
	return NULL;
#endif
}

const SSL_METHOD *X_TLSv1_method() {
	return TLSv1_method();
}

const SSL_METHOD *X_TLSv1_1_method() {
#if defined(TLS1_1_VERSION) && !defined(OPENSSL_SYSNAME_MACOSX)
	return TLSv1_1_method();
#else
	return NULL;
#endif
}

const SSL_METHOD *X_TLSv1_2_method() {
#if defined(TLS1_2_VERSION) && !defined(OPENSSL_SYSNAME_MACOSX)
	return TLSv1_2_method();
#else
	return NULL;
#endif
}

const SSL_METHOD *X_NTLS_method() {
	return NTLS_method();
}
const SSL_METHOD *X_NTLS_client_method() {
	return NTLS_client_method();
}
const SSL_METHOD *X_NTLS_server_method() {
	return NTLS_server_method();
}

int X_SSL_CTX_new_index() {
	return SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

void X_SSL_CTX_enable_ntls(SSL_CTX* ctx) {
	return SSL_CTX_enable_ntls(ctx);
}

long X_SSL_CTX_set_options(SSL_CTX* ctx, long options) {
	return SSL_CTX_set_options(ctx, options);
}

long X_SSL_CTX_clear_options(SSL_CTX* ctx, long options) {
	return SSL_CTX_clear_options(ctx, options);
}

long X_SSL_CTX_get_options(SSL_CTX* ctx) {
	return SSL_CTX_get_options(ctx);
}

long X_SSL_CTX_set_mode(SSL_CTX* ctx, long modes) {
	return SSL_CTX_set_mode(ctx, modes);
}

long X_SSL_CTX_get_mode(SSL_CTX* ctx) {
	return SSL_CTX_get_mode(ctx);
}

long X_SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long modes) {
	return SSL_CTX_set_session_cache_mode(ctx, modes);
}

long X_SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long t) {
	return SSL_CTX_sess_set_cache_size(ctx, t);
}

long X_SSL_CTX_sess_get_cache_size(SSL_CTX* ctx) {
	return SSL_CTX_sess_get_cache_size(ctx);
}

long X_SSL_CTX_set_timeout(SSL_CTX* ctx, long t) {
	return SSL_CTX_set_timeout(ctx, t);
}

long X_SSL_CTX_get_timeout(SSL_CTX* ctx) {
	return SSL_CTX_get_timeout(ctx);
}

long X_SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509 *cert) {
	return SSL_CTX_add_extra_chain_cert(ctx, cert);
}

long X_SSL_CTX_set_tmp_ecdh(SSL_CTX* ctx, EC_KEY *key) {
	return SSL_CTX_set_tmp_ecdh(ctx, key);
}

long X_SSL_CTX_set_tlsext_servername_callback(
		SSL_CTX* ctx, int (*cb)(SSL *con, int *ad, void *args)) {
	return SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}

int X_SSL_CTX_verify_cb(int ok, X509_STORE_CTX* store) {
	SSL* ssl = (SSL *)X509_STORE_CTX_get_ex_data(store,
			SSL_get_ex_data_X509_STORE_CTX_idx());
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return go_ssl_ctx_verify_cb_thunk(p, ok, store);
}

long X_SSL_CTX_set_tmp_dh(SSL_CTX* ctx, DH *dh) {
    return SSL_CTX_set_tmp_dh(ctx, dh);
}

long X_PEM_read_DHparams(SSL_CTX* ctx, DH *dh) {
    return SSL_CTX_set_tmp_dh(ctx, dh);
}

int X_SSL_CTX_set_tlsext_ticket_key_cb(SSL_CTX *sslctx,
        int (*cb)(SSL *s, unsigned char key_name[16],
                  unsigned char iv[EVP_MAX_IV_LENGTH],
                  EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)) {
    return SSL_CTX_set_tlsext_ticket_key_cb(sslctx, cb);
}

int X_SSL_CTX_ticket_key_cb(SSL *s, unsigned char key_name[16],
		unsigned char iv[EVP_MAX_IV_LENGTH],
		EVP_CIPHER_CTX *cctx, HMAC_CTX *hctx, int enc) {

	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(s);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	// get the pointer to the go Ctx object and pass it back into the thunk
	return go_ticket_key_cb_thunk(p, s, key_name, iv, cctx, hctx, enc);
}

int X_BIO_get_flags(BIO *b) {
	return BIO_get_flags(b);
}

void X_BIO_set_flags(BIO *b, int flags) {
	return BIO_set_flags(b, flags);
}

void X_BIO_clear_flags(BIO *b, int flags) {
	BIO_clear_flags(b, flags);
}

int X_BIO_read(BIO *b, void *buf, int len) {
	return BIO_read(b, buf, len);
}

int X_BIO_write(BIO *b, const void *buf, int len) {
	return BIO_write(b, buf, len);
}

BIO *X_BIO_new_write_bio() {
	return BIO_new(BIO_s_writeBio());
}

BIO *X_BIO_new_read_bio() {
	return BIO_new(BIO_s_readBio());
}

const EVP_MD *X_EVP_get_digestbyname(const char *name) {
	return EVP_get_digestbyname(name);
}

const EVP_MD *X_EVP_md_null() {
	return EVP_md_null();
}

const EVP_MD *X_EVP_md5() {
	return EVP_md5();
}

#ifndef TONGSUO_VERSION_NUMBER
const EVP_MD *X_EVP_md4() {
	return EVP_md4();
}

const EVP_MD *X_EVP_ripemd160() {
	return EVP_ripemd160();
}
#endif

const EVP_MD *X_EVP_sha224() {
	return EVP_sha224();
}

const EVP_MD *X_EVP_sha1() {
	return EVP_sha1();
}

const EVP_MD *X_EVP_sha256() {
	return EVP_sha256();
}

const EVP_MD *X_EVP_sha384() {
	return EVP_sha384();
}

const EVP_MD *X_EVP_sha512() {
	return EVP_sha512();
}

int X_EVP_MD_size(const EVP_MD *md) {
	return EVP_MD_size(md);
}

int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
	return EVP_DigestInit_ex(ctx, type, impl);
}

int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
	return EVP_DigestUpdate(ctx, d, cnt);
}

int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
	return EVP_DigestFinal_ex(ctx, md, s);
}

int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_SignInit(ctx, type);
}

int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) {
	return EVP_SignUpdate(ctx, d, cnt);
}

EVP_PKEY *X_EVP_PKEY_new(void) {
	return EVP_PKEY_new();
}

void X_EVP_PKEY_free(EVP_PKEY *pkey) {
	EVP_PKEY_free(pkey);
}

int X_EVP_PKEY_size(EVP_PKEY *pkey) {
	return EVP_PKEY_size(pkey);
}

struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey) {
	return EVP_PKEY_get1_RSA(pkey);
}

int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key) {
	return EVP_PKEY_set1_RSA(pkey, key);
}

int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key) {
	return EVP_PKEY_assign(pkey, type, key);
}

int X_EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey) {
	return EVP_SignFinal(ctx, md, s, pkey);
}

int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_VerifyInit(ctx, type);
}

int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d,
		unsigned int cnt) {
	return EVP_VerifyUpdate(ctx, d, cnt);
}

int X_EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey) {
	return EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
}

int X_EVP_CIPHER_block_size(EVP_CIPHER *c) {
    return EVP_CIPHER_block_size(c);
}

int X_EVP_CIPHER_key_length(EVP_CIPHER *c) {
    return EVP_CIPHER_key_length(c);
}

int X_EVP_CIPHER_iv_length(EVP_CIPHER *c) {
    return EVP_CIPHER_iv_length(c);
}

int X_EVP_CIPHER_nid(EVP_CIPHER *c) {
    return EVP_CIPHER_nid(c);
}

int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_block_size(ctx);
}

int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_key_length(ctx);
}

int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_iv_length(ctx);
}

void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding) {
    //openssl always returns 1 for set_padding
    //hence return value is not checked
    EVP_CIPHER_CTX_set_padding(ctx, padding);
}

const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_cipher(ctx);
}

int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
	return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

size_t X_HMAC_size(const HMAC_CTX *e) {
	return HMAC_size(e);
}

int X_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl) {
	return HMAC_Init_ex(ctx, key, len, md, impl);
}

int X_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len) {
	return HMAC_Update(ctx, data, len);
}

int X_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
	return HMAC_Final(ctx, md, len);
}

int X_sk_X509_num(STACK_OF(X509) *sk) {
	return sk_X509_num(sk);
}

X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i) {
   return sk_X509_value(sk, i);
}

long X_X509_get_version(const X509 *x) {
	return X509_get_version(x);
}

int X_X509_set_version(X509 *x, long version) {
	return X509_set_version(x, version);
}
