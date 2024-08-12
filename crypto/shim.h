// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>

/* shim  methods */
extern int X_tscrypto_init();

/* Library methods */
extern void X_OPENSSL_free(void *ref);
extern void *X_OPENSSL_malloc(size_t size);

/* BIO methods */
extern int X_BIO_get_flags(BIO *b);
extern void X_BIO_set_flags(BIO *bio, int flags);
extern void X_BIO_clear_flags(BIO *bio, int flags);
extern void X_BIO_set_data(BIO *bio, void* data);
extern void *X_BIO_get_data(BIO *bio);
extern int X_BIO_read(BIO *b, void *buf, int len);
extern int X_BIO_write(BIO *b, const void *buf, int len);
extern BIO *X_BIO_new_write_bio();
extern BIO *X_BIO_new_read_bio();
extern long X_BIO_get_mem_data(BIO *b, char **pp);

extern int X_BN_num_bytes(const BIGNUM *a);

/* EVP methods */
extern const int X_ED25519_SUPPORT;
extern int X_EVP_PKEY_ED25519;
extern const EVP_MD *X_EVP_get_digestbyname(const char *name);
extern EVP_MD_CTX *X_EVP_MD_CTX_new();
extern int X_EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
extern void X_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
extern const EVP_MD *X_EVP_md_null();
extern const EVP_MD *X_EVP_md5();
extern const EVP_MD *X_EVP_md4();
extern const EVP_MD *X_EVP_sha();
extern const EVP_MD *X_EVP_sha1();
extern const EVP_MD *X_EVP_dss();
extern const EVP_MD *X_EVP_dss1();
extern const EVP_MD *X_EVP_ripemd160();
extern const EVP_MD *X_EVP_sha224();
extern const EVP_MD *X_EVP_sha256();
extern const EVP_MD *X_EVP_sha384();
extern const EVP_MD *X_EVP_sha512();
extern const EVP_MD *X_EVP_sm3();
extern int X_EVP_MD_size(const EVP_MD *md);
extern int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
extern int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
extern int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
extern int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
extern int X_EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
extern EVP_PKEY *X_EVP_PKEY_new(void);
extern void X_EVP_PKEY_free(EVP_PKEY *pkey);
extern int X_EVP_PKEY_size(EVP_PKEY *pkey);
extern struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
extern int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
extern int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key);
extern int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
extern int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int X_EVP_CIPHER_block_size(EVP_CIPHER *c);
extern int X_EVP_CIPHER_key_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_iv_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_nid(EVP_CIPHER *c);
extern int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx);
extern void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding);
extern const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
extern int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
extern int X_EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, void *id, int id_len);
extern int X_EVP_PKEY_is_sm2(EVP_PKEY *pkey);

/* HMAC methods */
extern size_t X_HMAC_size(const HMAC_CTX *e);
extern HMAC_CTX *X_HMAC_CTX_new(void);
extern void X_HMAC_CTX_free(HMAC_CTX *ctx);
extern int X_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
extern int X_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
extern int X_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

/* X509 methods */
extern const ASN1_TIME *X_X509_get0_notBefore(const X509 *x);
extern const ASN1_TIME *X_X509_get0_notAfter(const X509 *x);
extern long X_X509_get_version(const X509 *x);
extern int X_X509_set_version(X509 *x, long version);

/* PEM methods */
extern int X_PEM_write_bio_PrivateKey_traditional(BIO *bio, EVP_PKEY *key, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

/* ASN.1 methods */
extern ECDSA_SIG *X_d2i_ECDSA_SIG(ECDSA_SIG **psig, const unsigned char **ppin, long len);
