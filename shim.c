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


void X_tongsuogo_init(void) {
	SSL_load_error_strings();
	SSL_library_init();
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

int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version) {
	return SSL_CTX_set_max_proto_version(ctx, version);
}

int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) {
	return SSL_CTX_set_min_proto_version(ctx, version);
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
	return go_ticket_key_cb_thunk(p, key_name, cctx, hctx, enc);
}

int X_X509_add_ref(X509* x509) {
	return X509_up_ref(x509);
}

int X_sk_X509_num(STACK_OF(X509) *sk) {
	return sk_X509_num(sk);
}

X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i) {
   return sk_X509_value(sk, i);
}
