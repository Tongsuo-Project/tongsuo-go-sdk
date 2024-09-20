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

#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "crypto/shim.h"

#ifndef SSL_MODE_RELEASE_BUFFERS
#define SSL_MODE_RELEASE_BUFFERS 0
#endif

#ifndef SSL_OP_NO_COMPRESSION
#define SSL_OP_NO_COMPRESSION 0
#endif

/* shim  methods */
extern int X_tongsuogo_init(void);

/* SSL methods */
extern long X_SSL_set_options(SSL* ssl, long options);
extern long X_SSL_get_options(SSL* ssl);
extern long X_SSL_clear_options(SSL* ssl, long options);
extern long X_SSL_set_tlsext_host_name(SSL *ssl, const char *name);
extern const char *X_SSL_get_cipher_name(const SSL *ssl);
extern const char *X_SSL_get_version(const SSL *ssl);
extern int X_SSL_session_reused(SSL *ssl);
extern int X_SSL_new_index();

extern const SSL_METHOD *X_SSLv23_method();
extern const SSL_METHOD *X_SSLv3_method();
extern const SSL_METHOD *X_TLSv1_method();
extern const SSL_METHOD *X_TLSv1_1_method();
extern const SSL_METHOD *X_TLSv1_2_method();
extern const SSL_METHOD *X_NTLS_method();
extern const SSL_METHOD *X_NTLS_client_method();
extern const SSL_METHOD *X_NTLS_server_method();

#if defined SSL_CTRL_SET_TLSEXT_HOSTNAME
extern int sni_cb(SSL *ssl_conn, int *ad, void *arg);
#endif

extern int alpn_cb(SSL *ssl_conn, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
extern int X_SSL_verify_cb(int ok, X509_STORE_CTX* store);

/* SSL_CTX methods */
extern int X_SSL_CTX_new_index();
extern void X_SSL_CTX_enable_ntls(SSL_CTX* ctx);
extern long X_SSL_CTX_set_options(SSL_CTX* ctx, long options);
extern long X_SSL_CTX_clear_options(SSL_CTX* ctx, long options);
extern long X_SSL_CTX_get_options(SSL_CTX* ctx);
extern long X_SSL_CTX_set_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_get_mode(SSL_CTX* ctx);
extern long X_SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, long modes);
extern long X_SSL_CTX_sess_set_cache_size(SSL_CTX* ctx, long t);
extern long X_SSL_CTX_sess_get_cache_size(SSL_CTX* ctx);
extern long X_SSL_CTX_set_timeout(SSL_CTX* ctx, long t);
extern long X_SSL_CTX_get_timeout(SSL_CTX* ctx);
extern long X_SSL_CTX_add_extra_chain_cert(SSL_CTX* ctx, X509 *cert);
extern long X_SSL_CTX_set_tmp_ecdh(SSL_CTX* ctx, EC_KEY *key);
extern long X_SSL_CTX_set_tlsext_servername_callback(SSL_CTX* ctx, int (*cb)(SSL *con, int *ad, void *args));
extern int X_SSL_CTX_verify_cb(int ok, X509_STORE_CTX* store);
extern long X_SSL_CTX_set_tmp_dh(SSL_CTX* ctx, DH *dh);
extern long X_PEM_read_DHparams(SSL_CTX* ctx, DH *dh);
extern int X_SSL_CTX_set_tlsext_ticket_key_cb(SSL_CTX *sslctx,
        int (*cb)(SSL *s, unsigned char key_name[16],
                  unsigned char iv[EVP_MAX_IV_LENGTH],
                  EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc));
extern int X_SSL_CTX_ticket_key_cb(SSL *s, unsigned char key_name[16],
        unsigned char iv[EVP_MAX_IV_LENGTH],
        EVP_CIPHER_CTX *cctx, HMAC_CTX *hctx, int enc);

extern int X_X509_add_ref(X509* x509);
extern int X_sk_X509_num(STACK_OF(X509) *sk);
extern X509 *X_sk_X509_value(STACK_OF(X509)* sk, int i);
