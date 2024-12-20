// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/ssl.h>
#include "_cgo_export.h"
#include <stdio.h>

int sni_cb(SSL *con, int *ad, void *arg) {
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(con);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	return sniCbThunk(p, con, ad, arg);
}

int alpn_cb(SSL *ssl_conn, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl_conn);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	return alpn_cb_thunk(p, ssl_conn, (unsigned char **)out, outlen, (unsigned char *)in, inlen, arg);
}