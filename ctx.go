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

package tongsuogo

// #include "shim.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

var sslCtxIdx = C.X_SSL_CTX_new_index()

type Ctx struct {
	ctx   *C.SSL_CTX
	cert  *crypto.Certificate
	chain []*crypto.Certificate

	key      crypto.PrivateKey
	verifyCb VerifyCallback
	sniCb    TLSExtServernameCallback
	alpnCb   TLSExtAlpnCallback

	encCert *crypto.Certificate
	encKey  crypto.PrivateKey

	ticketStoreMu sync.Mutex
	ticketStore   *TicketStore
}

//export get_ssl_ctx_idx
func get_ssl_ctx_idx() C.int {
	return sslCtxIdx
}

func newCtx(method *C.SSL_METHOD) (*Ctx, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sslCtx := C.SSL_CTX_new(method)
	if sslCtx == nil {
		return nil, fmt.Errorf("failed to create SSL CTX: %w", crypto.PopError())
	}
	ctx := &Ctx{ctx: sslCtx}
	// Bypass go vet check, possibly passing Go type with embedded pointer to C
	var p (*C.char) = (*C.char)(unsafe.Pointer(ctx))
	C.SSL_CTX_set_ex_data(sslCtx, get_ssl_ctx_idx(), unsafe.Pointer(p))
	runtime.SetFinalizer(ctx, func(c *Ctx) {
		C.SSL_CTX_free(c.ctx)
	})

	return ctx, nil
}

type SSLVersion int

const (
	SSLv3   SSLVersion = 0x0300 // Vulnerable to "POODLE" attack.
	TLSv1   SSLVersion = 0x0301
	TLSv1_1 SSLVersion = 0x0302
	TLSv1_2 SSLVersion = 0x0303
	TLSv1_3 SSLVersion = 0x0304
	NTLS    SSLVersion = 0x0101

	// AnyVersion Make sure to disable SSLv2 and SSLv3 if you use this. SSLv3 is vulnerable
	// to the "POODLE" attack, and SSLv2 is what, just don't even.
	AnyVersion SSLVersion = 0x01
)

// NewCtxWithVersion creates an SSL context that is specific to the provided
// SSL version. See http://www.openssl.org/docs/ssl/SSL_CTX_new.html for more.
func NewCtxWithVersion(version SSLVersion) (*Ctx, error) {
	var enableNTLS bool
	var method *C.SSL_METHOD
	if version == NTLS {
		method = C.X_NTLS_method()
		enableNTLS = true
	} else {
		method = C.TLS_method()
	}
	if method == nil {
		return nil, fmt.Errorf("unknown ssl/tls version: %w", crypto.ErrUnknownTLSVersion)
	}

	ctx, err := newCtx(method)
	if err != nil {
		return nil, err
	}

	if enableNTLS {
		C.X_SSL_CTX_enable_ntls(ctx.ctx)
	}

	if version == AnyVersion {
		C.X_SSL_CTX_set_min_proto_version(ctx.ctx, C.int(TLSv1))
		C.X_SSL_CTX_set_max_proto_version(ctx.ctx, C.int(TLSv1_3))
	} else {
		C.X_SSL_CTX_set_min_proto_version(ctx.ctx, C.int(version))
		C.X_SSL_CTX_set_max_proto_version(ctx.ctx, C.int(version))
	}

	return ctx, nil
}

// NewCtx creates a context that supports any TLS version 1.0 and newer.
func NewCtx() (*Ctx, error) {
	c, err := NewCtxWithVersion(AnyVersion)
	if err == nil {
		c.SetOptions(NoSSLv2 | NoSSLv3)
	}
	return c, err
}

// NewCtxFromFiles calls NewCtx, loads the provided files, and configures the
// context to use them.
func NewCtxFromFiles(certFile string, keyFile string) (*Ctx, error) {
	ctx, err := NewCtx()
	if err != nil {
		return nil, err
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	certs := SplitPEM(certBytes)
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificate found in '%s': %w", certFile, crypto.ErrNoCert)
	}
	first, certs := certs[0], certs[1:]
	cert, err := crypto.LoadCertificateFromPEM(first)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert from pem: %w", err)
	}

	err = ctx.UseCertificate(cert)
	if err != nil {
		return nil, err
	}

	for _, pem := range certs {
		cert, err := crypto.LoadCertificateFromPEM(pem)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert from pem: %w", err)
		}
		err = ctx.AddChainCertificate(cert)
		if err != nil {
			return nil, err
		}
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	key, err := crypto.LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key from pem: %w", err)
	}

	err = ctx.UsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

// SetEllipticCurve sets the elliptic curve used by the SSL context to
// enable an ECDH cipher suite to be selected during the handshake.
func (ctx *Ctx) SetEllipticCurve(curve crypto.EllipticCurve) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	key := C.EC_KEY_new_by_curve_name(C.int(curve))
	if key == nil {
		return fmt.Errorf("failed to create ec key: %w", crypto.PopError())
	}
	defer C.EC_KEY_free(key)

	if int(C.X_SSL_CTX_set_tmp_ecdh(ctx.ctx, key)) != 1 {
		return fmt.Errorf("failed to set temp ecdh: %w", crypto.PopError())
	}

	return nil
}

// UseSignCertificate configures the context to present the given sign certificate to
// peers.
func (ctx *Ctx) UseSignCertificate(cert *crypto.Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.cert = cert
	if int(C.SSL_CTX_use_sign_certificate(ctx.ctx, (*C.X509)(cert.GetCert()))) != 1 {
		return fmt.Errorf("failed to set sign cert: %w", crypto.PopError())
	}
	return nil
}

// UseEncryptCertificate configures the context to present the given encrypt certificate to
// peers.
func (ctx *Ctx) UseEncryptCertificate(cert *crypto.Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.encCert = cert
	if int(C.SSL_CTX_use_enc_certificate(ctx.ctx, (*C.X509)(cert.GetCert()))) != 1 {
		return fmt.Errorf("failed to set enc cert: %w", crypto.PopError())
	}
	return nil
}

// UseCertificate configures the context to present the given certificate to
// peers.
func (ctx *Ctx) UseCertificate(cert *crypto.Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.cert = cert
	if int(C.SSL_CTX_use_certificate(ctx.ctx, (*C.X509)(cert.GetCert()))) != 1 {
		return fmt.Errorf("failed to set cert: %w", crypto.PopError())
	}
	return nil
}

// AddChainCertificate adds a certificate to the chain presented in the
// handshake.
func (ctx *Ctx) AddChainCertificate(cert *crypto.Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.chain = append(ctx.chain, cert)
	if int(C.X_SSL_CTX_add_extra_chain_cert(ctx.ctx, (*C.X509)(cert.GetCert()))) != 1 {
		return fmt.Errorf("failed to set chain cert: %w", crypto.PopError())
	}
	// OpenSSL takes ownership via SSL_CTX_add_extra_chain_cert
	runtime.SetFinalizer(cert, nil)
	return nil
}

// UseSignPrivateKey configures the context to use the given sign private key for SSL
// handshakes.
func (ctx *Ctx) UseSignPrivateKey(key crypto.PrivateKey) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.key = key
	if int(C.SSL_CTX_use_sign_PrivateKey(ctx.ctx, (*C.EVP_PKEY)(key.EvpPKey()))) != 1 {
		return fmt.Errorf("failed to set sign private key: %w", crypto.PopError())
	}
	return nil
}

// UseEncryptPrivateKey configures the context to use the given encrypt private key for SSL
// handshakes.
func (ctx *Ctx) UseEncryptPrivateKey(key crypto.PrivateKey) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.encKey = key
	if int(C.SSL_CTX_use_enc_PrivateKey(ctx.ctx, (*C.EVP_PKEY)(key.EvpPKey()))) != 1 {
		return fmt.Errorf("failed to set enc private key: %w", crypto.PopError())
	}
	return nil
}

// UsePrivateKey configures the context to use the given private key for SSL
// handshakes.
func (ctx *Ctx) UsePrivateKey(key crypto.PrivateKey) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx.key = key
	if int(C.SSL_CTX_use_PrivateKey(ctx.ctx, (*C.EVP_PKEY)(key.EvpPKey()))) != 1 {
		return fmt.Errorf("failed to set private key: %w", crypto.PopError())
	}
	return nil
}

type CertificateStore struct {
	store *C.X509_STORE
	// for GC
	ctx   *Ctx
	certs []*crypto.Certificate
}

// NewCertificateStore Allocate a new, empty CertificateStore
func NewCertificateStore() (*CertificateStore, error) {
	s := C.X509_STORE_new()
	if s == nil {
		return nil, fmt.Errorf("failed to create X509_STORE: %w", crypto.PopError())
	}
	store := &CertificateStore{store: s, ctx: nil, certs: nil}
	runtime.SetFinalizer(store, func(s *CertificateStore) {
		C.X509_STORE_free(s.store)
	})
	return store, nil
}

// LoadCertificatesFromPEM Parse a chained PEM file, loading all certificates into the Store.
func (s *CertificateStore) LoadCertificatesFromPEM(data []byte) error {
	pems := SplitPEM(data)
	for _, pem := range pems {
		cert, err := crypto.LoadCertificateFromPEM(pem)
		if err != nil {
			return fmt.Errorf("failed to load cert from pem: %w", err)
		}
		err = s.AddCertificate(cert)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetCertificateStore returns the context's certificate store that will be
// used for peer validation.
func (ctx *Ctx) GetCertificateStore() *CertificateStore {
	// we don't need to dealloc the cert store pointer here, because it points
	// to a ctx internal. so we do need to keep the ctx around
	return &CertificateStore{
		store: C.SSL_CTX_get_cert_store(ctx.ctx),
		ctx:   ctx,
		certs: nil,
	}
}

// SetDHParameters sets the DH group (DH parameters) used to
// negotiate an emphemeral DH key during handshaking.
func (ctx *Ctx) SetDHParameters(dh *crypto.DH) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if int(C.X_SSL_CTX_set_tmp_dh(ctx.ctx, (*C.DH)(dh.GetDH()))) != 1 {
		return fmt.Errorf("failed to set temp dh: %w", crypto.PopError())
	}
	return nil
}

// AddCertificate marks the provided Certificate as a trusted certificate in
// the given CertificateStore.
func (s *CertificateStore) AddCertificate(cert *crypto.Certificate) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s.certs = append(s.certs, cert)
	if int(C.X509_STORE_add_cert(s.store, (*C.X509)(cert.GetCert()))) != 1 {
		return fmt.Errorf("failed to add cert: %w", crypto.PopError())
	}
	return nil
}

type CertificateStoreCtx struct {
	ctx    *C.X509_STORE_CTX
	sslCtx *Ctx
}

func (ctx *CertificateStoreCtx) VerifyResult() VerifyResult {
	return VerifyResult(C.X509_STORE_CTX_get_error(ctx.ctx))
}

func (ctx *CertificateStoreCtx) Err() error {
	code := C.X509_STORE_CTX_get_error(ctx.ctx)
	if code == C.X509_V_OK {
		return nil
	}

	return errors.New("x509 verify error: " + C.GoString(C.X509_verify_cert_error_string(C.long(code))))
}

func (ctx *CertificateStoreCtx) Depth() int {
	return int(C.X509_STORE_CTX_get_error_depth(ctx.ctx))
}

// GetCurrentCert the certicate returned is only valid for the lifetime of the underlying
// X509_STORE_CTX
func (ctx *CertificateStoreCtx) GetCurrentCert() *crypto.Certificate {
	x509 := C.X509_STORE_CTX_get_current_cert(ctx.ctx)
	if x509 == nil {
		return nil
	}
	// add a ref
	if C.X_X509_add_ref(x509) != 1 {
		return nil
	}
	cert := crypto.NewCertWrapper((unsafe.Pointer(x509)))
	runtime.SetFinalizer(cert, func(cert *crypto.Certificate) {
		C.X509_free((*C.X509)(cert.GetCert()))
	})
	return cert
}

// LoadVerifyLocations tells the context to trust all certificate authorities
// provided in either the ca_file or the ca_path.
// See http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html for
// more.
func (ctx *Ctx) LoadVerifyLocations(caFile string, caPath string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var cCaFile, cCaPath *C.char

	if caPath == "" && caFile == "" {
		if C.SSL_CTX_set_default_verify_file(ctx.ctx) <= 0 {
			return fmt.Errorf("failed to set default verify file: %w", crypto.PopError())
		}
		if C.SSL_CTX_set_default_verify_dir(ctx.ctx) <= 0 {
			return fmt.Errorf("failed to set default verify dir: %w", crypto.PopError())
		}

		return nil
	}

	if caFile != "" {
		cCaFile = C.CString(caFile)
		defer C.free(unsafe.Pointer(cCaFile))
	}

	if caPath != "" {
		cCaPath = C.CString(caPath)
		defer C.free(unsafe.Pointer(cCaPath))
	}

	if C.SSL_CTX_load_verify_locations(ctx.ctx, cCaFile, cCaPath) <= 0 {
		return fmt.Errorf("failed to load verify locations: %w", crypto.PopError())
	}
	return nil
}

type Options int

const (
	// NoCompression is only valid if you are using OpenSSL 1.0.1 or newer
	NoCompression                      Options = C.SSL_OP_NO_COMPRESSION
	NoSSLv2                            Options = C.SSL_OP_NO_SSLv2
	NoSSLv3                            Options = C.SSL_OP_NO_SSLv3
	NoTLSv1                            Options = C.SSL_OP_NO_TLSv1
	CipherServerPreference             Options = C.SSL_OP_CIPHER_SERVER_PREFERENCE
	NoSessionResumptionOrRenegotiation Options = C.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	NoTicket                           Options = C.SSL_OP_NO_TICKET
)

// SetOptions sets context options. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (ctx *Ctx) SetOptions(options Options) Options {
	return Options(C.X_SSL_CTX_set_options(
		ctx.ctx, C.long(options)))
}

func (ctx *Ctx) ClearOptions(options Options) Options {
	return Options(C.X_SSL_CTX_clear_options(
		ctx.ctx, C.long(options)))
}

// GetOptions returns context options. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
func (ctx *Ctx) GetOptions() Options {
	return Options(C.X_SSL_CTX_get_options(ctx.ctx))
}

type Modes int

const (
	// ReleaseBuffers is only valid if you are using OpenSSL 1.0.1 or newer
	ReleaseBuffers Modes = C.SSL_MODE_RELEASE_BUFFERS
)

// SetMode sets context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (ctx *Ctx) SetMode(modes Modes) Modes {
	return Modes(C.X_SSL_CTX_set_mode(ctx.ctx, C.long(modes)))
}

// GetMode returns context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (ctx *Ctx) GetMode() Modes {
	return Modes(C.X_SSL_CTX_get_mode(ctx.ctx))
}

type VerifyOptions int

const (
	VerifyNone             VerifyOptions = C.SSL_VERIFY_NONE
	VerifyPeer             VerifyOptions = C.SSL_VERIFY_PEER
	VerifyFailIfNoPeerCert VerifyOptions = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	VerifyClientOnce       VerifyOptions = C.SSL_VERIFY_CLIENT_ONCE
)

type VerifyCallback func(ok bool, store *CertificateStoreCtx) bool

//export go_ssl_ctx_verify_cb_thunk
func go_ssl_ctx_verify_cb_thunk(callback unsafe.Pointer, ok C.int, ctx *C.X509_STORE_CTX) C.int {
	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: verify callback panic'd: %v", err)
			os.Exit(1)
		}
	}()
	verifyCb := (*Ctx)(callback).verifyCb
	// set up defaults just in case verify_cb is nil
	if verifyCb != nil {
		store := &CertificateStoreCtx{ctx: ctx, sslCtx: nil}
		if verifyCb(ok == 1, store) {
			ok = 1
		} else {
			ok = 0
		}
	}
	return ok
}

// SetVerify controls peer verification settings. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (ctx *Ctx) SetVerify(options VerifyOptions, verifyCb VerifyCallback) {
	ctx.verifyCb = verifyCb
	if verifyCb != nil {
		C.SSL_CTX_set_verify(ctx.ctx, C.int(options), (*[0]byte)(C.X_SSL_CTX_verify_cb))
	} else {
		C.SSL_CTX_set_verify(ctx.ctx, C.int(options), nil)
	}
}

func (ctx *Ctx) SetVerifyMode(options VerifyOptions) {
	ctx.SetVerify(options, ctx.verifyCb)
}

func (ctx *Ctx) SetVerifyCallback(verifyCb VerifyCallback) {
	ctx.SetVerify(ctx.VerifyMode(), verifyCb)
}

func (ctx *Ctx) GetVerifyCallback() VerifyCallback {
	return ctx.verifyCb
}

func (ctx *Ctx) VerifyMode() VerifyOptions {
	return VerifyOptions(C.SSL_CTX_get_verify_mode(ctx.ctx))
}

// SetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (ctx *Ctx) SetVerifyDepth(depth int) {
	C.SSL_CTX_set_verify_depth(ctx.ctx, C.int(depth))
}

// GetVerifyDepth controls how many certificates deep the certificate
// verification logic is willing to follow a certificate chain. See
// https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
func (ctx *Ctx) GetVerifyDepth() int {
	return int(C.SSL_CTX_get_verify_depth(ctx.ctx))
}

type TLSExtServernameCallback func(ssl *SSL) SSLTLSExtErr

// SetTLSExtServernameCallback sets callback function for Server Name Indication
// (SNI) rfc6066 (http://tools.ietf.org/html/rfc6066). See
// http://stackoverflow.com/questions/22373332/serving-multiple-domains-in-one-box-with-sni
func (ctx *Ctx) SetTLSExtServernameCallback(sniCb TLSExtServernameCallback) {
	ctx.sniCb = sniCb
	C.X_SSL_CTX_set_tlsext_servername_callback(ctx.ctx, (*[0]byte)(C.sni_cb))
}

type TLSExtAlpnCallback func(ssl *SSL, out unsafe.Pointer, outlen unsafe.Pointer, in unsafe.Pointer, inlen uint,
	arg unsafe.Pointer) SSLTLSExtErr

// SetServerALPNProtos sets the ALPN protocol list, if failed the negotiation will lead to server handshake failure
func (ctx *Ctx) SetServerALPNProtos(protos []string) {
	// Construct the protocol list (format: length byte of each protocol + protocol content)
	var protoList []byte
	for _, proto := range protos {
		protoList = append(protoList, byte(len(proto))) // Add the length of the protocol
		protoList = append(protoList, []byte(proto)...) // Add the protocol content
	}

	ctx.alpnCb = func(_ *SSL, out unsafe.Pointer, outlen unsafe.Pointer, in unsafe.Pointer, inlen uint,
		arg unsafe.Pointer,
	) SSLTLSExtErr {
		_ = arg // Unused

		// Use OpenSSL function to select the protocol
		ret := C.SSL_select_next_proto(
			(**C.uchar)(out),
			(*C.uchar)(outlen),
			(*C.uchar)(unsafe.Pointer(&protoList[0])),
			C.uint(len(protoList)),
			(*C.uchar)(in),
			C.uint(inlen),
		)

		if ret != NPNNegotiated {
			return SSLTLSExtErrAlertFatal
		}

		return SSLTLSExtErrOK
	}
	C.SSL_CTX_set_alpn_select_cb(ctx.ctx, (*[0]byte)(C.alpn_cb), nil)
}

// SetClientALPNProtos sets the ALPN protocol list
func (ctx *Ctx) SetClientALPNProtos(protos []string) error {
	// Construct the protocol list (format: length byte of each protocol + protocol content)
	var protoList []byte
	for _, proto := range protos {
		protoList = append(protoList, byte(len(proto))) // Add the length of the protocol
		protoList = append(protoList, []byte(proto)...) // Add the protocol content
	}

	// Convert Go's []byte to a C pointer
	cProtoList := (*C.uchar)(C.CBytes(protoList))
	defer C.free(unsafe.Pointer(cProtoList)) // Ensure memory is freed after use

	// Call the C function to set the ALPN protocols
	ret := C.SSL_CTX_set_alpn_protos(ctx.ctx, cProtoList, C.uint(len(protoList)))
	if ret != 0 {
		return fmt.Errorf("failed to set ALPN protocols: %w", crypto.PopError())
	}
	return nil
}

func (ctx *Ctx) SetSessionID(sessionID []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var ptr *C.uchar
	if len(sessionID) > 0 {
		ptr = (*C.uchar)(unsafe.Pointer(&sessionID[0]))
	}
	if int(C.SSL_CTX_set_session_id_context(ctx.ctx, ptr,
		C.uint(len(sessionID)))) == 0 {
		return fmt.Errorf("failed to set session id ctx: %w", crypto.PopError())
	}
	return nil
}

// SetCipherList sets the list of available ciphers. The format of the list is
// described at http://www.openssl.org/docs/apps/ciphers.html, but see
// http://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html for more.
func (ctx *Ctx) SetCipherList(list string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	clist := C.CString(list)
	defer C.free(unsafe.Pointer(clist))

	if int(C.SSL_CTX_set_cipher_list(ctx.ctx, clist)) == 0 {
		return fmt.Errorf("failed to set cipher list: %w", crypto.PopError())
	}
	return nil
}

func (ctx *Ctx) SetCipherSuites(suites string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	csuits := C.CString(suites)
	defer C.free(unsafe.Pointer(csuits))

	if int(C.SSL_CTX_set_ciphersuites(ctx.ctx, csuits)) == 0 {
		return fmt.Errorf("failed to set ciphersuites: %w", crypto.PopError())
	}
	return nil
}

type SessionCacheModes int

const (
	SessionCacheOff    SessionCacheModes = C.SSL_SESS_CACHE_OFF
	SessionCacheClient SessionCacheModes = C.SSL_SESS_CACHE_CLIENT
	SessionCacheServer SessionCacheModes = C.SSL_SESS_CACHE_SERVER
	SessionCacheBoth   SessionCacheModes = C.SSL_SESS_CACHE_BOTH
)

// SetSessionCacheMode enables or disables session caching. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_session_cache_mode.html
func (ctx *Ctx) SetSessionCacheMode(modes SessionCacheModes) SessionCacheModes {
	return SessionCacheModes(
		C.X_SSL_CTX_set_session_cache_mode(ctx.ctx, C.long(modes)))
}

// Set session cache timeout. Returns previously set value.
// See https://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
func (ctx *Ctx) SetTimeout(t time.Duration) time.Duration {
	prev := C.X_SSL_CTX_set_timeout(ctx.ctx, C.long(t/time.Second))
	return time.Duration(prev) * time.Second
}

// GetTimeout Get session cache timeout.
// See https://www.openssl.org/docs/ssl/SSL_CTX_set_timeout.html
func (ctx *Ctx) GetTimeout() time.Duration {
	return time.Duration(C.X_SSL_CTX_get_timeout(ctx.ctx)) * time.Second
}

// SessSetCacheSize Set session cache size. Returns previously set value.
// https://www.openssl.org/docs/ssl/SSL_CTX_sess_set_cache_size.html
func (ctx *Ctx) SessSetCacheSize(t int) int {
	return int(C.X_SSL_CTX_sess_set_cache_size(ctx.ctx, C.long(t)))
}

// SessGetCacheSize Get session cache size.
// https://www.openssl.org/docs/ssl/SSL_CTX_sess_set_cache_size.html
func (ctx *Ctx) SessGetCacheSize() int {
	return int(C.X_SSL_CTX_sess_get_cache_size(ctx.ctx))
}
