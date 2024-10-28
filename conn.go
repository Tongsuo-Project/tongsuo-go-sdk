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
	"io"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/utils"
)

var (
	errZeroReturn = errors.New("zero return")
	errWantRead   = errors.New("want read")
	errWantWrite  = errors.New("want write")
	errTryAgain   = errors.New("try again")
)

type Conn struct {
	*SSL

	conn           net.Conn
	ctx            *Ctx // for gc
	intoSSL        *crypto.ReadBio
	fromSSL        *crypto.WriteBio
	isShutdown     bool
	mtx            sync.Mutex
	wantReadFuture *utils.Future
}

type VerifyResult int

const (
	Ok                            VerifyResult = C.X509_V_OK
	UnableToGetIssuerCert         VerifyResult = C.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
	UnableToGetCrl                VerifyResult = C.X509_V_ERR_UNABLE_TO_GET_CRL
	UnableToDecryptCertSignature  VerifyResult = C.X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
	UnableToDecryptCrlSignature   VerifyResult = C.X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
	UnableToDecodeIssuerPublicKey VerifyResult = C.X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
	CertSignatureFailure          VerifyResult = C.X509_V_ERR_CERT_SIGNATURE_FAILURE
	CrlSignatureFailure           VerifyResult = C.X509_V_ERR_CRL_SIGNATURE_FAILURE
	CertNotYetValid               VerifyResult = C.X509_V_ERR_CERT_NOT_YET_VALID
	CertHasExpired                VerifyResult = C.X509_V_ERR_CERT_HAS_EXPIRED
	CrlNotYetValid                VerifyResult = C.X509_V_ERR_CRL_NOT_YET_VALID
	CrlHasExpired                 VerifyResult = C.X509_V_ERR_CRL_HAS_EXPIRED
	ErrorInCertNotBeforeField     VerifyResult = C.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
	ErrorInCertNotAfterField      VerifyResult = C.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
	ErrorInCrlLastUpdateField     VerifyResult = C.X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
	ErrorInCrlNextUpdateField     VerifyResult = C.X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
	OutOfMem                      VerifyResult = C.X509_V_ERR_OUT_OF_MEM
	DepthZeroSelfSignedCert       VerifyResult = C.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
	SelfSignedCertInChain         VerifyResult = C.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
	UnableToGetIssuerCertLocally  VerifyResult = C.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
	UnableToVerifyLeafSignature   VerifyResult = C.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
	CertChainTooLong              VerifyResult = C.X509_V_ERR_CERT_CHAIN_TOO_LONG
	CertRevoked                   VerifyResult = C.X509_V_ERR_CERT_REVOKED
	InvalidCa                     VerifyResult = C.X509_V_ERR_INVALID_CA
	PathLengthExceeded            VerifyResult = C.X509_V_ERR_PATH_LENGTH_EXCEEDED
	InvalidPurpose                VerifyResult = C.X509_V_ERR_INVALID_PURPOSE
	CertUntrusted                 VerifyResult = C.X509_V_ERR_CERT_UNTRUSTED
	CertRejected                  VerifyResult = C.X509_V_ERR_CERT_REJECTED
	SubjectIssuerMismatch         VerifyResult = C.X509_V_ERR_SUBJECT_ISSUER_MISMATCH
	AkidSkidMismatch              VerifyResult = C.X509_V_ERR_AKID_SKID_MISMATCH
	AkidIssuerSerialMismatch      VerifyResult = C.X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH
	KeyusageNoCertsign            VerifyResult = C.X509_V_ERR_KEYUSAGE_NO_CERTSIGN
	UnableToGetCrlIssuer          VerifyResult = C.X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
	UnhandledCriticalExtension    VerifyResult = C.X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
	KeyusageNoCrlSign             VerifyResult = C.X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
	UnhandledCriticalCrlExtension VerifyResult = C.X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
	InvalidNonCa                  VerifyResult = C.X509_V_ERR_INVALID_NON_CA
	ProxyPathLengthExceeded       VerifyResult = C.X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED
	KeyusageNoDigitalSignature    VerifyResult = C.X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE
	ProxyCertificatesNotAllowed   VerifyResult = C.X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
	InvalidExtension              VerifyResult = C.X509_V_ERR_INVALID_EXTENSION
	InvalidPolicyExtension        VerifyResult = C.X509_V_ERR_INVALID_POLICY_EXTENSION
	NoExplicitPolicy              VerifyResult = C.X509_V_ERR_NO_EXPLICIT_POLICY
	UnnestedResource              VerifyResult = C.X509_V_ERR_UNNESTED_RESOURCE
	ApplicationVerification       VerifyResult = C.X509_V_ERR_APPLICATION_VERIFICATION
)

func newSSL(ctx *C.SSL_CTX) (*C.SSL, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ssl := C.SSL_new(ctx)
	if ssl == nil {
		return nil, fmt.Errorf("failed to create SSL: %w", crypto.PopError())
	}

	return ssl, nil
}

func newConn(conn net.Conn, ctx *Ctx) (*Conn, error) {
	ssl, err := newSSL(ctx.ctx)
	if err != nil {
		return nil, err
	}

	intoSSL := &crypto.ReadBio{}
	fromSSL := &crypto.WriteBio{}

	if ctx.GetMode()&ReleaseBuffers > 0 {
		intoSSL.SetRelease(true)
		fromSSL.SetRelease(true)
	}

	intoSSLCbio := intoSSL.MakeCBIO()
	fromSSLCbio := fromSSL.MakeCBIO()
	if intoSSLCbio == nil || fromSSLCbio == nil {
		// these frees are null safe
		C.BIO_free((*C.BIO)(intoSSLCbio))
		C.BIO_free((*C.BIO)(fromSSLCbio))
		C.SSL_free(ssl)
		return nil, fmt.Errorf("failed to allocate memory BIO: %w", crypto.ErrMallocFailure)
	}

	// the ssl object takes ownership of these objects now
	C.SSL_set_bio(ssl, (*C.BIO)(intoSSLCbio), (*C.BIO)(fromSSLCbio))

	s := &SSL{ssl: ssl}
	C.SSL_set_ex_data(s.ssl, get_ssl_idx(), unsafe.Pointer(s.ssl))

	con := &Conn{
		SSL:     s,
		conn:    conn,
		ctx:     ctx,
		intoSSL: intoSSL,
		fromSSL: fromSSL,
	}
	runtime.SetFinalizer(con, func(c *Conn) {
		c.intoSSL.Disconnect(intoSSLCbio)
		c.fromSSL.Disconnect(fromSSLCbio)
		C.SSL_free(c.ssl)
	})

	return con, nil
}

// Client wraps an existing stream connection and puts it in the connect state
// for any subsequent handshakes.
//
// IMPORTANT NOTE: if you use this method instead of Dial to construct an SSL
// connection, you are responsible for verifying the peer's hostname.
// Otherwise, you are vulnerable to MITM attacks.
//
// Client also does not set up SNI for you like Dial does.
//
// Client connections probably won't work for you unless you set a verify
// location or add some certs to the certificate store of the client context
// you're using. This library is not nice enough to use the system certificate
// store by default for you yet.
func Client(conn net.Conn, ctx *Ctx) (*Conn, error) {
	c, err := newConn(conn, ctx)
	if err != nil {
		return nil, err
	}
	C.SSL_set_connect_state(c.ssl)
	return c, nil
}

// Server wraps an existing stream connection and puts it in the accept state
// for any subsequent handshakes.
func Server(conn net.Conn, ctx *Ctx) (*Conn, error) {
	c, err := newConn(conn, ctx)
	if err != nil {
		return nil, err
	}
	C.SSL_set_accept_state(c.ssl)
	return c, nil
}

func (c *Conn) GetCtx() *Ctx { return c.ctx }

func (c *Conn) CurrentCipher() (string, error) {
	p := C.X_SSL_get_cipher_name(c.ssl)
	if p == nil {
		return "", fmt.Errorf("failed to get cipher: %w", crypto.ErrNoCipher)
	}

	return C.GoString(p), nil
}

func (c *Conn) GetVersion() (string, error) {
	p := C.X_SSL_get_version(c.ssl)
	if p == nil {
		return "", fmt.Errorf("failed to get version: %w", crypto.ErrNoVersion)
	}

	return C.GoString(p), nil
}

func (c *Conn) fillInputBuffer() error {
	for {
		n, err := c.intoSSL.ReadFromOnce(c.conn)
		if n == 0 && err == nil {
			continue
		}

		if errors.Is(err, io.EOF) {
			c.intoSSL.MarkEOF()
			return c.Close()
		}

		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}

		return nil
	}
}

func (c *Conn) flushOutputBuffer() error {
	_, err := c.fromSSL.WriteTo(c.conn)
	if err != nil {
		return fmt.Errorf("failed to write to connection: %w", err)
	}

	return nil
}

func (c *Conn) getErrorHandler(rv C.int, errno error) func() error {
	errcode := C.SSL_get_error(c.ssl, rv)
	switch errcode {
	case C.SSL_ERROR_ZERO_RETURN:
		return func() error {
			c.Close()
			return io.ErrUnexpectedEOF
		}
	case C.SSL_ERROR_WANT_READ:
		go c.flushOutputBuffer()
		if c.wantReadFuture != nil {
			wantReadFuture := c.wantReadFuture
			return func() error {
				_, err := wantReadFuture.Get()
				if err != nil {
					return fmt.Errorf("want read future get error: %w", err)
				}
				return nil
			}
		}
		c.wantReadFuture = utils.NewFuture()
		wantReadFuture := c.wantReadFuture
		return func() error {
			var err error

			defer func() {
				c.mtx.Lock()
				c.wantReadFuture = nil
				c.mtx.Unlock()
				wantReadFuture.Set(nil, err)
			}()

			err = c.fillInputBuffer()
			if err != nil {
				return err
			}

			err = errTryAgain
			return err
		}
	case C.SSL_ERROR_WANT_WRITE:
		return func() error {
			err := c.flushOutputBuffer()
			if err != nil {
				return err
			}
			return errTryAgain
		}
	case C.SSL_ERROR_SYSCALL:
		var err error
		if C.ERR_peek_error() == 0 {
			switch rv {
			case 0:
				err = fmt.Errorf("protocol-violating: %w", crypto.ErrUnexpectedEOF)
			case -1:
				err = errno
			default:
				err = crypto.PopError()
			}
		} else {
			err = crypto.PopError()
		}
		return func() error { return fmt.Errorf("syscall error: %w", err) }
	default:
		err := crypto.PopError()
		return func() error { return fmt.Errorf("SSL error: %w", err) }
	}
}

func (c *Conn) handleError(errcb func() error) error {
	if errcb != nil {
		return errcb()
	}
	return nil
}

func (c *Conn) handshake() func() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.isShutdown {
		return func() error { return io.ErrUnexpectedEOF }
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rv, errno := C.SSL_do_handshake(c.ssl)
	if rv > 0 {
		return nil
	}

	return c.getErrorHandler(rv, errno)
}

// Handshake performs an SSL handshake. If a handshake is not manually
// triggered, it will run before the first I/O on the encrypted stream.
func (c *Conn) Handshake() error {
	err := errTryAgain

	for errors.Is(err, errTryAgain) {
		err = c.handleError(c.handshake())
	}
	go c.flushOutputBuffer()
	return err
}

// PeerCertificate returns the Certificate of the peer with which you're
// communicating. Only valid after a handshake.
func (c *Conn) PeerCertificate() (*crypto.Certificate, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isShutdown {
		return nil, fmt.Errorf("connection closed: %w", crypto.ErrShutdown)
	}
	x := C.SSL_get_peer_certificate(c.ssl)
	if x == nil {
		return nil, fmt.Errorf("failed to get peer cert: %w", crypto.ErrNoPeerCert)
	}
	cert := crypto.NewCertWrapper(unsafe.Pointer(x))
	runtime.SetFinalizer(cert, func(cert *crypto.Certificate) {
		C.X509_free((*C.X509)(cert.GetCert()))
	})
	return cert, nil
}

// loadCertificateStack loads up a stack of x509 certificates and returns them,
// handling memory ownership.
func (c *Conn) loadCertificateStack(sk *C.struct_stack_st_X509) []*crypto.Certificate {
	skNum := int(C.X_sk_X509_num(sk))
	rv := make([]*crypto.Certificate, 0, skNum)
	for i := 0; i < skNum; i++ {
		x := C.X_sk_X509_value(sk, C.int(i))
		// ref holds on to the underlying connection memory so we don't need to
		// worry about incrementing refcounts manually or freeing the X509
		rv = append(rv, crypto.NewCertWrapper(unsafe.Pointer(x), c))
	}
	return rv
}

// PeerCertificateChain returns the certificate chain of the peer. If called on
// the client side, the stack also contains the peer's certificate; if called
// on the server side, the peer's certificate must be obtained separately using
// PeerCertificate.
func (c *Conn) PeerCertificateChain() ([]*crypto.Certificate, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isShutdown {
		return nil, fmt.Errorf("connection closed: %w", crypto.ErrShutdown)
	}
	sk := C.SSL_get_peer_cert_chain(c.ssl)
	if sk == nil {
		return nil, fmt.Errorf("no peer certificates found: %w", crypto.ErrNoPeerCert)
	}
	return c.loadCertificateStack(sk), nil
}

type ConnectionState struct {
	Certificate           *crypto.Certificate
	CertificateError      error
	CertificateChain      []*crypto.Certificate
	CertificateChainError error
	SessionReused         bool
}

func (c *Conn) ConnectionState() ConnectionState {
	cert, certErr := c.PeerCertificate()
	certChain, certChainErr := c.PeerCertificateChain()
	sessReused := c.SessionReused()

	return ConnectionState{
		Certificate: cert, CertificateError: certErr, CertificateChain: certChain,
		CertificateChainError: certChainErr, SessionReused: sessReused,
	}
}

func (c *Conn) shutdown() func() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rv, errno := C.SSL_shutdown(c.ssl)
	if rv > 0 {
		return nil
	}
	if rv == 0 {
		// The OpenSSL docs say that in this case, the shutdown is not
		// finished, and we should call SSL_shutdown() a second time, if a
		// bidirectional shutdown is going to be performed. Further, the
		// output of SSL_get_error may be misleading, as an erroneous
		// SSL_ERROR_SYSCALL may be flagged even though no error occurred.
		// So, TODO: revisit bidrectional shutdown, possibly trying again.
		// Note: some broken clients won't engage in bidirectional shutdown
		// without tickling them to close by sending a TCP_FIN packet, or
		// shutting down the write-side of the connection.
		return nil
	}

	return c.getErrorHandler(rv, errno)
}

func (c *Conn) shutdownLoop() error {
	err := errTryAgain
	shutdownTries := 0

	for errors.Is(err, errTryAgain) {
		shutdownTries++
		err = c.handleError(c.shutdown())
		if err == nil {
			return c.flushOutputBuffer()
		}

		if errors.Is(err, errTryAgain) && shutdownTries >= 2 {
			return fmt.Errorf("shutdown requested a third time? %w", crypto.ErrShutdown)
		}
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}

	return err
}

// Close shuts down the SSL connection and closes the underlying wrapped
// connection.
func (c *Conn) Close() error {
	c.mtx.Lock()
	if c.isShutdown {
		c.mtx.Unlock()
		return nil
	}
	c.isShutdown = true
	c.mtx.Unlock()
	var errs utils.ErrorGroup
	errs.Add(c.shutdownLoop())
	errs.Add(c.conn.Close())

	err := errs.Finalize()
	if err != nil {
		return fmt.Errorf("shutdown or close error: %w", err)
	}

	return nil
}

func (c *Conn) read(buf []byte) (int, func() error) {
	if len(buf) == 0 {
		return 0, nil
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isShutdown {
		return 0, func() error { return io.EOF }
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rv, errno := C.SSL_read(c.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if rv > 0 {
		return int(rv), nil
	}
	return 0, c.getErrorHandler(rv, errno)
}

// Read reads up to len(buf) bytes into buf. It returns the number of bytes read
// and an error if applicable. io.EOF is returned when the caller can expect
// to see no more data.
func (c *Conn) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	err := errTryAgain

	for errors.Is(err, errTryAgain) {
		n, errcb := c.read(buf)
		err = c.handleError(errcb)
		if err == nil {
			go c.flushOutputBuffer()
			return n, nil
		}

		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
	}
	return 0, err
}

func (c *Conn) write(buf []byte) (int, func() error) {
	if len(buf) == 0 {
		return 0, nil
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isShutdown {
		err := fmt.Errorf("connection closed: %w", crypto.ErrShutdown)
		return 0, func() error { return err }
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rv, errno := C.SSL_write(c.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if rv > 0 {
		return int(rv), nil
	}

	return 0, c.getErrorHandler(rv, errno)
}

// Write will encrypt the contents of b and write it to the underlying stream.
// Performance will be vastly improved if the size of b is a multiple of
// SSLRecordSize.
func (c *Conn) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	err := errTryAgain

	for errors.Is(err, errTryAgain) {
		n, errcb := c.write(data)
		err = c.handleError(errcb)
		if err == nil {
			return n, c.flushOutputBuffer()
		}
	}

	return 0, err
}

// VerifyHostname pulls the PeerCertificate and calls VerifyHostname on the
// certificate.
func (c *Conn) VerifyHostname(host string) error {
	cert, err := c.PeerCertificate()
	if err != nil {
		return err
	}

	err = cert.VerifyHostname(host)
	if err != nil {
		return fmt.Errorf("failed to verify hostname: %w", err)
	}

	return nil
}

// LocalAddr returns the underlying connection's local address
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the underlying connection's remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline calls SetDeadline on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	err := c.conn.SetDeadline(t)
	if err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	return nil
}

// SetReadDeadline calls SetReadDeadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	err := c.conn.SetReadDeadline(t)
	if err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	return nil
}

// SetWriteDeadline calls SetWriteDeadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	err := c.conn.SetWriteDeadline(t)
	if err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	return nil
}

func (c *Conn) UnderlyingConn() net.Conn {
	return c.conn
}

func (c *Conn) SetTLSExtHostName(name string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.X_SSL_set_tlsext_host_name(c.ssl, cname) == 0 {
		return fmt.Errorf("failed to set TLS host name: %w", crypto.PopError())
	}
	return nil
}

func (c *Conn) VerifyResult() VerifyResult {
	return VerifyResult(C.SSL_get_verify_result(c.ssl))
}

func (c *Conn) SessionReused() bool {
	return C.X_SSL_session_reused(c.ssl) == 1
}

func (c *Conn) GetSession() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// get1 increases the refcount of the session, so we have to free it.
	session := C.SSL_get1_session(c.ssl)
	if session == nil {
		return nil, fmt.Errorf("failed to get session: %w", crypto.ErrNoSession)
	}
	defer C.SSL_SESSION_free(session)

	// get the size of the encoding
	slen := C.i2d_SSL_SESSION(session, nil)

	buf := (*C.uchar)(C.malloc(C.size_t(slen)))
	defer C.free(unsafe.Pointer(buf))

	// this modifies the value of buf (seriously), so we have to pass in a temp
	// var so that we can actually read the bytes from buf.
	tmp := buf
	slen2 := C.i2d_SSL_SESSION(session, &tmp)
	if slen != slen2 {
		return nil, fmt.Errorf("session had different lengths: %w", crypto.ErrSessionLength)
	}

	return C.GoBytes(unsafe.Pointer(buf), slen), nil
}

func (c *Conn) setSession(session []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if len(session) == 0 {
		return fmt.Errorf("session is empty: %w", crypto.ErrEmptySession)
	}

	cSession := C.CBytes(session)
	defer C.free(cSession)

	ptr := (*C.uchar)(cSession)
	sess := C.d2i_SSL_SESSION(nil, &ptr, C.long(len(session)))
	if sess == nil {
		return fmt.Errorf("unable to load session: %w", crypto.PopError())
	}
	defer C.SSL_SESSION_free(sess)

	ret := C.SSL_set_session(c.ssl, sess)
	if ret != 1 {
		return fmt.Errorf("unable to set session: %w", crypto.PopError())
	}
	return nil
}

// GetALPNNegotiated returns the negotiated ALPN protocol
func (c *Conn) GetALPNNegotiated() (string, error) {
	var proto *C.uchar
	var protoLen C.uint
	C.SSL_get0_alpn_selected(c.ssl, &proto, &protoLen)
	if protoLen == 0 {
		return "", fmt.Errorf("no ALPN protocol negotiated: %w", crypto.ErrNoALPN)
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(proto)), C.int(protoLen)), nil
}
