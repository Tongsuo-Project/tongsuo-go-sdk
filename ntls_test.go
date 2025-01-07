// Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE
package tongsuogo_test

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ts "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
	TLSSMGCMCipher = "TLS_SM4_GCM_SM3"
	TLSSMCCMCipher = "TLS_SM4_CCM_SM3"
	internalServer = true
	enableSNI      = true

	testCertDir = "test/certs/sm2"
	testCaFile  = "test/certs/sm2/chain-ca.crt"
	testRequest = "hello tongsuo\n"
)

func generateSM2KeyAndSave(t *testing.T, filename string) crypto.PrivateKey {
	t.Helper()

	key, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := key.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	err = crypto.SavePEMToFile(pem, filename)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestCAGenerateSM2AndNTLS(t *testing.T) {
	t.Parallel()
	// Create a temporary directory to store generated keys and certificates
	tmpDir, err := os.MkdirTemp("", "tongsuo-test-*")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	signAndSaveCert := func(cert *crypto.Certificate, caKey crypto.PrivateKey, filename string) {
		err := cert.Sign(caKey, crypto.DigestSM3)
		if err != nil {
			t.Fatal(err)
		}

		certPem, err := cert.MarshalPEM()
		if err != nil {
			t.Fatal(err)
		}

		err = crypto.SavePEMToFile(certPem, filename)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create CA certificate
	caKey, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	caInfo := crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      87600 * time.Hour, // 10 years
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	caExtensions := map[crypto.NID]string{
		crypto.NidBasicConstraints:       "critical,CA:TRUE",
		crypto.NidKeyUsage:               "critical,digitalSignature,keyCertSign,cRLSign",
		crypto.NidSubjectKeyIdentifier:   "hash",
		crypto.NidAuthorityKeyIdentifier: "keyid:always,issuer",
	}

	caCert, err := crypto.NewCertificate(&caInfo, caKey)
	if err != nil {
		t.Fatal(err)
	}

	err = caCert.AddExtensions(caExtensions)
	if err != nil {
		t.Fatal(err)
	}
	// Save CA certificate to tmpDir
	caCertFile := filepath.Join(tmpDir, "chain-ca.crt")
	signAndSaveCert(caCert, caKey, caCertFile)

	// Define additional certificate information
	certInfos := []struct {
		name     string
		keyUsage string
	}{
		{"server_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
		{"server_sign", "nonRepudiation, digitalSignature"},
		{"client_sign", "nonRepudiation, digitalSignature"},
		{"client_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
	}

	// Create additional certificates
	for _, info := range certInfos {
		keyFile := filepath.Join(tmpDir, info.name+".key")
		key := generateSM2KeyAndSave(t, keyFile)
		certInfo := crypto.CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[crypto.NID]string{
			crypto.NidBasicConstraints: "critical,CA:FALSE",
			crypto.NidKeyUsage:         info.keyUsage,
		}

		cert, err := crypto.NewCertificate(&certInfo, key)
		if err != nil {
			t.Fatal(err)
		}

		err = cert.AddExtensions(extensions)
		if err != nil {
			t.Fatal(err)
		}

		err = cert.SetIssuer(caCert)
		if err != nil {
			t.Fatal(err)
		}

		certFile := filepath.Join(tmpDir, info.name+".crt")
		signAndSaveCert(cert, caKey, certFile)
	}

	t.Run("NTLS Test", func(t *testing.T) {
		t.Parallel()
		testNTLS(t, tmpDir)
	})
}

func testNTLS(t *testing.T, tmpDir string) {
	t.Helper()
	// Use the generated keys and certificates from tmpDir to test NTLS
	cases := []struct {
		cipher       string
		signCertFile string
		signKeyFile  string
		encCertFile  string
		encKeyFile   string
		caFile       string
		runServer    bool
	}{
		{
			cipher:       ECCSM2Cipher,
			signCertFile: "",
			signKeyFile:  "",
			encCertFile:  "",
			encKeyFile:   "",
			caFile:       filepath.Join(tmpDir, "chain-ca.crt"),
			runServer:    internalServer,
		},
		{
			cipher:       ECDHESM2Cipher,
			signCertFile: filepath.Join(tmpDir, "client_sign.crt"),
			signKeyFile:  filepath.Join(tmpDir, "client_sign.key"),
			encCertFile:  filepath.Join(tmpDir, "client_enc.crt"),
			encKeyFile:   filepath.Join(tmpDir, "client_enc.key"),
			caFile:       filepath.Join(tmpDir, "chain-ca.crt"),
			runServer:    internalServer,
		},
	}

	for _, item := range cases {
		t.Run(item.cipher, func(t *testing.T) {
			server, err := newNTLSServer(t, tmpDir, func(sslctx *ts.Ctx) error {
				return sslctx.SetCipherList(item.cipher)
			})
			if err != nil {
				t.Error(err)

				return
			}

			defer server.Close()
			go server.Run()

			ctx, err := ts.NewCtxWithVersion(ts.NTLS)
			if err != nil {
				t.Error(err)

				return
			}

			if err := ctx.SetCipherList(item.cipher); err != nil {
				t.Error(err)

				return
			}

			err = ctxSetGMDoubleCertKey(ctx, item.signCertFile, item.signKeyFile, item.encCertFile, item.encKeyFile)
			if err != nil {
				t.Error(err)
				return
			}

			if item.caFile != "" {
				if err := ctx.LoadVerifyLocations(item.caFile, ""); err != nil {
					t.Error(err)
					return
				}
			}

			conn, err := ts.DialSession(server.Addr().Network(), server.Addr().String(), ctx,
				ts.InsecureSkipHostVerification, nil, "")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()

			cipher, err := conn.CurrentCipher()
			if err != nil {
				t.Error(err)
				return
			}

			t.Log("current cipher", cipher)

			if _, err := conn.Write([]byte(testRequest)); err != nil {
				t.Error(err)
				return
			}

			resp, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			if resp != testRequest {
				t.Error("response data is not expected: ", resp)
				return
			}
		})
	}
}

func TestNTLS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cipher       string
		signCertFile string
		signKeyFile  string
		encCertFile  string
		encKeyFile   string
		caFile       string
	}{
		{
			cipher:       ECCSM2Cipher,
			signCertFile: "",
			signKeyFile:  "",
			encCertFile:  "",
			encKeyFile:   "",
			caFile:       filepath.Join(testCertDir, "chain-ca.crt"),
		},
		{
			cipher:       ECDHESM2Cipher,
			signCertFile: filepath.Join(testCertDir, "client_sign.crt"),
			signKeyFile:  filepath.Join(testCertDir, "client_sign.key"),
			encCertFile:  filepath.Join(testCertDir, "client_enc.crt"),
			encKeyFile:   filepath.Join(testCertDir, "client_enc.key"),
			caFile:       filepath.Join(testCertDir, "chain-ca.crt"),
		},
	}

	for _, item := range cases {
		item := item
		t.Run(item.cipher, func(t *testing.T) {
			t.Parallel()

			server, err := newNTLSServer(t, testCertDir, func(sslctx *ts.Ctx) error {
				return sslctx.SetCipherList(item.cipher)
			})
			if err != nil {
				t.Error(err)
				return
			}

			defer server.Close()

			go server.Run()

			ctx, err := ts.NewCtxWithVersion(ts.NTLS)
			if err != nil {
				t.Error(err)
				return
			}

			if err := ctx.SetCipherList(item.cipher); err != nil {
				t.Error(err)
				return
			}

			err = ctxSetGMDoubleCertKey(ctx, item.signCertFile, item.signKeyFile, item.encCertFile, item.encKeyFile)
			if err != nil {
				t.Error(err)
				return
			}

			if item.caFile != "" {
				if err := ctx.LoadVerifyLocations(item.caFile, ""); err != nil {
					t.Error(err)
					return
				}
			}

			conn, err := ts.DialSession(server.Addr().Network(), server.Addr().String(), ctx,
				ts.InsecureSkipHostVerification, nil, "")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()

			cipher, err := conn.CurrentCipher()
			if err != nil {
				t.Error(err)
				return
			}

			t.Log("current cipher", cipher)

			if _, err := conn.Write([]byte(testRequest)); err != nil {
				t.Error(err)
				return
			}

			resp, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			if resp != testRequest {
				t.Error("response data is not expected: ", resp)
				return
			}
		})
	}
}

func newNTLSServer(t *testing.T, testDir string, options ...func(sslctx *ts.Ctx) error) (*echoServer, error) {
	t.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	for _, f := range options {
		if err := f(ctx); err != nil {
			t.Error(err)
			return nil, err
		}
	}

	if err := ctx.LoadVerifyLocations(filepath.Join(testDir, "chain-ca.crt"), ""); err != nil {
		t.Error(err)
		return nil, err
	}

	err = ctxSetGMDoubleCertKey(ctx, filepath.Join(testDir, "server_sign.crt"),
		filepath.Join(testDir, "server_sign.key"), filepath.Join(testDir, "server_enc.crt"),
		filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := ts.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

type echoServer struct {
	net.Listener
}

func (s *echoServer) Close() error {
	err := s.Listener.Close()
	if err != nil {
		return fmt.Errorf("failed to close listener: %w", err)
	}

	return nil
}

func (s *echoServer) Run() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %w", err)
		}

		go handleConn(conn)
	}
}

func (s *echoServer) RunForALPN() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %w", err)
		}

		go handleConnForALPN(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %s", err)
		return
	}

	// Send a response back to the client
	if _, err = conn.Write([]byte(req + "\n")); err != nil {
		log.Printf("Unable to send response: %s", err)
		return
	}
}

func handleConnForALPN(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %s", err)
		return
	}

	// Send a response back to the client
	if _, err = conn.Write([]byte(req + "\n")); err != nil {
		log.Printf("Unable to send response: %s", err)
		return
	}

	ntls, ok := conn.(*ts.Conn)
	if !ok {
		log.Printf("Connection is not an NTLS connection")
		return
	}

	protocol, err := ntls.GetALPNNegotiated()
	if err != nil {
		log.Printf("Error getting negotiated protocol: %s", err)
		return
	}

	log.Printf("Negotiated protocol: %s\n", protocol)
}

func TestSNI(t *testing.T) {
	t.Parallel()
	// Run server
	certFiles, err := ReadCertificateFiles("test/sni_certs")
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := newNTLSServerWithSNI(t, testCertDir, certFiles, enableSNI, func(sslctx *ts.Ctx) error {
		return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
	})
	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.Run()

	// Run Client
	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.SetCipherList("ECC-SM2-SM4-CBC-SM3"); err != nil {
		t.Error(err)
		return
	}

	if err := ctx.LoadVerifyLocations(testCaFile, ""); err != nil {
		t.Error(err)
		return
	}

	// Add SNI
	serverName := "default"

	// Connect to the server
	conn, err := ts.DialSession(server.Addr().Network(), server.Addr().String(), ctx,
		ts.InsecureSkipHostVerification, nil, serverName)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	cipher, err := conn.CurrentCipher()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("current cipher", cipher)

	if _, err := conn.Write([]byte(testRequest)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != testRequest {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func ctxSetGMDoubleCertKey(ctx *ts.Ctx, signCertFile, signKeyFile, encCertFile, encKeyFile string) error {
	if signCertFile != "" {
		signCertPEM, err := os.ReadFile(signCertFile)
		if err != nil {
			return fmt.Errorf("failed to read sign cert file: %w", err)
		}

		signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
		if err != nil {
			return fmt.Errorf("failed to load sign cert: %w", err)
		}

		if err := ctx.UseSignCertificate(signCert); err != nil {
			return fmt.Errorf("failed to set sign cert: %w", err)
		}
	}

	if signKeyFile != "" {
		signKeyPEM, err := os.ReadFile(signKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read sign key file: %w", err)
		}

		signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to load sign key: %w", err)
		}

		if err := ctx.UseSignPrivateKey(signKey); err != nil {
			return fmt.Errorf("failed to set sign key: %w", err)
		}
	}

	if encCertFile != "" {
		encCertPEM, err := os.ReadFile(encCertFile)
		if err != nil {
			return fmt.Errorf("failed to read enc cert file: %w", err)
		}

		encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
		if err != nil {
			return fmt.Errorf("failed to load enc cert: %w", err)
		}

		if err := ctx.UseEncryptCertificate(encCert); err != nil {
			return fmt.Errorf("failed to set enc cert: %w", err)
		}
	}

	if encKeyFile != "" {
		encKeyPEM, err := os.ReadFile(encKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read enc key file: %w", err)
		}

		encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to load enc key: %w", err)
		}

		if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
			return fmt.Errorf("failed to set enc key: %w", err)
		}
	}

	return nil
}

func newNTLSServerWithSNI(t *testing.T, testDir string, certKeyPairs map[string]crypto.GMDoubleCertKey, sni bool,
	options ...func(sslctx *ts.Ctx) error,
) (*echoServer, error) {
	t.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	for _, f := range options {
		if err := f(ctx); err != nil {
			t.Error(err)
			return nil, err
		}
	}

	if err := ctx.LoadVerifyLocations(filepath.Join(testDir, "chain-ca.crt"), ""); err != nil {
		t.Error(err)
		return nil, err
	}

	// Set SNI callback
	if sni == true {
		ctx.SetTLSExtServernameCallback(func(ssl *ts.SSL) ts.SSLTLSExtErr {
			serverName := ssl.GetServername()
			log.Printf("SNI: Client requested hostname: %s\n", serverName)

			if certKeyPair, ok := certKeyPairs[serverName]; ok {
				if err := loadCertAndKeyForSSL(ssl, certKeyPair); err != nil {
					log.Printf("Error loading certificate for %s: %v\n", serverName, err)
					return ts.SSLTLSExtErrAlertFatal
				}
			} else {
				log.Printf("No certificate found for %s, using default\n", serverName)
				return ts.SSLTLSExtErrNoAck
			}

			return ts.SSLTLSExtErrOK
		})
	}

	err = ctxSetGMDoubleCertKey(ctx, filepath.Join(testDir, "server_sign.crt"),
		filepath.Join(testDir, "server_sign.key"), filepath.Join(testDir, "server_enc.crt"),
		filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := ts.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

// Load certificate and key for SSL.
func loadCertAndKeyForSSL(ssl *ts.SSL, certKeyPair crypto.GMDoubleCertKey) error {
	ctx, err := ts.NewCtx()
	if err != nil {
		return fmt.Errorf("failed to create ctx: %w", err)
	}

	encCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.EncCertFile)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load certificate from file: %w", err)
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load enc cert: %w", err)
	}

	err = ctx.UseEncryptCertificate(encCert)
	if err != nil {
		return fmt.Errorf("failed to set enc cert: %w", err)
	}

	signCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.SignCertFile)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load sign cert from file: %w", err)
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load sign cert: %w", err)
	}

	err = ctx.UseSignCertificate(signCert)
	if err != nil {
		return fmt.Errorf("failed to set sign cert: %w", err)
	}

	encKeyPEM, err := os.ReadFile(certKeyPair.EncKeyFile)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to read enc key file: %w", err)
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load enc key: %w", err)
	}

	err = ctx.UseEncryptPrivateKey(encKey)
	if err != nil {
		return fmt.Errorf("failed to set enc key: %w", err)
	}

	signKeyPEM, err := os.ReadFile(certKeyPair.SignKeyFile)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to read sign key file: %w", err)
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("failed to load sign key: %w", err)
	}

	err = ctx.UseSignPrivateKey(signKey)
	if err != nil {
		return fmt.Errorf("failed to set sign key: %w", err)
	}

	ssl.SetSSLCtx(ctx)

	return nil
}

func ReadCertificateFiles(dirPath string) (map[string]crypto.GMDoubleCertKey, error) {
	certFiles := make(map[string]crypto.GMDoubleCertKey)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			domain := file.Name()
			encCertFile := filepath.Join(dirPath, domain, "server_enc.crt")
			encKeyFile := filepath.Join(dirPath, domain, "server_enc.key")
			signCertFile := filepath.Join(dirPath, domain, "server_sign.crt")
			signKeyFile := filepath.Join(dirPath, domain, "server_sign.key")

			certFiles[domain] = crypto.GMDoubleCertKey{
				EncCertFile:  encCertFile,
				SignCertFile: signCertFile,
				EncKeyFile:   encKeyFile,
				SignKeyFile:  signKeyFile,
			}
		}
	}

	return certFiles, nil
}

func TestALPN(t *testing.T) {
	t.Parallel()
	// Run server
	server, err := newNTLSServerWithALPN(t, testCertDir, func(sslctx *ts.Ctx) error {
		return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
	})
	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.RunForALPN()

	// Run Client
	alpnProtocols := []string{"h3"}

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.SetCipherList("ECC-SM2-SM4-CBC-SM3"); err != nil {
		t.Error(err)
		return
	}

	// Set the ALPN protocols for the context
	if err := ctx.SetClientALPNProtos(alpnProtocols); err != nil {
		t.Error(err)
		return
	}

	if err := ctx.LoadVerifyLocations(testCaFile, ""); err != nil {
		t.Error(err)
		return
	}

	// Connect to the server
	conn, err := ts.DialSession(server.Addr().Network(), server.Addr().String(), ctx,
		ts.InsecureSkipHostVerification, nil, "")
	if err != nil {
		t.Log(err)
		return
	}
	defer conn.Close()

	// Attempt to retrieve the negotiated ALPN (Application-Layer Protocol Negotiation) protocol
	negotiatedProto, err := conn.GetALPNNegotiated()
	if err != nil {
		// If there is an error, log it and terminate the test
		t.Log("Failed to get negotiated ALPN protocol:", err)
		return
	}

	t.Log("ALPN negotiated successfully", negotiatedProto)

	cipher, err := conn.CurrentCipher()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("current cipher", cipher)

	if _, err := conn.Write([]byte(testRequest)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != testRequest {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func newNTLSServerWithALPN(t *testing.T, testDir string, options ...func(sslctx *ts.Ctx) error) (*echoServer, error) {
	t.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	for _, f := range options {
		if err := f(ctx); err != nil {
			t.Error(err)
			return nil, err
		}
	}

	if err := ctx.LoadVerifyLocations(filepath.Join(testDir, "chain-ca.crt"), ""); err != nil {
		t.Error(err)
		return nil, err
	}

	// Set ALPN
	supportedProtos := []string{"h2", "http/1.1"}
	ctx.SetServerALPNProtos(supportedProtos)

	err = ctxSetGMDoubleCertKey(ctx, filepath.Join(testDir, "server_sign.crt"),
		filepath.Join(testDir, "server_sign.key"), filepath.Join(testDir, "server_enc.crt"),
		filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := ts.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

// TestSessionReuse Test session reuse.
func TestSessionReuse(t *testing.T) {
	t.Parallel()
	// Run server
	// Execute for loop to test various CacheModes
	for _, cacheMode := range []ts.SessionCacheModes{
		ts.SessionCacheOff,
		ts.SessionCacheClient,
		ts.SessionCacheServer,
		ts.SessionCacheBoth,
	} {
		cacheMode := cacheMode
		t.Run(fmt.Sprintf("cacheMode: %d", cacheMode), func(t *testing.T) {
			t.Parallel()

			server, err := newNTLSServerWithSessionReuse(t, testCertDir, cacheMode, func(sslctx *ts.Ctx) error {
				return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
			})
			if err != nil {
				t.Error(err)
				return
			}

			defer server.Close()
			go server.Run()

			// Run client
			ctx, err := ts.NewCtxWithVersion(ts.NTLS)
			if err != nil {
				t.Error(err)
				return
			}

			ctx.SetOptions(ts.NoTicket)

			if err := ctx.SetCipherList("ECC-SM2-SM4-CBC-SM3"); err != nil {
				t.Error(err)
				return
			}

			if err := ctx.LoadVerifyLocations(testCaFile, ""); err != nil {
				t.Error(err)
				return
			}

			// Connect to the server, and get reused session, use session to connect again
			// Use a for loop to connect 2 times
			sessions := make([][]byte, 2)

			var session []byte
			for i := 0; i < 2; i++ {
				conn, err := ts.DialSession(server.Addr().Network(), server.Addr().String(), ctx,
					ts.InsecureSkipHostVerification, session, "")
				if err != nil {
					t.Log(err)
					return
				}

				// get reused session
				sessions[i], err = conn.GetSession()
				if err != nil {
					t.Error(err)
					return
				}

				session = sessions[i]

				if _, err := conn.Write([]byte(testRequest)); err != nil {
					t.Error(err)
					return
				}

				resp, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					t.Error(err)
					return
				}

				if resp != testRequest {
					t.Error("response data is not expected: ", resp)
					return
				}

				conn.Close()
			}

			switch cacheMode {
			case ts.SessionCacheOff, ts.SessionCacheClient:
				if !bytes.Equal(sessions[0], sessions[1]) {
					t.Log("session is not reused")
				} else {
					t.Error("session is reused")
				}
			case ts.SessionCacheServer, ts.SessionCacheBoth:
				if !bytes.Equal(sessions[0], sessions[1]) {
					t.Error("session is not reused")
				} else {
					t.Log("session is reused")
				}
			default:
				t.Error("unexpected cache mode")
			}
		})
	}
}

func newNTLSServerWithSessionReuse(t *testing.T, testDir string, cacheMode ts.SessionCacheModes,
	options ...func(sslctx *ts.Ctx) error,
) (*echoServer, error) {
	t.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	for _, f := range options {
		if err := f(ctx); err != nil {
			t.Error(err)
			return nil, err
		}
	}

	if err := ctx.LoadVerifyLocations(filepath.Join(testDir, "chain-ca.crt"), ""); err != nil {
		t.Error(err)
		return nil, err
	}

	err = ctxSetGMDoubleCertKey(ctx, filepath.Join(testDir, "server_sign.crt"),
		filepath.Join(testDir, "server_sign.key"), filepath.Join(testDir, "server_enc.crt"),
		filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	// Set session reuse
	sessionCacheMode := ctx.SetSessionCacheMode(cacheMode)
	t.Log("session cache mode", sessionCacheMode, "new mode", cacheMode)

	lis, err := ts.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

func TestTLS13Connection(t *testing.T) {
	t.Parallel()

	// Run server
	server, err := newTLS13Server(t, "test/certs")
	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.Run()

	// Run client
	ctx, err := ts.NewCtxWithVersion(ts.TLSv1_3)
	if err != nil {
		t.Error(err)
		return
	}

	conn, err := ts.Dial(server.Addr().Network(), server.Addr().String(), ctx, ts.InsecureSkipHostVerification, "")
	if err != nil {
		t.Log(err)
		return
	}

	defer conn.Close()

	// Check the tls version
	tlsVersion, err := conn.GetVersion()
	if err != nil {
		t.Error(err)
		return
	}

	if tlsVersion != "TLSv1.3" {
		t.Error("tls version is not TLSv1.3")
		return
	}

	t.Log("tls version", tlsVersion)

	if _, err := conn.Write([]byte(testRequest)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != testRequest {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func newTLS13Server(t *testing.T, testDir string, options ...func(sslctx *ts.Ctx) error) (*echoServer, error) {
	t.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.TLSv1_3)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	for _, f := range options {
		if err := f(ctx); err != nil {
			t.Error(err)
			return nil, err
		}
	}

	certPEM, err := os.ReadFile(filepath.Join(testDir, "sm2-cert.pem"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	cert, err := crypto.LoadCertificateFromPEM(certPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseCertificate(cert); err != nil {
		t.Error(err)
		return nil, err
	}

	keyPEM, err := os.ReadFile(filepath.Join(testDir, "sm2.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	key, err := crypto.LoadPrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UsePrivateKey(key); err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := ts.Listen("tcp", "localhost:0", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

func TestTLSv13SMCipher(t *testing.T) {
	t.Parallel()

	ciphers := []string{
		TLSSMGCMCipher,
		TLSSMCCMCipher,
	}
	testCertDir := "test/certs"

	for _, cipher := range ciphers {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()
			// Run server
			server, err := newTLS13Server(t, testCertDir, func(sslctx *ts.Ctx) error {
				return sslctx.SetCipherSuites(cipher)
			})
			if err != nil {
				t.Error(err)
				return
			}

			defer server.Close()
			go server.Run()

			// Run client
			ctx, err := ts.NewCtxWithVersion(ts.TLSv1_3)
			if err != nil {
				t.Error(err)
				return
			}

			if err := ctx.SetCipherSuites(cipher); err != nil {
				t.Error(err)
				return
			}

			conn, err := ts.Dial(server.Addr().Network(), server.Addr().String(), ctx,
				ts.InsecureSkipHostVerification, "")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()

			cipher, err = conn.CurrentCipher()
			if err != nil {
				t.Error(err)
				return
			}

			t.Log("current cipher", cipher)

			if _, err := conn.Write([]byte(testRequest)); err != nil {
				t.Error(err)
				return
			}

			resp, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			if resp != testRequest {
				t.Error("response data is not expected: ", resp)
				return
			}
		})
	}
}
