package tongsuogo

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

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
	TLSSMGCMCipher = "TLS_SM4_GCM_SM3"
	internalServer = true
	enableSNI      = true

	testCertDir = "test/certs/sm2"
)

func TestCAGenerateSM2AndNTLS(t *testing.T) {
	// Create a temporary directory to store generated keys and certificates
	tmpDir, err := os.MkdirTemp("", "tongsuo-test-*")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Helper function: generate and save key
	generateAndSaveKey := func(filename string) crypto.PrivateKey {
		key, err := crypto.GenerateECKey(crypto.Sm2Curve)
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

	// Helper function: sign and save certificate
	signAndSaveCert := func(cert *crypto.Certificate, caKey crypto.PrivateKey, filename string) {
		err := cert.Sign(caKey, crypto.EVP_SM3)
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
	caKey, err := crypto.GenerateECKey(crypto.Sm2Curve)
	if err != nil {
		t.Fatal(err)
	}
	caInfo := crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Expires:      87600 * time.Hour, // 10 years
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	caExtensions := map[crypto.NID]string{
		crypto.NID_basic_constraints:        "critical,CA:TRUE",
		crypto.NID_key_usage:                "critical,digitalSignature,keyCertSign,cRLSign",
		crypto.NID_subject_key_identifier:   "hash",
		crypto.NID_authority_key_identifier: "keyid:always,issuer",
	}
	ca, err := crypto.NewCertificate(&caInfo, caKey)
	if err != nil {
		t.Fatal(err)
	}
	err = ca.AddExtensions(caExtensions)
	if err != nil {
		t.Fatal(err)
	}
	// Save CA certificate to tmpDir
	caCertFile := filepath.Join(tmpDir, "chain-ca.crt")
	signAndSaveCert(ca, caKey, caCertFile)

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
		keyFile := filepath.Join(tmpDir, fmt.Sprintf("%s.key", info.name))
		key := generateAndSaveKey(keyFile)
		certInfo := crypto.CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[crypto.NID]string{
			crypto.NID_basic_constraints: "critical,CA:FALSE",
			crypto.NID_key_usage:         info.keyUsage,
		}
		cert, err := crypto.NewCertificate(&certInfo, key)
		if err != nil {
			t.Fatal(err)
		}
		err = cert.AddExtensions(extensions)
		if err != nil {
			t.Fatal(err)
		}
		err = cert.SetIssuer(ca)
		if err != nil {
			t.Fatal(err)
		}
		certFile := filepath.Join(tmpDir, fmt.Sprintf("%s.crt", info.name))
		signAndSaveCert(cert, caKey, certFile)
	}

	t.Run("NTLS Test", func(t *testing.T) {
		testNTLS(t, tmpDir)
	})
}

func testNTLS(t *testing.T, tmpDir string) {
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
			cipher:    ECCSM2Cipher,
			runServer: internalServer,
			caFile:    filepath.Join(tmpDir, "chain-ca.crt"),
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

	for _, c := range cases {
		t.Run(c.cipher, func(t *testing.T) {
			if c.runServer {
				server, err := newNTLSServer(t, tmpDir, func(sslctx *Ctx) error {
					return sslctx.SetCipherList(c.cipher)
				})

				if err != nil {
					t.Error(err)
					return
				}
				defer server.Close()
				go server.Run()
			}

			ctx, err := NewCtxWithVersion(NTLS)
			if err != nil {
				t.Error(err)
				return
			}

			if err := ctx.SetCipherList(c.cipher); err != nil {
				t.Error(err)
				return
			}

			if c.signCertFile != "" {
				signCertPEM, err := os.ReadFile(c.signCertFile)
				if err != nil {
					t.Error(err)
					return
				}
				signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseSignCertificate(signCert); err != nil {
					t.Error(err)
					return
				}
			}

			if c.signKeyFile != "" {
				signKeyPEM, err := os.ReadFile(c.signKeyFile)
				if err != nil {
					t.Error(err)
					return
				}
				signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseSignPrivateKey(signKey); err != nil {
					t.Error(err)
					return
				}
			}

			if c.encCertFile != "" {
				encCertPEM, err := os.ReadFile(c.encCertFile)
				if err != nil {
					t.Error(err)
					return
				}
				encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseEncryptCertificate(encCert); err != nil {
					t.Error(err)
					return
				}
			}

			if c.encKeyFile != "" {
				encKeyPEM, err := os.ReadFile(c.encKeyFile)
				if err != nil {
					t.Error(err)
					return
				}

				encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
					t.Error(err)
					return
				}
			}

			if c.caFile != "" {
				if err := ctx.LoadVerifyLocations(c.caFile, ""); err != nil {
					t.Error(err)
					return
				}
			}

			conn, err := DialSession("tcp", "127.0.0.1:4433", ctx, InsecureSkipHostVerification, nil, "")
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

			request := "hello tongsuo\n"
			if _, err := conn.Write([]byte(request)); err != nil {
				t.Error(err)
				return
			}

			resp, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			if resp != request {
				t.Error("response data is not expected: ", resp)
				return
			}
		})
	}
}

func TestNTLS(t *testing.T) {
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
			cipher:    ECCSM2Cipher,
			runServer: internalServer,
			caFile:    filepath.Join(testCertDir, "chain-ca.crt"),
		},
		{
			cipher:       ECDHESM2Cipher,
			signCertFile: filepath.Join(testCertDir, "client_sign.crt"),
			signKeyFile:  filepath.Join(testCertDir, "client_sign.key"),
			encCertFile:  filepath.Join(testCertDir, "client_enc.crt"),
			encKeyFile:   filepath.Join(testCertDir, "client_enc.key"),
			caFile:       filepath.Join(testCertDir, "chain-ca.crt"),
			runServer:    internalServer,
		},
	}

	for _, c := range cases {
		t.Run(c.cipher, func(t *testing.T) {
			if c.runServer {
				server, err := newNTLSServer(t, testCertDir, func(sslctx *Ctx) error {
					return sslctx.SetCipherList(c.cipher)
				})

				if err != nil {
					t.Error(err)
					return
				}
				defer server.Close()
				go server.Run()
			}

			ctx, err := NewCtxWithVersion(NTLS)
			if err != nil {
				t.Error(err)
				return
			}

			if err := ctx.SetCipherList(c.cipher); err != nil {
				t.Error(err)
				return
			}

			if c.signCertFile != "" {
				signCertPEM, err := os.ReadFile(c.signCertFile)
				if err != nil {
					t.Error(err)
					return
				}
				signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseSignCertificate(signCert); err != nil {
					t.Error(err)
					return
				}
			}

			if c.signKeyFile != "" {
				signKeyPEM, err := os.ReadFile(c.signKeyFile)
				if err != nil {
					t.Error(err)
					return
				}
				signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseSignPrivateKey(signKey); err != nil {
					t.Error(err)
					return
				}
			}

			if c.encCertFile != "" {
				encCertPEM, err := os.ReadFile(c.encCertFile)
				if err != nil {
					t.Error(err)
					return
				}
				encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseEncryptCertificate(encCert); err != nil {
					t.Error(err)
					return
				}
			}

			if c.encKeyFile != "" {
				encKeyPEM, err := os.ReadFile(c.encKeyFile)
				if err != nil {
					t.Error(err)
					return
				}

				encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
				if err != nil {
					t.Error(err)
					return
				}

				if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
					t.Error(err)
					return
				}
			}

			if c.caFile != "" {
				if err := ctx.LoadVerifyLocations(c.caFile, ""); err != nil {
					t.Error(err)
					return
				}
			}

			conn, err := DialSession("tcp", "127.0.0.1:4433", ctx, InsecureSkipHostVerification, nil, "")
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

			request := "hello tongsuo\n"
			if _, err := conn.Write([]byte(request)); err != nil {
				t.Error(err)
				return
			}

			resp, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			if resp != request {
				t.Error("response data is not expected: ", resp)
				return
			}
		})
	}
}

func newNTLSServer(t *testing.T, testDir string, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(NTLS)
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

	encCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptCertificate(encCert); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignCertificate(signCert); err != nil {
		t.Error(err)
		return nil, err
	}

	encKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignPrivateKey(signKey); err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
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
	return s.Listener.Close()
}

func (s *echoServer) Run() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn)
	}
}

func (s *echoServer) RunForALPN() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go handleConnForALPN(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %v", err)
		return
	}

	// Send a response back to the client
	if _, err = conn.Write([]byte(req + "\n")); err != nil {
		log.Printf("Unable to send response: %v", err)
		return
	}
}

func handleConnForALPN(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %v", err)
		return
	}

	// Send a response back to the client
	if _, err = conn.Write([]byte(req + "\n")); err != nil {
		log.Printf("Unable to send response: %v", err)
		return
	}

	ntls := conn.(*Conn)
	protocol, err := ntls.GetALPNNegotiated()
	if err != nil {
		log.Printf("Error getting negotiated protocol: %v", err)
		return
	}

	log.Printf("Negotiated protocol: %s\n", protocol)
}

func TestSNI(t *testing.T) {
	// Run server
	certFiles, err := ReadCertificateFiles("test/sni_certs")
	if err != nil {
		t.Fatal(err)
		return
	}

	server, err := newNTLSServerWithSNI(t, testCertDir, certFiles, enableSNI, func(sslctx *Ctx) error {
		return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
	})

	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.Run()

	// Run Client
	caFile := "test/certs/sm2/chain-ca.crt"
	connAddr := "127.0.0.1:4433"

	ctx, err := NewCtxWithVersion(NTLS)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.SetCipherList("ECC-SM2-SM4-CBC-SM3"); err != nil {
		t.Error(err)
		return
	}

	if err := ctx.LoadVerifyLocations(caFile, ""); err != nil {
		t.Error(err)
		return
	}

	// Add SNI
	serverName := "default"

	// Connect to the server
	conn, err := DialSession("tcp", connAddr, ctx, InsecureSkipHostVerification, nil, serverName)
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

	request := "hello tongsuo\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != request {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func newNTLSServerWithSNI(t *testing.T, testDir string, certKeyPairs map[string]crypto.GMDoubleCertKey, sni bool, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(NTLS)
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
		ctx.SetTLSExtServernameCallback(func(ssl *SSL) SSLTLSExtErr {
			serverName := ssl.GetServername()
			log.Printf("SNI: Client requested hostname: %s\n", serverName)

			if certKeyPair, ok := certKeyPairs[serverName]; ok {
				if err := loadCertAndKeyForSSL(ssl, certKeyPair); err != nil {
					log.Printf("Error loading certificate for %s: %v\n", serverName, err)
					return SSLTLSExtErrAlertFatal
				}
			} else {
				log.Printf("No certificate found for %s, using default\n", serverName)
				return SSLTLSExtErrNoAck
			}

			return SSLTLSExtErrOK
		})
	}

	// Load a default certificate and key
	encCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptCertificate(encCert); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignCertificate(signCert); err != nil {
		t.Error(err)
		return nil, err
	}

	encKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignPrivateKey(signKey); err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

// Load certificate and key for SSL
func loadCertAndKeyForSSL(ssl *SSL, certKeyPair crypto.GMDoubleCertKey) error {
	ctx, err := NewCtx()
	if err != nil {
		return err
	}

	encCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.EncCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptCertificate(encCert)
	if err != nil {
		return err
	}

	signCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.SignCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignCertificate(signCert)
	if err != nil {
		return err
	}

	encKeyPEM, err := os.ReadFile(certKeyPair.EncKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptPrivateKey(encKey)
	if err != nil {
		return err
	}

	signKeyPEM, err := os.ReadFile(certKeyPair.SignKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignPrivateKey(signKey)
	if err != nil {
		return err
	}

	ssl.SetSSLCtx(ctx)

	return nil
}

func ReadCertificateFiles(dirPath string) (map[string]crypto.GMDoubleCertKey, error) {
	certFiles := make(map[string]crypto.GMDoubleCertKey)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
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
	// Run server
	server, err := newNTLSServerWithALPN(t, testCertDir, func(sslctx *Ctx) error {
		return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
	})

	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.RunForALPN()

	// Run Client

	caFile := "test/certs/sm2/chain-ca.crt"
	connAddr := "127.0.0.1:4433"
	alpnProtocols := []string{"h3"}

	ctx, err := NewCtxWithVersion(NTLS)
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

	if err := ctx.LoadVerifyLocations(caFile, ""); err != nil {
		t.Error(err)
		return
	}

	// Connect to the server
	conn, err := DialSession("tcp", connAddr, ctx, InsecureSkipHostVerification, nil, "")
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
	} else {
		t.Log("ALPN negotiated successfully", negotiatedProto)
	}

	cipher, err := conn.CurrentCipher()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("current cipher", cipher)

	request := "hello tongsuo\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != request {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func newNTLSServerWithALPN(t *testing.T, testDir string, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(NTLS)
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

	encCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptCertificate(encCert); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignCertificate(signCert); err != nil {
		t.Error(err)
		return nil, err
	}

	encKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignPrivateKey(signKey); err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

// TestSessionReuse Test session reuse
func TestSessionReuse(t *testing.T) {
	// Run server
	// Execute for loop to test various CacheModes
	for _, cacheMode := range []SessionCacheModes{
		SessionCacheOff,
		SessionCacheClient,
		SessionCacheServer,
		SessionCacheBoth,
	} {
		t.Run(fmt.Sprintf("cacheMode: %d", cacheMode), func(t *testing.T) {
			server, err := newNTLSServerWithSessionReuse(t, testCertDir, cacheMode, func(sslctx *Ctx) error {
				return sslctx.SetCipherList("ECC-SM2-SM4-CBC-SM3")
			})
			if err != nil {
				t.Error(err)
				return
			}

			defer server.Close()
			go server.Run()

			// Run client
			caFile := "test/certs/sm2/chain-ca.crt"
			connAddr := "127.0.0.1:4433"

			ctx, err := NewCtxWithVersion(NTLS)
			if err != nil {
				t.Error(err)
				return
			}

			ctx.SetOptions(NoTicket)
			if err := ctx.SetCipherList("ECC-SM2-SM4-CBC-SM3"); err != nil {
				t.Error(err)
				return
			}

			if err := ctx.LoadVerifyLocations(caFile, ""); err != nil {
				t.Error(err)
				return
			}

			// Connect to the server, and get reused session, use session to connect again
			// Use a for loop to connect 2 times
			var sessions = make([][]byte, 2)
			var session []byte
			for i := 0; i < 2; i++ {
				conn, err := DialSession("tcp", connAddr, ctx, InsecureSkipHostVerification, session, "")
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

				request := "hello tongsuo\n"
				if _, err := conn.Write([]byte(request)); err != nil {
					t.Error(err)
					return
				}

				resp, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					t.Error(err)
					return
				}

				if resp != request {
					t.Error("response data is not expected: ", resp)
					return
				}

				conn.Close()
			}

			switch cacheMode {
			case SessionCacheOff, SessionCacheClient:
				if !bytes.Equal(sessions[0], sessions[1]) {
					t.Log("session is not reused")
				} else {
					t.Error("session is reused")
				}
			case SessionCacheServer, SessionCacheBoth:
				if !bytes.Equal(sessions[0], sessions[1]) {
					t.Error("session is not reused")
				} else {
					t.Log("session is reused")
				}
			}
		})
	}
}

func newNTLSServerWithSessionReuse(t *testing.T, testDir string, cacheMode SessionCacheModes, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(NTLS)
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

	encCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptCertificate(encCert); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignCertificate(signCert); err != nil {
		t.Error(err)
		return nil, err
	}

	encKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_sign.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseSignPrivateKey(signKey); err != nil {
		t.Error(err)
		return nil, err
	}

	// Set session reuse
	sessionCacheMode := ctx.SetSessionCacheMode(cacheMode)
	t.Log("session cache mode", sessionCacheMode, "new mode", cacheMode)

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

func TestTLS13Connection(t *testing.T) {
	// Run server
	server, err := newTLS13Server(t, testCertDir)

	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.Run()

	// Run client
	caFile := "test/certs/sm2/chain-ca.crt"
	connAddr := "127.0.0.1:4433"

	ctx, err := NewCtxWithVersion(TLSv1_3)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.LoadVerifyLocations(caFile, ""); err != nil {
		t.Error(err)
		return
	}

	certPEM, err := os.ReadFile("test/certs/sm2/client_enc.crt")
	if err != nil {
		t.Error(err)
		return
	}

	cert, err := crypto.LoadCertificateFromPEM(certPEM)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.UseCertificate(cert); err != nil {
		t.Error(err)
		return
	}

	keyPEM, err := os.ReadFile("test/certs/sm2/client_enc.key")
	if err != nil {
		t.Error(err)
		return
	}

	key, err := crypto.LoadPrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Error(err)
		return
	}

	if err = ctx.UsePrivateKey(key); err != nil {
		t.Error(err)
		return
	}

	conn, err := Dial("tcp", connAddr, ctx, InsecureSkipHostVerification, "")
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

	request := "hello tongsuo\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != request {
		t.Error("response data is not expected: ", resp)
		return
	}
}

func newTLS13Server(t *testing.T, testDir string, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(TLSv1_3)
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

	encCertPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	Cert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UseCertificate(Cert); err != nil {
		t.Error(err)
		return nil, err
	}

	KeyPEM, err := os.ReadFile(filepath.Join(testDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	Key, err := crypto.LoadPrivateKeyFromPEM(KeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.UsePrivateKey(Key); err != nil {
		t.Error(err)
		return nil, err
	}

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}

func TestTLSv13SMCipher(t *testing.T) {
	cipher := TLSSMGCMCipher
	testCertDir := "test/certs"
	//caFile := filepath.Join(testCertDir, "chain-ca.crt")

	// Run server
	server, err := newTLSv13SMCipherServer(t, testCertDir, func(sslctx *Ctx) error {
		return sslctx.SetCipherSuites(cipher)
	})
	if err != nil {
		t.Error(err)
		return
	}

	defer server.Close()
	go server.Run()

	// Run client
	ctx, err := NewCtxWithVersion(TLSv1_3)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.SetCipherSuites(cipher); err != nil {
		t.Error(err)
		return
	}

	conn, err := DialSession("tcp", "127.0.0.1:4433", ctx, InsecureSkipHostVerification, nil, "")
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

	request := "hello tongsuo\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Error(err)
		return
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Error(err)
		return
	}

	if resp != request {
		t.Error("response data is not expected: ", resp)
		return
	}

}

func newTLSv13SMCipherServer(t *testing.T, testDir string, options ...func(sslctx *Ctx) error) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(TLSv1_3)
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

	lis, err := Listen("tcp", "127.0.0.1:4433", ctx)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	return &echoServer{lis}, nil
}
