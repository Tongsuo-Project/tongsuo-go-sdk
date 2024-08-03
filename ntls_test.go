package tongsuogo

import (
	"bufio"
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
	internalServer = true

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

			conn, err := Dial("tcp", "127.0.0.1:4433", ctx, InsecureSkipHostVerification)
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

			conn, err := Dial("tcp", "127.0.0.1:4433", ctx, InsecureSkipHostVerification)
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
