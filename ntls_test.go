package tongsuogo

import (
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
	internalServer = true

	testCertDir = "tongsuo/test/certs/sm2"
)

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
				server, err := newNTLSServer(t, func(sslctx *Ctx) error {
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
				signCert, err := LoadCertificateFromPEM(signCertPEM)
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
				signKey, err := LoadPrivateKeyFromPEM(signKeyPEM)
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
				encCert, err := LoadCertificateFromPEM(encCertPEM)
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

				encKey, err := LoadPrivateKeyFromPEM(encKeyPEM)
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

func newNTLSServer(t *testing.T, options ...func(sslctx *Ctx) error) (*echoServer, error) {
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

	if err := ctx.LoadVerifyLocations(filepath.Join(testCertDir, "chain-ca.crt"), ""); err != nil {
		t.Error(err)
		return nil, err
	}

	encCertPEM, err := os.ReadFile(filepath.Join(testCertDir, "server_enc.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(filepath.Join(testCertDir, "server_sign.crt"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encCert, err := LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCert, err := LoadCertificateFromPEM(signCertPEM)
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

	encKeyPEM, err := os.ReadFile(filepath.Join(testCertDir, "server_enc.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(filepath.Join(testCertDir, "server_sign.key"))
	if err != nil {
		t.Error(err)
		return nil, err
	}

	encKey, err := LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKey, err := LoadPrivateKeyFromPEM(signKeyPEM)
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
