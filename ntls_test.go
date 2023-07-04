package tongsuogo

import (
	"bufio"
	"log"
	"net"
	"os"
	"testing"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
)

func TestNTLSECCSM2(t *testing.T) {
	ctx, err := NewCtxWithVersion(NTLS)
	if err != nil {
		t.Error(err)
		return
	}

	if err := ctx.SetCipherList(ECCSM2Cipher); err != nil {
		t.Error(err)
		return
	}

	server, err := newNTLSServer(t)
	if err != nil {
		t.Error(err)
		return
	}
	defer server.Close()
	go server.Run()

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

	req, err := bufio.NewReader(conn).ReadString('\n')
	if req != request {
		t.Errorf("expect response '%s' got '%s'", request, req)
		return
	}
}

func newNTLSServer(t *testing.T) (*echoServer, error) {
	ctx, err := NewCtxWithVersion(NTLS)
	if err != nil {
		t.Error(err)
		return nil, err
	}

	if err := ctx.SetCipherList(ECCSM2Cipher); err != nil {
		t.Error(err)
		return nil, err
	}

	encCertPEM, err := os.ReadFile("tongsuo/test_certs/double_cert/SE.cert.pem")
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile("tongsuo/test_certs/double_cert/SS.cert.pem")
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

	encKeyPEM, err := os.ReadFile("tongsuo/test_certs/double_cert/SE.key.pem")
	if err != nil {
		t.Error(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile("tongsuo/test_certs/double_cert/SS.key.pem")
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
