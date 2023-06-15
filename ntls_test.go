package tongsuogo

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
)

func TestMain(m *testing.M) {
	var wg sync.WaitGroup

	cctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := exec.CommandContext(
			cctx,
			"/opt/tongsuo/bin/openssl",
			"s_server",
			"-accept",
			"127.0.0.1:4433",
			"-enc_cert",
			"tongsuo/test_certs/double_cert/SE.cert.pem",
			"-enc_key",
			"tongsuo/test_certs/double_cert/SE.key.pem",
			"-sign_cert",
			"tongsuo/test_certs/double_cert/SS.cert.pem",
			"-sign_key",
			"tongsuo/test_certs/double_cert/SS.key.pem",
			"-enable_ntls",
		)

		cmd.Env = append(os.Environ(), "DYLD_LIBRARY_PATH=/opt/tongsuo/lib", "LD_LIBRARY_PATH=/opt/tongsuo/lib")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(time.Second)

	ret := m.Run()
	cancel()
	wg.Wait()
	os.Exit(ret)
}

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

	request := `hello tongsuo`
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Error(err)
		return
	}

	data := make([]byte, len(request))
	if _, err := conn.Read(data); err != nil {
		t.Error(err)
		return
	}

	t.Log("response", string(data))
}
