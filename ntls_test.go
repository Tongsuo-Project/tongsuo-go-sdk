package tongsuogo

import (
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
}
