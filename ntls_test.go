package tongsuogo

import (
	"log"
	"testing"
)

const (
	ECCSM2Cipher   = "ECC-SM2-WITH-SM4-SM3"
	ECDHESM2Cipher = "ECDHE-SM2-WITH-SM4-SM3"
)

func TestNTLSECCSM2(t *testing.T) {

	ctx, err := NewCtxWithVersion(NTLS)
	if err != nil {
		t.Fatal(err)
	}

	if err := ctx.SetCipherList(ECCSM2Cipher); err != nil {
		t.Fatal(err)
	}

	conn, err := Dial("tcp", "demo.gmssl.cn:2443", ctx, InsecureSkipHostVerification)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	cipher, err := conn.CurrentCipher()
	if err != nil {
		log.Fatal(err)
	}

	t.Log("current cipher", cipher)

	request := `GET / HTTP/1.1
Host: demo.gmssl.cn
User-Agent: tongsuog
Accept: text/html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8

`

	if _, err := conn.Write([]byte(request)); err != nil {
		log.Fatal(err)
	}

	data := make([]byte, 10240)
	if _, err := conn.Read(data); err != nil {
		log.Fatal(err)
	}

	t.Log("response", string(data))
}
