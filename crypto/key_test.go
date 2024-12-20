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

package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	pem_pkg "encoding/pem"
	"os"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	certBytes = `-----BEGIN CERTIFICATE-----
MIIExjCCAy6gAwIBAgIRAMqZUO0eR6sVZ3A8iG8bJK8wDQYJKoZIhvcNAQELBQAw
ezEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSgwJgYDVQQLDB90b21z
YXd5ZXJAQi1GRzc5TUw3SC0wNDQ4LmxvY2FsMS8wLQYDVQQDDCZta2NlcnQgdG9t
c2F3eWVyQEItRkc3OU1MN0gtMDQ0OC5sb2NhbDAeFw0yMjA0MDcwMzU5NDVaFw0z
MjA0MDcwMzU5NDVaMHsxHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTEo
MCYGA1UECwwfdG9tc2F3eWVyQEItRkc3OU1MN0gtMDQ0OC5sb2NhbDEvMC0GA1UE
AwwmbWtjZXJ0IHRvbXNhd3llckBCLUZHNzlNTDdILTA0NDgubG9jYWwwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDCiPTlT2P5jzEazzFX2fT7pToolJLp
4yf3EvgJb2qjFumY1fBk2q6MtYfQutx4Xfhfq+obdTqauFAq3aDjLBYY6bFCT064
mrAetUU9nKF6JLjPHBQP8KexnlyrVo4of89qZadpp83KUF2PfejcJBdkFGSJg1qd
0kY+NCxWN8jojTzLZE5hTZVPiNQCgTgEQnFYKZHhMiliRmDULfZYtzuRZ5DtmOM9
7vQEOdPKz3lUYL4mcIWQjcK6FVvrlJCQ+IpoNQT0gO1G9IvSkxW/HnU4oGIJL2ZT
VOG+FLDVz+gBcov5HsoXsn8P9W+zpUAiyFIk8iX2AEgjYlrUOySa+a/0/T9MDkKs
vAAsA5cJpn/r3tJ3z5szVl25oA5K9dWqz+TfAzrfwn6XRhr4Dy2g40YnRCjluL5o
Nta9wG0gh/IN6yZuv+DLKoWHFg8G8fUPQ7mSP+4fKA3tSTeYNXgG6+6K56feTBsx
eiNBw2MjLLQg1C9hD+23sX7LlHBP/Rc8R8ECAwEAAaNFMEMwDgYDVR0PAQH/BAQD
AgIEMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOzh0Zk5E80of0Ak077f
dEjwRYDQMA0GCSqGSIb3DQEBCwUAA4IBgQAwig6V0/RnrLzuAnZIy0DCQzvCx33k
4DqIHEktCGQ6weBbtv/wz4MLcGjy6hJu2KS/ZZdBiCWern3x/tdu1LWjfav1NK1W
QwOyHb+gDa+c7oQHKelw3J3Nnfb8Vb4EgdkMFRbx0qmxGHEracyZHy0/zoA7Rplm
I7Go5pdDD49otO/QEojeDb7b1BAELDB2ZcUMQaQfkkreYnwIHx76Bvqw6lIsF/6y
M1asr4Mz9JOxOPlAVsT7/JD5lGD3bT87evPgngpp7OsyylUCdTaHyU4Cv/9Axsv6
TUZBx+3xZsqRtnWxE2ivn3UKp6dD0+ykgG0U2SwFzqvLEH9r/9gfElE6oYbZJiR6
UjxAjLXvWmij6ilpMADnLQA0SH6s+9E2Aa5LTpEMDqXORcu+sq5/m3RuDtVxuYdU
HNnVAmIdTLKC9CWnRfDxH8zPgIr/L8Yhdw92YST8hNqGQHeR0qoBcKYMHkpH6Ay4
yuKERO5LaAmjoXJW3n5Zal6jogf3wpiV1o4=
-----END CERTIFICATE-----
`
	keyBytes = `-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAwoj05U9j+Y8xGs8xV9n0+6U6KJSS6eMn9xL4CW9qoxbpmNXw
ZNqujLWH0LrceF34X6vqG3U6mrhQKt2g4ywWGOmxQk9OuJqwHrVFPZyheiS4zxwU
D/CnsZ5cq1aOKH/PamWnaafNylBdj33o3CQXZBRkiYNandJGPjQsVjfI6I08y2RO
YU2VT4jUAoE4BEJxWCmR4TIpYkZg1C32WLc7kWeQ7ZjjPe70BDnTys95VGC+JnCF
kI3CuhVb65SQkPiKaDUE9IDtRvSL0pMVvx51OKBiCS9mU1ThvhSw1c/oAXKL+R7K
F7J/D/Vvs6VAIshSJPIl9gBII2Ja1Dskmvmv9P0/TA5CrLwALAOXCaZ/697Sd8+b
M1ZduaAOSvXVqs/k3wM638J+l0Ya+A8toONGJ0Qo5bi+aDbWvcBtIIfyDesmbr/g
yyqFhxYPBvH1D0O5kj/uHygN7Uk3mDV4Buvuiuen3kwbMXojQcNjIyy0INQvYQ/t
t7F+y5RwT/0XPEfBAgMBAAECggGBAJj6fKMLQJJS0YnEn4f3ZVizAT5CQBnfQWFh
sF4zGMexz/cZXlbhRVxvsKMrHw8kzpnlpk77bB+Zi6l56fhbhfEHbRa5KS2wr4km
gZHG55EW6aIs8XXriOP7peIzSc19XM3NrM5AYGuVsU2S9RiQ5TgVdU5SVmM/pW9r
NeaDLeH6l3FWqvCHwz/tWNOzbCqlWV68KfTOro6Sy7hvgIcZaKWarPS7QxBEJe5g
zzVw3HfHMCEoYVBgul39R/DFPr5SQ55Z6lw5rRuejnc0cvA3VAFpAR1DganTQDqD
QZDV+bJjRpvZULf9c5WfkkFk3kPQ/Q78K2Se1t98Wrvtf5YGUXIO+8nl+L64PIDb
Wimlf7sT2vwowqCdGCUWXQguaIE6IKN9AwnceTZa1R2NXfoiL6jc/lQ0plCJW4lg
B/Op7JPXzlBpW1ca4BqNlkXqN7se4g5M2gkbAeHHOViWixrbdlgNRQ3WFDRqQrt+
XNgUgFA4VhURAn2Td4fLy7JIXkdYxQKBwQDg/wihYF1pmwjjp/saM0I1Uh/IroFH
4ShOfkDkgHzEkYozTXSdAaEgZg5HLoyrsFNeBQ7qUYwqPhklf27xJVWjJyr42tNK
k5Rjgc87vfJE8E0ju9ZYntzN+UHfgoGu5n9Cuu5/6l2qjORhu8PzUzJDdjGU51RR
sbG5HzwqnKmwOKBDX15J8ekZpyYTpKEY+W5/j3gWqpwSkJ/tWryALjuc3ORebR8B
FgYtsv8bgqZQa2bRYpZnQqasympfHgMZSl8CgcEA3VdfUUOnge7bp86OZ2mJXu12
md9GG/QwQ9LChMWc/5t8CtV1e2pO+K3lM5Ubi/XKfcgMBO5LH9X3PbnUVXrskLC9
rQkriVrgt9UaGkcGThfxX0jj8Bo5mqCYAIRjKTSWciqXW0MI2p9WEW2blP5jPghL
0s66vwNBEd1dEmHhf85SAvwISXJ5YYm/ye/XD/4yv0ijRAIP2btnQIPQ7vUMcrSu
A++lLylt2lp4sRUaNsCfruvG/wThkl3lvhDDieHfAoHAb32Q7j6NK1Z6qizEHfCG
f1uJim0GfPLSgUrIpzIQIWupGtDn1yFGkYJg0t77L9x5Ax7ojC4Kkagh19X0yKPi
cq1m+tecWdkVb9WUNhtioMyevPVIOrPF4H8CKFpIHr3zE8MDifk9ntSgGtnrOHji
cFFyMkILI0w1L/GNY+Qrpbn5mEj6tROdmWudT6CFf5WiLq2OKVUzb3Og/AG5ZJ8E
RS+kLjJOacBbIWwQQ7aS6Ui/M0RyGQsLApZu7WE20eJrAoHBANYEDV3+FJFF642t
43OKUBFBelP910RgL+rkdsD6cnuUU7QGAbp7aDB7tArUOfZyioBkVXrPDkSSFqXQ
cMbWPLcKrdwJ6da90Frv6nVOB4KrE/AWAo++S8R/U3nsiBTnjDCHjiHoBz+coRPo
7255KmxoiSgkS901wE0NxVho3Ck/zXylRT3/Oe5dytvu0/vaxia+jV7Mv5a/5W40
BmmG96pRmZCkvwuC+30NzXUr+lTGm5/+ykL67UEhGWtVujwv8QKBwEmRZxVi6mXs
XjiFefhN27S0vzPEBrRo6lDZz7w49LgoNb56ijezOZ8rg05hrqA00uLRNk/rbjC2
JBfFkFXDvcbaYmpcOVCS1susPrPr8rgIm+vK6X+UoWE1RcCMGQMKObQIDGpE4IWe
TDoukqQ8peoffk6mtiCnph9Cl2uqAgmmX+GyunEMIdF/ySG0CCcfz180GsQCucax
+AxW2R7NJMAHvfeaYoLtSMYEVTS8sSpuIbRTfGuxbmMOD8a03gU6AA==
-----END RSA PRIVATE KEY-----
`
	prime256v1KeyBytes = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIB/XL0zZSsAu+IQF1AI/nRneabb2S126WFlvvhzmYr1KoAoGCCqGSM49
AwEHoUQDQgAESSFGWwF6W1hoatKGPPorh4+ipyk0FqpiWdiH+4jIiU39qtOeZGSh
1QgSbzfdHxvoYI0FXM+mqE7wec0kIvrrHw==
-----END EC PRIVATE KEY-----
`
	prime256v1CertBytes = `-----BEGIN CERTIFICATE-----
MIIChTCCAiqgAwIBAgIJAOQII2LQl4uxMAoGCCqGSM49BAMCMIGcMQswCQYDVQQG
EwJVUzEPMA0GA1UECAwGS2Fuc2FzMRAwDgYDVQQHDAdOb3doZXJlMR8wHQYDVQQK
DBZGYWtlIENlcnRpZmljYXRlcywgSW5jMUkwRwYDVQQDDEBhMWJkZDVmZjg5ZjQy
N2IwZmNiOTdlNDMyZTY5Nzg2NjI2ODJhMWUyNzM4MDhkODE0ZWJiZjY4ODBlYzA3
NDljMB4XDTE3MTIxNTIwNDU1MVoXDTI3MTIxMzIwNDU1MVowgZwxCzAJBgNVBAYT
AlVTMQ8wDQYDVQQIDAZLYW5zYXMxEDAOBgNVBAcMB05vd2hlcmUxHzAdBgNVBAoM
FkZha2UgQ2VydGlmaWNhdGVzLCBJbmMxSTBHBgNVBAMMQGExYmRkNWZmODlmNDI3
YjBmY2I5N2U0MzJlNjk3ODY2MjY4MmExZTI3MzgwOGQ4MTRlYmJmNjg4MGVjMDc0
OWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARJIUZbAXpbWGhq0oY8+iuHj6Kn
KTQWqmJZ2If7iMiJTf2q055kZKHVCBJvN90fG+hgjQVcz6aoTvB5zSQi+usfo1Mw
UTAdBgNVHQ4EFgQUfRYAFhlGM1wzvusyGrm26Vrbqm4wHwYDVR0jBBgwFoAUfRYA
FhlGM1wzvusyGrm26Vrbqm4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJ
ADBGAiEA6PWNjm4B6zs3Wcha9qyDdfo1ILhHfk9rZEAGrnfyc2UCIQD1IDVJUkI4
J/QVoOtP5DOdRPs/3XFy0Bk0qH+Uj5D7LQ==
-----END CERTIFICATE-----
`
	sm2KeyBytes = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ0I4yR5ezlVWygUi7+NNipNJSBqUjaCopitIJMU1nlSoAoGCCqBHM9V
AYItoUQDQgAEMbiGjBxkDrC1rwuVlIC/6fbGdnaKxj2/Lkv9EcOLKv3WFuFi1eae
UvQSkNcRMdaAixpM+RKQ+Cp6Z3szJUr0jQ==
-----END EC PRIVATE KEY-----
`
	sm2CertBytes = `-----BEGIN CERTIFICATE-----
MIIDKjCCAs+gAwIBAgIQILmubp7njmhGt3wZLFwx6jAKBggqgRzPVQGDdTBtMQsw
CQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD
YW50MRcwFQYDVQQDDA53d3cubWlkZGxlLmNvbTEcMBoGCSqGSIb3DQEJARYNdGVz
dEB0ZXN0LmNvbTAeFw0yMDA0MTQwOTA3MzlaFw0zMDA0MTIwOTA3MzlaME0xCzAJ
BgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYDVQQLDANh
bnQxFTATBgNVBAMMDCouYWxpcGF5LmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABDG4howcZA6wta8LlZSAv+n2xnZ2isY9vy5L/RHDiyr91hbhYtXmnlL0EpDX
ETHWgIsaTPkSkPgqemd7MyVK9I2jggFvMIIBazAJBgNVHRMEAjAAMBEGCWCGSAGG
+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQgU2Vy
dmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQpsBvv0pBVShGKj2Ib3MLqCr7Y8DCB
rAYDVR0jBIGkMIGhgBRxUGhXcyoi1ubSkgs6CcVWWABhXqF3pHUwczELMAkGA1UE
BhMCQ04xCzAJBgNVBAgMAkhaMQwwCgYDVQQKDANhbGkxDDAKBgNVBAsMA2FudDEY
MBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSEwHwYJKoZIhvcNAQkBFhJjbGllbnRA
ZXhhbXBsZS5jb22CECC5rm6e545oRrd8GSxcMegwDgYDVR0PAQH/BAQDAgWgMBMG
A1UdJQQMMAoGCCsGAQUFBwMBMCMGA1UdEQQcMBqCCmFsaXBheS5jb22CDCouYWxp
cGF5LmNvbTAKBggqgRzPVQGDdQNJADBGAiEAmuMCuZKaF3zVYc1T6DGGi0+hmMuZ
jpH7uznwqix7GJsCIQCOjB/iG+WxOvUz//t//Ru1QnVivDaCEQXkW2dXyX+fWg==
-----END CERTIFICATE-----
`
	ed25519CertBytes = `-----BEGIN CERTIFICATE-----
MIIBIzCB1gIUd0UUPX+qHrSKSVN9V/A3F1Eeti4wBQYDK2VwMDYxCzAJBgNVBAYT
AnVzMQ0wCwYDVQQKDARDU0NPMRgwFgYDVQQDDA9lZDI1NTE5X3Jvb3RfY2EwHhcN
MTgwODE3MDMzNzQ4WhcNMjgwODE0MDMzNzQ4WjAzMQswCQYDVQQGEwJ1czENMAsG
A1UECgwEQ1NDTzEVMBMGA1UEAwwMZWQyNTUxOV9sZWFmMCowBQYDK2VwAyEAKZZJ
zzlBcpjdbvzV0BRoaSiJKxbU6GnFeAELA0cHWR0wBQYDK2VwA0EAbfUJ7L7v3GDq
Gv7R90wQ/OKAc+o0q9eOrD6KRYDBhvlnMKqTMRVucnHXfrd5Rhmf4yHTvFTOhwmO
t/hpmISAAA==
-----END CERTIFICATE-----
`
	ed25519KeyBytes = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL3QVwyuusKuLgZwZn356UHk9u1REGHbNTLtFMPKNQSb
-----END PRIVATE KEY-----
`
)

func TestMarshal(t *testing.T) {
	t.Parallel()

	_, err := crypto.LoadPrivateKeyFromPEM([]byte(keyBytes))
	if err != nil {
		t.Error(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(certBytes))
	if err != nil {
		t.Error(err)
	}

	privateBlock, _ := pem_pkg.Decode([]byte(keyBytes))

	key, err := crypto.LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(certBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(certBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(keyBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(keyBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid private key pem bytes")
	}

	tlsCert, err := tls.X509KeyPair([]byte(certBytes), []byte(keyBytes))
	if err != nil {
		t.Error(err)
	}

	tlsKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Error("FASDFASDF")
	}

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Error(err)
	}

	tlsDer := x509.MarshalPKCS1PrivateKey(tlsKey)
	if !bytes.Equal(der, tlsDer) {
		t.Errorf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tlsDer))
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	tlsDer, err = x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(der, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(der)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	tlsPem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Headers: nil, Bytes: tlsDer,
	})
	if !bytes.Equal(pem, tlsPem) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", tlsPem, 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key pem bytes")
	}

	pubkeyFromPem, err := crypto.LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Error(err)
	}

	pubkeyFromDer, err := crypto.LoadPublicKeyFromDER(der)
	if err != nil {
		t.Error(err)
	}

	newDerFromPem, err := pubkeyFromPem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	newDerFromDer, err := pubkeyFromDer.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(newDerFromDer, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(newDerFromDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}

	if !bytes.Equal(newDerFromPem, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(newDerFromPem)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}

	_, err = crypto.GenerateRSAKeyWithExponent(1024, 65537)
	if err != nil {
		t.Error(err)
	}
}

func TestGenerateEC(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateECKey(crypto.Prime256v1)
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}
}

func TestGenerateEd25519(t *testing.T) {
	t.Parallel()

	if !crypto.SupportEd25519() {
		t.SkipNow()
	}

	key, err := crypto.GenerateED25519Key()
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateRSAKey(1024)
	data := []byte("the quick brown fox jumps over the lazy dog")

	_, err := key.SignPKCS1v15(crypto.SHA1Method(), data)
	if err != nil {
		t.Error(err)
	}

	_, err = key.SignPKCS1v15(crypto.SHA256Method(), data)
	if err != nil {
		t.Error(err)
	}

	_, err = key.SignPKCS1v15(crypto.SHA512Method(), data)
	if err != nil {
		t.Error(err)
	}
}

func TestSignEC(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateECKey(crypto.Prime256v1)
	if err != nil {
		t.Error(err)
	}

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sha1", func(t *testing.T) {
		t.Parallel()

		sig, err := key.SignPKCS1v15(crypto.SHA1Method(), data)
		if err != nil {
			t.Error(err)
		}

		err = key.VerifyPKCS1v15(crypto.SHA1Method(), data, sig)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("sha256", func(t *testing.T) {
		t.Parallel()

		sig, err := key.SignPKCS1v15(crypto.SHA256Method(), data)
		if err != nil {
			t.Error(err)
		}

		err = key.VerifyPKCS1v15(crypto.SHA256Method(), data, sig)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("sha512", func(t *testing.T) {
		t.Parallel()

		sig, err := key.SignPKCS1v15(crypto.SHA512Method(), data)
		if err != nil {
			t.Error(err)
		}

		err = key.VerifyPKCS1v15(crypto.SHA512Method(), data, sig)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestSignSM2(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Error(err)
	}

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sm2", func(t *testing.T) {
		t.Parallel()

		sig, err := key.SignPKCS1v15(crypto.SM3Method(), data)
		if err != nil {
			t.Error(err)
		}

		err = key.VerifyPKCS1v15(crypto.SM3Method(), data, sig)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestSignED25519(t *testing.T) {
	t.Parallel()

	if !crypto.SupportEd25519() {
		t.SkipNow()
	}

	key, err := crypto.GenerateED25519Key()
	if err != nil {
		t.Error(err)
	}

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("new", func(t *testing.T) {
		t.Parallel()

		sig, err := key.SignPKCS1v15(nil, data)
		if err != nil {
			t.Error(err)
		}

		err = key.VerifyPKCS1v15(nil, data, sig)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestMarshalEC(t *testing.T) {
	t.Parallel()

	_, err := crypto.LoadPrivateKeyFromPEM([]byte(prime256v1KeyBytes))
	if err != nil {
		t.Error(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(prime256v1CertBytes))
	if err != nil {
		t.Error(err)
	}

	privateBlock, _ := pem_pkg.Decode([]byte(prime256v1KeyBytes))

	key, err := crypto.LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(prime256v1CertBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(prime256v1CertBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(prime256v1KeyBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(prime256v1KeyBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid private key pem bytes")
	}

	tlsCert, err := tls.X509KeyPair([]byte(prime256v1CertBytes), []byte(prime256v1KeyBytes))
	if err != nil {
		t.Error(err)
	}

	tlsKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("FASDFASDF")
	}

	_ = tlsKey

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Error(err)
	}

	tlsDer, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(der, tlsDer) {
		t.Errorf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tlsDer))
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	tlsDer, err = x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(der, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(der)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	tlsPem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Headers: nil, Bytes: tlsDer,
	})
	if !bytes.Equal(pem, tlsPem) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", tlsPem, 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key pem bytes")
	}

	pubkeyFromPem, err := crypto.LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Error(err)
	}

	pubkeyFromDer, err := crypto.LoadPublicKeyFromDER(der)
	if err != nil {
		t.Error(err)
	}

	newDerFromPem, err := pubkeyFromPem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	newDerFromDer, err := pubkeyFromDer.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(newDerFromDer, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(newDerFromDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}

	if !bytes.Equal(newDerFromPem, tlsDer) {
		err := os.WriteFile("generated", []byte(hex.Dump(newDerFromPem)), 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(hex.Dump(tlsDer)), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid public key der bytes")
	}
}

func TestMarshalSM2(t *testing.T) {
	t.Parallel()

	_, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2KeyBytes))
	if err != nil {
		t.Error(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(sm2CertBytes))
	if err != nil {
		t.Error(err)
	}

	privateBlock, _ := pem_pkg.Decode([]byte(sm2KeyBytes))

	key, err := crypto.LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(sm2CertBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(sm2CertBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(sm2KeyBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(sm2KeyBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid private key pem bytes")
	}
}

func TestMarshalEd25519(t *testing.T) {
	t.Parallel()

	if !crypto.SupportEd25519() {
		t.SkipNow()
	}

	_, err := crypto.LoadPrivateKeyFromPEM([]byte(ed25519KeyBytes))
	if err != nil {
		t.Error(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(ed25519CertBytes))
	if err != nil {
		t.Error(err)
	}

	privateBlock, _ := pem_pkg.Decode([]byte(ed25519KeyBytes))

	key, err := crypto.LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(pem, []byte(ed25519CertBytes)) {
		err := os.WriteFile("generated", pem, 0o600)
		if err != nil {
			t.Error(err)
		}

		err = os.WriteFile("hardcoded", []byte(ed25519CertBytes), 0o600)
		if err != nil {
			t.Error(err)
		}

		t.Error("invalid cert pem bytes")
	}

	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Error(err)
	}

	_, err = key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Error(err)
	}

	der, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Error(err)
	}

	pubkeyFromPem, err := crypto.LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Error(err)
	}

	pubkeyFromDer, err := crypto.LoadPublicKeyFromDER(der)
	if err != nil {
		t.Error(err)
	}

	_, err = pubkeyFromPem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}

	_, err = pubkeyFromDer.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Error(err)
	}
}
