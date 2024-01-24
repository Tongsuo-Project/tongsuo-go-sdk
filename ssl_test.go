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

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/utils"
)

var (
	certBytes = []byte(`-----BEGIN CERTIFICATE-----
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
`)
	keyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)
	prime256v1KeyBytes = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIB/XL0zZSsAu+IQF1AI/nRneabb2S126WFlvvhzmYr1KoAoGCCqGSM49
AwEHoUQDQgAESSFGWwF6W1hoatKGPPorh4+ipyk0FqpiWdiH+4jIiU39qtOeZGSh
1QgSbzfdHxvoYI0FXM+mqE7wec0kIvrrHw==
-----END EC PRIVATE KEY-----
`)
	prime256v1CertBytes = []byte(`-----BEGIN CERTIFICATE-----
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
`)
	ed25519CertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIBIzCB1gIUd0UUPX+qHrSKSVN9V/A3F1Eeti4wBQYDK2VwMDYxCzAJBgNVBAYT
AnVzMQ0wCwYDVQQKDARDU0NPMRgwFgYDVQQDDA9lZDI1NTE5X3Jvb3RfY2EwHhcN
MTgwODE3MDMzNzQ4WhcNMjgwODE0MDMzNzQ4WjAzMQswCQYDVQQGEwJ1czENMAsG
A1UECgwEQ1NDTzEVMBMGA1UEAwwMZWQyNTUxOV9sZWFmMCowBQYDK2VwAyEAKZZJ
zzlBcpjdbvzV0BRoaSiJKxbU6GnFeAELA0cHWR0wBQYDK2VwA0EAbfUJ7L7v3GDq
Gv7R90wQ/OKAc+o0q9eOrD6KRYDBhvlnMKqTMRVucnHXfrd5Rhmf4yHTvFTOhwmO
t/hpmISAAA==
-----END CERTIFICATE-----
`)
	ed25519KeyBytes = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL3QVwyuusKuLgZwZn356UHk9u1REGHbNTLtFMPKNQSb
-----END PRIVATE KEY-----
`)
)

func NetPipe(t testing.TB) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client_future := utils.NewFuture()
	go func() {
		client_future.Set(net.Dial(l.Addr().Network(), l.Addr().String()))
	}()
	var errs utils.ErrorGroup
	server_conn, err := l.Accept()
	errs.Add(err)
	client_conn, err := client_future.Get()
	errs.Add(err)
	err = errs.Finalize()
	if err != nil {
		if server_conn != nil {
			server_conn.Close()
		}
		if client_conn != nil {
			client_conn.(net.Conn).Close()
		}
		t.Fatal(err)
	}
	return server_conn, client_conn.(net.Conn)
}

type HandshakingConn interface {
	net.Conn
	Handshake() error
}

func SimpleConnTest(t testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {
	server_conn, client_conn := NetPipe(t)
	defer server_conn.Close()
	defer client_conn.Close()

	data := "first test string\n"

	server, client := constructor(t, server_conn, client_conn)
	defer close_both(server, client)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		err := client.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		_, err = io.Copy(client, bytes.NewReader([]byte(data)))
		if err != nil {
			t.Fatal(err)
		}

		err = client.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()
	go func() {
		defer wg.Done()
		// TODO check server.Close if err
		defer server.Close()

		err := server.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		buf := bytes.NewBuffer(make([]byte, 0, len(data)))
		_, err = io.CopyN(buf, server, int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if string(buf.Bytes()) != data {
			t.Fatal("mismatched data")
		}

	}()
	wg.Wait()
}

func close_both(closer1, closer2 io.Closer) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		closer1.Close()
	}()
	go func() {
		defer wg.Done()
		closer2.Close()
	}()
	wg.Wait()
}

func ClosingTest(t testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {

	run_test := func(server_writes bool) {
		server_conn, client_conn := NetPipe(t)
		defer server_conn.Close()
		defer client_conn.Close()
		server, client := constructor(t, server_conn, client_conn)
		defer close_both(server, client)

		var sslconn1, sslconn2 HandshakingConn
		if server_writes {
			sslconn1 = server
			sslconn2 = client
		} else {
			sslconn1 = client
			sslconn2 = server
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := sslconn1.Write([]byte("hello"))
			if err != nil {
				t.Fatal(err)
			}

			sslconn1.Close()
		}()

		go func() {
			defer wg.Done()
			data, err := io.ReadAll(sslconn2)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, []byte("hello")) {
				t.Fatal("bytes don't match")
			}
		}()

		wg.Wait()
	}

	run_test(false)
	run_test(true)
}

func ThroughputBenchmark(b *testing.B, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {
	server_conn, client_conn := NetPipe(b)
	defer server_conn.Close()
	defer client_conn.Close()

	server, client := constructor(b, server_conn, client_conn)
	defer close_both(server, client)

	b.SetBytes(1024)
	data := make([]byte, b.N*1024)
	_, err := io.ReadFull(rand.Reader, data[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err = io.Copy(client, bytes.NewReader([]byte(data)))
		if err != nil {
			b.Error(err)
		}
	}()
	go func() {
		defer wg.Done()

		buf := &bytes.Buffer{}
		_, err = io.CopyN(buf, server, int64(len(data)))
		if err != nil {
			b.Error(err)
		}
		if !bytes.Equal(buf.Bytes(), data) {
			b.Error("mismatched data")
		}
	}()
	wg.Wait()
	b.StopTimer()
}

func StdlibConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	server = tls.Server(server_conn, config)
	client = tls.Client(client_conn, config)
	return server, client
}

func passThruVerify(t testing.TB) func(bool, *CertificateStoreCtx) bool {
	x := func(ok bool, store *CertificateStoreCtx) bool {
		cert := store.GetCurrentCert()
		if cert == nil {
			t.Fatalf("Could not obtain cert from store\n")
		}
		sn := cert.GetSerialNumberHex()
		if len(sn) == 0 {
			t.Fatalf("Could not obtain serial number from cert")
		}
		return ok
	}
	return x
}

func OpenSSLConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	ctx.SetVerify(VerifyNone, passThruVerify(t))
	key, err := crypto.LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := crypto.LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.SetCipherList("AES128-SHA")
	if err != nil {
		t.Fatal(err)
	}
	server, err = Server(server_conn, ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err = Client(client_conn, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

func StdlibOpenSSLConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	server_std, _ := StdlibConstructor(t, server_conn, client_conn)
	_, client_ssl := OpenSSLConstructor(t, server_conn, client_conn)
	return server_std, client_ssl
}

func OpenSSLStdlibConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	_, client_std := StdlibConstructor(t, server_conn, client_conn)
	server_ssl, _ := OpenSSLConstructor(t, server_conn, client_conn)
	return server_ssl, client_std
}

func TestStdlibSimple(t *testing.T) {
	SimpleConnTest(t, StdlibConstructor)
}

func TestOpenSSLSimple(t *testing.T) {
	SimpleConnTest(t, OpenSSLConstructor)
}

func TestStdlibClosing(t *testing.T) {
	ClosingTest(t, StdlibConstructor)
}

// TODO fix this
//func TestOpenSSLClosing(t *testing.T) {
//	ClosingTest(t, OpenSSLConstructor)
//}

func BenchmarkStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibConstructor)
}

func BenchmarkOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLConstructor)
}

func TestStdlibOpenSSLSimple(t *testing.T) {
	SimpleConnTest(t, StdlibOpenSSLConstructor)
}

func TestOpenSSLStdlibSimple(t *testing.T) {
	SimpleConnTest(t, OpenSSLStdlibConstructor)
}

func TestStdlibOpenSSLClosing(t *testing.T) {
	ClosingTest(t, StdlibOpenSSLConstructor)
}

func TestOpenSSLStdlibClosing(t *testing.T) {
	ClosingTest(t, OpenSSLStdlibConstructor)
}

func BenchmarkStdlibOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibOpenSSLConstructor)
}

func BenchmarkOpenSSLStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLStdlibConstructor)
}

func FullDuplexRenegotiationTest(t testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {
	SSLRecordSize := 16 * 1024
	server_conn, client_conn := NetPipe(t)
	defer server_conn.Close()
	defer client_conn.Close()

	times := 256
	data_len := 4 * SSLRecordSize
	data1 := make([]byte, data_len)
	_, err := io.ReadFull(rand.Reader, data1[:])
	if err != nil {
		t.Fatal(err)
	}
	data2 := make([]byte, data_len)
	_, err = io.ReadFull(rand.Reader, data1[:])
	if err != nil {
		t.Fatal(err)
	}

	server, client := constructor(t, server_conn, client_conn)
	defer close_both(server, client)

	var wg sync.WaitGroup

	send_func := func(sender HandshakingConn, data []byte) {
		defer wg.Done()
		for i := 0; i < times; i++ {
			if i == times/2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := sender.Handshake()
					if err != nil {
						t.Fatal(err)
					}
				}()
			}
			_, err := sender.Write(data)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	recv_func := func(receiver net.Conn, data []byte) {
		defer wg.Done()

		buf := make([]byte, len(data))
		for i := 0; i < times; i++ {
			n, err := io.ReadFull(receiver, buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], data) {
				t.Fatal(err)
			}
		}
	}

	wg.Add(4)
	go recv_func(server, data1)
	go send_func(client, data1)
	go send_func(server, data2)
	go recv_func(client, data2)
	wg.Wait()
}

func TestStdlibFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, StdlibConstructor)
}

func TestOpenSSLFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, OpenSSLConstructor)
}

func TestOpenSSLStdlibFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, OpenSSLStdlibConstructor)
}

func TestStdlibOpenSSLFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, StdlibOpenSSLConstructor)
}

func LotsOfConns(t *testing.T, payload_size int64, loops, clients int,
	sleep time.Duration, newListener func(net.Listener) net.Listener,
	newClient func(net.Conn) (net.Conn, error)) {
	tcp_listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	ssl_listener := newListener(tcp_listener)
	go func() {
		for {
			conn, err := ssl_listener.Accept()
			if err != nil {
				t.Error("failed accept: ", err)
				continue
			}
			go func() {
				defer func() {
					err = conn.Close()
					if err != nil {
						t.Error("failed closing: ", err)
					}
				}()
				for i := 0; i < loops; i++ {
					_, err := io.Copy(ioutil.Discard,
						io.LimitReader(conn, payload_size))
					if err != nil {
						t.Error("failed reading: ", err)
						return
					}
					_, err = io.Copy(conn, io.LimitReader(rand.Reader,
						payload_size))
					if err != nil {
						t.Error("failed writing: ", err)
						return
					}
				}
				time.Sleep(sleep)
			}()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		tcp_client, err := net.Dial(tcp_listener.Addr().Network(),
			tcp_listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ssl_client, err := newClient(tcp_client)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int) {
			defer func() {
				err = ssl_client.Close()
				if err != nil {
					t.Error("failed closing: ", err)
				}
				wg.Done()
			}()
			for i := 0; i < loops; i++ {
				_, err := io.Copy(ssl_client, io.LimitReader(rand.Reader,
					payload_size))
				if err != nil {
					t.Error("failed writing: ", err)
					return
				}
				_, err = io.Copy(ioutil.Discard,
					io.LimitReader(ssl_client, payload_size))
				if err != nil {
					t.Error("failed reading: ", err)
					return
				}
			}
			time.Sleep(sleep)
		}(i)
	}
	wg.Wait()
}

func TestStdlibLotsOfConns(t *testing.T) {
	tls_cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_config := &tls.Config{
		Certificates:       []tls.Certificate{tls_cert},
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return tls.NewListener(l, tls_config)
		}, func(c net.Conn) (net.Conn, error) {
			return tls.Client(c, tls_config), nil
		})
}

func TestOpenSSLLotsOfConns(t *testing.T) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := crypto.LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.SetCipherList("AES128-SHA")
	if err != nil {
		t.Fatal(err)
	}
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return NewListener(l, ctx)
		}, func(c net.Conn) (net.Conn, error) {
			return Client(c, ctx)
		})
}
