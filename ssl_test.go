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

package tongsuogo_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ts "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/utils"
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
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
-----END RSA PRIVATE KEY-----
`
)

// NetPipe creates a TCP connection pipe and returns two connections.
func NetPipe(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer lis.Close()

	// Use Future pattern to create client connection asynchronously
	clientFuture := utils.NewFuture()
	go func() {
		clientFuture.Set(net.Dial(lis.Addr().Network(), lis.Addr().String()))
	}()

	var (
		errs utils.ErrorGroup
		conn net.Conn
		ok   bool
	)

	serverConn, err := lis.Accept()
	errs.Add(err)
	clientConn, err := clientFuture.Get()
	errs.Add(err)

	if clientConn != nil {
		conn, ok = clientConn.(net.Conn)
		if !ok {
			tb.Fatal("clientConn is not a net.Conn")
		}
	}

	err = errs.Finalize()
	if err == nil {
		return serverConn, conn
	}

	if serverConn != nil {
		err := serverConn.Close()
		if err != nil {
			tb.Fatal(err)
		}
	}

	if clientConn != nil {
		err := conn.Close()
		if err != nil {
			tb.Fatal(err)
		}
	}

	tb.Fatal(err)

	return nil, nil
}

// HandshakingConn interface extends net.Conn interface with Handshake method.
type HandshakingConn interface {
	net.Conn
	Handshake() error
}

// SimpleConnTest tests simple SSL/TLS connections.
func SimpleConnTest(tb testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn),
) {
	tb.Helper()
	// Create network pipe
	serverConn, clientConn := NetPipe(tb)
	defer serverConn.Close()
	defer clientConn.Close()

	data := "first test string\n"

	// Create SSL/TLS connections using provided constructor
	server, client := constructor(tb, serverConn, clientConn)
	defer closeBoth(server, client)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		err := client.Handshake()
		if err != nil {
			tb.Fatal(err)
		}

		_, err = io.Copy(client, bytes.NewReader([]byte(data)))
		if err != nil {
			tb.Fatal(err)
		}

		err = client.Close()
		if err != nil {
			tb.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
		defer server.Close()

		err := server.Handshake()
		if err != nil {
			tb.Fatal(err)
		}

		buf := bytes.NewBuffer(make([]byte, 0, len(data)))

		_, err = io.CopyN(buf, server, int64(len(data)))
		if err != nil {
			tb.Fatal(err)
		}

		if buf.String() != data {
			tb.Fatal("mismatched data")
		}
	}()
	wg.Wait()
}

// closeBoth closes two connections.
func closeBoth(closer1, closer2 io.Closer) {
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

// ClosingTest tests connection closing scenarios.
func ClosingTest(tb testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn),
) {
	tb.Helper()

	runTest := func(serverWrites bool) {
		// Create network pipe
		serverConn, clientConn := NetPipe(tb)
		defer serverConn.Close()
		defer clientConn.Close()

		server, client := constructor(tb, serverConn, clientConn)
		defer closeBoth(server, client)

		// Determine who writes and who reads based on server_writes parameter
		var sslconn1, sslconn2 HandshakingConn
		if serverWrites {
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
				tb.Fatal(err)
			}

			sslconn1.Close()
		}()

		go func() {
			defer wg.Done()

			data, err := io.ReadAll(sslconn2)
			if err != nil {
				tb.Fatal(err)
			}

			if !bytes.Equal(data, []byte("hello")) {
				tb.Fatal("bytes don't match")
			}
		}()

		wg.Wait()
	}

	// Test both client writing and server writing scenarios
	runTest(false)
	runTest(true)
}

// ThroughputBenchmark benchmarks SSL/TLS connection throughput.
func ThroughputBenchmark(b *testing.B, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn),
) {
	b.Helper()
	// Create network pipe
	serverConn, clientConn := NetPipe(b)
	defer serverConn.Close()
	defer clientConn.Close()

	// Create SSL/TLS connections
	server, client := constructor(b, serverConn, clientConn)
	defer closeBoth(server, client)

	// Set benchmark parameters
	b.SetBytes(1024)
	data := make([]byte, b.N*1024)

	_, err := io.ReadFull(rand.Reader, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		_, err = io.Copy(client, bytes.NewReader(data))
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

// StdlibConstructor creates standard library SSL/TLS connections.
func StdlibConstructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	cert, err := tls.X509KeyPair([]byte(certBytes), []byte(keyBytes))
	if err != nil {
		tb.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	server := tls.Server(serverConn, tlsConfig)
	client := tls.Client(clientConn, tlsConfig)

	return server, client
}

// StdlibTLSv13Constructor creates standard library SSL/TLS connections with TLSv1.3.
func StdlibTLSv13Constructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	cert, err := tls.X509KeyPair([]byte(certBytes), []byte(keyBytes))
	if err != nil {
		tb.Fatal(err)
	}

	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13

	server := tls.Server(serverConn, tlsConfig)
	client := tls.Client(clientConn, tlsConfig)

	return server, client
}

// passThruVerify is used to pass through certificate verification.
func passThruVerify(tb testing.TB) func(bool, *ts.CertificateStoreCtx) bool {
	tb.Helper()

	check := func(ok bool, store *ts.CertificateStoreCtx) bool {
		cert := store.GetCurrentCert()
		if cert == nil {
			tb.Fatalf("Could not obtain cert from store\n")
		}

		sn := cert.GetSerialNumberHex()
		if len(sn) == 0 {
			tb.Fatalf("Could not obtain serial number from cert")
		}

		return ok
	}

	return check
}

// OpenSSLConstructor creates OpenSSL SSL/TLS connections.
func OpenSSLConstructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	ctx, err := ts.NewCtx()
	if err != nil {
		tb.Fatal(err)
	}

	ctx.SetVerify(ts.VerifyNone, passThruVerify(tb))

	key, err := crypto.LoadPrivateKeyFromPEM([]byte(keyBytes))
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.UsePrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(certBytes))
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.UseCertificate(cert)
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.SetCipherList("AES128-SHA")
	if err != nil {
		tb.Fatal(err)
	}

	server, err := ts.Server(serverConn, ctx)
	if err != nil {
		tb.Fatal(err)
	}

	client, err := ts.Client(clientConn, ctx)
	if err != nil {
		tb.Fatal(err)
	}

	return server, client
}

// OpenSSLTLSv3Constructor function is used to create SSL/TLS connections for OpenSSL and TLSv3.
func OpenSSLTLSv3Constructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	ctx, err := ts.NewCtxWithVersion(ts.SSLv3)
	if err != nil {
		tb.Fatal(err)
	}

	ctx.SetVerify(ts.VerifyNone, passThruVerify(tb))

	key, err := crypto.LoadPrivateKeyFromPEM([]byte(keyBytes))
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.UsePrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(certBytes))
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.UseCertificate(cert)
	if err != nil {
		tb.Fatal(err)
	}

	err = ctx.SetCipherList("AES128-SHA")
	if err != nil {
		tb.Fatal(err)
	}

	server, err := ts.Server(serverConn, ctx)
	if err != nil {
		tb.Fatal(err)
	}

	client, err := ts.Client(clientConn, ctx)
	if err != nil {
		tb.Fatal(err)
	}

	return server, client
}

// StdlibOpenSSLConstructor function is used to create SSL/TLS connections for the standard library and OpenSSL.
func StdlibOpenSSLConstructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	serverStd, _ := StdlibConstructor(tb, serverConn, clientConn)
	_, clientSsl := OpenSSLConstructor(tb, serverConn, clientConn)

	return serverStd, clientSsl
}

// OpenSSLStdlibConstructor function is used to create SSL/TLS connections for OpenSSL and the standard library.
func OpenSSLStdlibConstructor(tb testing.TB, serverConn, clientConn net.Conn) (HandshakingConn, HandshakingConn) {
	tb.Helper()

	_, clientStd := StdlibConstructor(tb, serverConn, clientConn)
	serverSsl, _ := OpenSSLConstructor(tb, serverConn, clientConn)

	return serverSsl, clientStd
}

// TestStdlibSimple function is used to test simple connections of the standard library.
func TestStdlibSimple(t *testing.T) {
	t.Parallel()
	SimpleConnTest(t, StdlibConstructor)
}

// TestStdlibTLSv13Simple function is used to test simple connections of the standard library with TLSv1.3.
func TestStdlibTLSv13Simple(t *testing.T) {
	t.Parallel()
	SimpleConnTest(t, StdlibTLSv13Constructor)
}

// TestOpenSSLSimple function is used to test simple connections of OpenSSL.
func TestOpenSSLSimple(t *testing.T) {
	t.Parallel()
	SimpleConnTest(t, OpenSSLConstructor)
}

// TestStdlibClosing function is used to test closing connections of the standard library.
func TestStdlibClosing(t *testing.T) {
	t.Parallel()
	ClosingTest(t, StdlibConstructor)
}

// TestStdlibTLSv13Closing function is used to test closing connections of the standard library with TLSv1.3.
func TestStdlibTLSv13Closing(t *testing.T) {
	t.Parallel()
	ClosingTest(t, StdlibTLSv13Constructor)
}

func TestOpenSSLClosing(t *testing.T) {
	t.Parallel()
	ClosingTest(t, OpenSSLConstructor)
}

// BenchmarkStdlibThroughput function is used to benchmark the throughput of the standard library.
func BenchmarkStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibConstructor)
}

// BenchmarkStdlibTLSv13Throughput function is used to benchmark the throughput of the standard library with TLSv1.3.
func BenchmarkStdlibTLSv13Throughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibTLSv13Constructor)
}

// BenchmarkOpenSSLThroughput function is used to benchmark the throughput of OpenSSL.
func BenchmarkOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLConstructor)
}

// TestStdlibOpenSSLSimple function is used to test simple connections of the standard library and OpenSSL.
func TestStdlibOpenSSLSimple(t *testing.T) {
	t.Parallel()
	SimpleConnTest(t, StdlibOpenSSLConstructor)
}

// TestOpenSSLStdlibSimple function is used to test simple connections of OpenSSL and the standard library.
func TestOpenSSLStdlibSimple(t *testing.T) {
	t.Parallel()
	SimpleConnTest(t, OpenSSLStdlibConstructor)
}

// TestStdlibOpenSSLClosing function is used to test closing connections of the standard library and OpenSSL.
func TestStdlibOpenSSLClosing(t *testing.T) {
	t.Parallel()
	ClosingTest(t, StdlibOpenSSLConstructor)
}

// TestOpenSSLStdlibClosing function is used to test closing connections of OpenSSL and the standard library.
func TestOpenSSLStdlibClosing(t *testing.T) {
	t.Parallel()
	ClosingTest(t, OpenSSLStdlibConstructor)
}

// BenchmarkStdlibOpenSSLThroughput function is used to benchmark the throughput of the standard library and OpenSSL.
func BenchmarkStdlibOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibOpenSSLConstructor)
}

// BenchmarkOpenSSLStdlibThroughput function is used to benchmark the throughput of OpenSSL and the standard library.
func BenchmarkOpenSSLStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLStdlibConstructor)
}

// FullDuplexRenegotiationTest function is used to test full-duplex renegotiation.
func FullDuplexRenegotiationTest(tb testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn),
) {
	tb.Helper()

	SSLRecordSize := 16 * 1024

	serverConn, clientConn := NetPipe(tb)
	defer serverConn.Close()
	defer clientConn.Close()

	// Set test parameters
	times := 256
	dataLen := 4 * SSLRecordSize
	data1 := make([]byte, dataLen)

	_, err := io.ReadFull(rand.Reader, data1)
	if err != nil {
		tb.Fatal(err)
	}

	data2 := make([]byte, dataLen)

	_, err = io.ReadFull(rand.Reader, data2)
	if err != nil {
		tb.Fatal(err)
	}

	// Create SSL/TLS connections
	server, client := constructor(tb, serverConn, clientConn)
	defer closeBoth(server, client)

	var wg sync.WaitGroup

	sendFunc := func(sender HandshakingConn, data []byte) {
		defer wg.Done()

		for i := 0; i < times; i++ {
			if i == times/2 {
				wg.Add(1)

				go func() {
					defer wg.Done()

					err := sender.Handshake()
					if err != nil {
						tb.Fatal(err)
					}
				}()
			}

			_, err := sender.Write(data)
			if err != nil {
				tb.Fatal(err)
			}
		}
	}

	recvFunc := func(receiver net.Conn, data []byte) {
		defer wg.Done()

		buf := make([]byte, len(data))
		for i := 0; i < times; i++ {
			n, err := io.ReadFull(receiver, buf)
			if err != nil {
				tb.Fatal(err)
			}

			if !bytes.Equal(buf[:n], data) {
				tb.Fatal(err)
			}
		}
	}

	wg.Add(4)

	go recvFunc(server, data1)
	go sendFunc(client, data1)
	go sendFunc(server, data2)
	go recvFunc(client, data2)
	wg.Wait()
}

// TestStdlibFullDuplexRenegotiation function is used to test full-duplex renegotiation of the standard library.
func TestStdlibFullDuplexRenegotiation(t *testing.T) {
	t.Parallel()
	FullDuplexRenegotiationTest(t, StdlibConstructor)
}

// TestOpenSSLFullDuplexRenegotiation function is used to test full-duplex renegotiation of OpenSSL.
func TestOpenSSLFullDuplexRenegotiation(t *testing.T) {
	t.Parallel()
	FullDuplexRenegotiationTest(t, OpenSSLConstructor)
}

// TestOpenSSLStdlibFullDuplexRenegotiation function is used to test full-duplex renegotiation of OpenSSL and the
// standard library.
func TestOpenSSLStdlibFullDuplexRenegotiation(t *testing.T) {
	t.Parallel()
	FullDuplexRenegotiationTest(t, OpenSSLStdlibConstructor)
}

// TestStdlibOpenSSLFullDuplexRenegotiation function is used to test full-duplex renegotiation of the standard library
// and OpenSSL.
func TestStdlibOpenSSLFullDuplexRenegotiation(t *testing.T) {
	t.Parallel()
	FullDuplexRenegotiationTest(t, StdlibOpenSSLConstructor)
}

func startTLSServer(t *testing.T, sslListener net.Listener, payloadSize int64, loops int, sleep time.Duration) {
	t.Helper()

	for {
		conn, err := sslListener.Accept()
		if err != nil {
			t.Error("failed to accept: ", err)
			continue
		}

		go func() {
			defer func() {
				err = conn.Close()
				if err != nil {
					t.Error("failed to close: ", err)
				}
			}()

			for i := 0; i < loops; i++ {
				_, err := io.Copy(io.Discard, io.LimitReader(conn, payloadSize))
				if err != nil {
					t.Error("failed to read: ", err)
					return
				}

				_, err = io.Copy(conn, io.LimitReader(rand.Reader, payloadSize))
				if err != nil {
					t.Error("failed to write: ", err)
					return
				}
			}

			time.Sleep(sleep)
		}()
	}
}

// LotsOfConns function is used to test the situation of a large number of connections.
func LotsOfConns(t *testing.T, payloadSize int64, loops, clients int,
	sleep time.Duration, newListener func(net.Listener) net.Listener,
	newClient func(net.Conn) (net.Conn, error),
) {
	t.Helper()

	tcpListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	sslListener := newListener(tcpListener)

	go startTLSServer(t, sslListener, payloadSize, loops, sleep)

	// Create multiple client connections
	var wg sync.WaitGroup

	for i := 0; i < clients; i++ {
		tcpClient, err := net.Dial(tcpListener.Addr().Network(),
			tcpListener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		sslClient, err := newClient(tcpClient)
		if err != nil {
			t.Fatal(err)
		}

		wg.Add(1)

		go func(_ int) {
			defer func() {
				err = sslClient.Close()
				if err != nil {
					t.Error("failed to close: ", err)
				}

				wg.Done()
			}()

			for i := 0; i < loops; i++ {
				// Write and read data
				_, err := io.Copy(sslClient, io.LimitReader(rand.Reader,
					payloadSize))
				if err != nil {
					t.Error("failed to write: ", err)
					return
				}

				_, err = io.Copy(io.Discard,
					io.LimitReader(sslClient, payloadSize))
				if err != nil {
					t.Error("failed to read: ", err)
					return
				}
			}

			time.Sleep(sleep)
		}(i)
	}

	wg.Wait()
}

// TestStdlibLotsOfConns function is used to test the situation of a large number of connections of the standard
// library.
func TestStdlibLotsOfConns(t *testing.T) {
	t.Parallel()

	// Load certificate and configure TLS
	tlsCert, err := tls.X509KeyPair([]byte(certBytes), []byte(keyBytes))
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}

	// Execute large number of connections test
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return tls.NewListener(l, tlsConfig)
		}, func(c net.Conn) (net.Conn, error) {
			return tls.Client(c, tlsConfig), nil
		})
}

// TestStdlibTLSv13LotsOfConns function is used to test the situation of a large number of connections of the standard
// library with TLSv1.3.
func TestStdlibTLSv13LotsOfConns(t *testing.T) {
	t.Parallel()

	// Load certificate and configure TLS
	tlsCert, err := tls.X509KeyPair([]byte(certBytes), []byte(keyBytes))
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13

	// Execute large number of connections test
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return tls.NewListener(l, tlsConfig)
		}, func(c net.Conn) (net.Conn, error) {
			return tls.Client(c, tlsConfig), nil
		})
}

// TestOpenSSLLotsOfConns function is used to test the situation of a large number of connections of OpenSSL.
func TestOpenSSLLotsOfConns(t *testing.T) {
	t.Parallel()

	// Create SSL context and configure
	ctx, err := ts.NewCtx()
	if err != nil {
		t.Fatal(err)
	}

	key, err := crypto.LoadPrivateKeyFromPEM([]byte(keyBytes))
	if err != nil {
		t.Fatal(err)
	}

	err = ctx.UsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := crypto.LoadCertificateFromPEM([]byte(certBytes))
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
	// Execute large number of connections test
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return ts.NewListener(l, ctx)
		}, func(c net.Conn) (net.Conn, error) {
			return ts.Client(c, ctx)
		})
}
