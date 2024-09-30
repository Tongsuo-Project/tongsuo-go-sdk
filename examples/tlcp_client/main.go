// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	ts "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

func main() {
	cipherSuite := ""
	signCertFile := ""
	signKeyFile := ""
	encCertFile := ""
	encKeyFile := ""
	caFile := ""
	connAddr := ""
	serverName := ""
	alpnProtocols := []string{"h2", "http/1.1"}
	tlsVersion := ""
	flag.StringVar(&connAddr, "conn", "127.0.0.1:4438", "host:port")
	flag.StringVar(&cipherSuite, "cipher", "ECC-SM2-SM4-CBC-SM3", "cipher suite")
	flag.StringVar(&signCertFile, "sign_cert", "test/certs/sm2/client_sign.crt", "sign certificate file")
	flag.StringVar(&signKeyFile, "sign_key", "test/certs/sm2/client_sign.key", "sign private key file")
	flag.StringVar(&encCertFile, "enc_cert", "test/certs/sm2/client_enc.crt", "encrypt certificate file")
	flag.StringVar(&encKeyFile, "enc_key", "test/certs/sm2/client_enc.key", "encrypt private key file")
	flag.StringVar(&caFile, "CAfile", "test/certs/sm2/chain-ca.crt", "CA certificate file")
	flag.StringVar(&serverName, "servername", "", "server name")
	flag.Var((*stringSlice)(&alpnProtocols), "alpn", "ALPN protocols")
	flag.StringVar(&tlsVersion, "tls_version", "NTLS", "TLS version")
	flag.Parse()

	var version ts.SSLVersion
	switch tlsVersion {
	case "TLSv1.3":
		version = ts.TLSv1_3
	case "TLSv1.2":
		version = ts.TLSv1_2
	case "TLSv1.1":
		version = ts.TLSv1_1
	case "TLSv1":
		version = ts.TLSv1
	case "NTLS":
		version = ts.NTLS
	default:
		version = ts.TLSv1_3
	}
	ctx, err := ts.NewCtxWithVersion(version)
	if err != nil {
		panic("NewCtxWithVersion failed: " + err.Error())
	}

	if err := ctx.SetClientALPNProtos(alpnProtocols); err != nil {
		panic(err)
	}

	if err := ctx.SetCipherList(cipherSuite); err != nil {
		panic(err)
	}

	if signCertFile != "" {
		signCertPEM, err := os.ReadFile(signCertFile)
		if err != nil {
			panic(err)
		}
		signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
		if err != nil {
			panic(err)
		}

		if err := ctx.UseSignCertificate(signCert); err != nil {
			panic(err)
		}
	}

	if signKeyFile != "" {
		signKeyPEM, err := os.ReadFile(signKeyFile)
		if err != nil {
			panic(err)
		}
		signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
		if err != nil {
			panic(err)
		}

		if err := ctx.UseSignPrivateKey(signKey); err != nil {
			panic(err)
		}
	}

	if encCertFile != "" {
		encCertPEM, err := os.ReadFile(encCertFile)
		if err != nil {
			panic(err)
		}
		encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
		if err != nil {
			panic(err)
		}

		if err := ctx.UseEncryptCertificate(encCert); err != nil {
			panic(err)
		}
	}

	if encKeyFile != "" {
		encKeyPEM, err := os.ReadFile(encKeyFile)
		if err != nil {
			panic(err)
		}

		encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
		if err != nil {
			panic(err)
		}

		if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
			panic(err)
		}
	}

	if caFile != "" {
		if err := ctx.LoadVerifyLocations(caFile, ""); err != nil {
			panic(err)
		}
	}

	conn, err := ts.Dial("tcp", connAddr, ctx, ts.InsecureSkipHostVerification, serverName)
	if err != nil {
		panic("connected failed" + err.Error())
	}
	defer conn.Close()

	// Get the negotiated ALPN protocol
	negotiatedProto, err := conn.GetALPNNegotiated()
	if err != nil {
		fmt.Println("Failed to get negotiated ALPN protocol:", err)
	} else {
		fmt.Println("Negotiated ALPN protocol:", negotiatedProto)
	}

	cipher, err := conn.CurrentCipher()
	if err != nil {
		panic(err)
	}

	ver, err := conn.GetVersion()
	if err != nil {
		panic(err)
	}

	fmt.Println("New connection: " + ver + ", cipher=" + cipher)

	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')

	request := text + "\n"
	fmt.Println(">>>\n" + request)
	if _, err := conn.Write([]byte(request)); err != nil {
		panic(err)
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("read error:", err)
		return
	}

	fmt.Println("<<<\n" + string(buffer[:n]))

	return
}

// Define a custom type to handle string slices in command line flags
type stringSlice []string

// String method returns the string representation of the stringSlice
func (s *stringSlice) String() string {
	return fmt.Sprintf("%v", *s)
}

// Set method splits the input string by commas and assigns the result to the stringSlice
func (s *stringSlice) Set(value string) error {
	*s = strings.Split(value, ",")
	return nil
}
