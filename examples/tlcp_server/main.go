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
	"log"
	"net"
	"os"

	ts "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Read incoming data into buffer
	req, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading incoming data: %v", err)
		return
	}

	ntls := conn.(*ts.Conn)
	ver, err := ntls.GetVersion()
	if err != nil {
		log.Println("failed get version: ", err)
		return
	}

	cipher, err := ntls.CurrentCipher()
	if err != nil {
		log.Println("failed get cipher: ", err)
		return
	}

	log.Println("New connection: " + ver + ", cipher=" + cipher)
	log.Println("Recv:\n" + req)

	// Send a response back to the client
	if _, err = conn.Write([]byte(req + "\n")); err != nil {
		log.Printf("Unable to send response: %v", err)
		return
	}

	log.Println("Sent:\n" + req)
	log.Println("Close connection")
}

func newNTLSServer(acceptAddr string, signCertFile string, signKeyFile string, encCertFile string, encKeyFile string, cafile string) (net.Listener, error) {
	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.LoadVerifyLocations(cafile, ""); err != nil {
		log.Println(err)
		return nil, err
	}

	encCertPEM, err := os.ReadFile(encCertFile)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	signCertPEM, err := os.ReadFile(signCertFile)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.UseEncryptCertificate(encCert); err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.UseSignCertificate(signCert); err != nil {
		log.Println(err)
		return nil, err
	}

	encKeyPEM, err := os.ReadFile(encKeyFile)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	signKeyPEM, err := os.ReadFile(signKeyFile)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.UseEncryptPrivateKey(encKey); err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.UseSignPrivateKey(signKey); err != nil {
		log.Println(err)
		return nil, err
	}

	lis, err := ts.Listen("tcp", acceptAddr, ctx)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return lis, nil
}

func main() {
	signCertFile := ""
	signKeyFile := ""
	encCertFile := ""
	encKeyFile := ""
	caFile := ""
	acceptAddr := ""

	flag.StringVar(&acceptAddr, "accept", "127.0.0.1:443", "host:port")
	flag.StringVar(&signCertFile, "sign_cert", "", "sign certificate file")
	flag.StringVar(&signKeyFile, "sign_key", "", "sign private key file")
	flag.StringVar(&encCertFile, "enc_cert", "", "encrypt certificate file")
	flag.StringVar(&encKeyFile, "enc_key", "", "encrypt private key file")
	flag.StringVar(&caFile, "CAfile", "", "CA certificate file")

	flag.Parse()

	server, err := newNTLSServer(acceptAddr, signCertFile, signKeyFile, encCertFile, encKeyFile, caFile)

	if err != nil {
		return
	}
	defer server.Close()

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Println("failed accept: ", err)
			continue
		}

		go handleConn(conn)
	}
}
