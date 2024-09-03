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
	ts "github.com/tongsuo-project/tongsuo-go-sdk"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"log"
	"net"
	"os"
	"path/filepath"
)

func ReadCertificateFiles(dirPath string) (map[string]crypto.GMDoubleCertKey, error) {
	certFiles := make(map[string]crypto.GMDoubleCertKey)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			domain := file.Name()
			encCertFile := filepath.Join(dirPath, domain, "server_enc.crt")
			encKeyFile := filepath.Join(dirPath, domain, "server_enc.key")
			signCertFile := filepath.Join(dirPath, domain, "server_sign.crt")
			signKeyFile := filepath.Join(dirPath, domain, "server_sign.key")

			certFiles[domain] = crypto.GMDoubleCertKey{
				EncCertFile:  encCertFile,
				SignCertFile: signCertFile,
				EncKeyFile:   encKeyFile,
				SignKeyFile:  signKeyFile,
			}
		}
	}

	return certFiles, nil
}

func handleConn(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

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

func newNTLSServerWithSNI(acceptAddr string, certKeyPairs map[string]crypto.GMDoubleCertKey, cafile string) (net.Listener, error) {

	ctx, err := ts.NewCtxWithVersion(ts.NTLS)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if err := ctx.LoadVerifyLocations(cafile, ""); err != nil {
		log.Println(err)
		return nil, err
	}

	// Set SNI callback
	ctx.SetTLSExtServernameCallback(func(ssl *ts.SSL) ts.SSLTLSExtErr {
		serverName := ssl.GetServername()
		log.Printf("SNI: Client requested hostname: %s\n", serverName)

		if certKeyPair, ok := certKeyPairs[serverName]; ok {
			if err := loadCertAndKeyForSSL(ssl, certKeyPair); err != nil {
				log.Printf("Error loading certificate for %s: %v\n", serverName, err)
				return ts.SSLTLSEXTErrAlertFatal
			}
		} else {
			log.Printf("No certificate found for %s, using default\n", serverName)
			return ts.SSLTLSEXTErrNoAck
		}

		return ts.SSLTLSExtErrOK
	})

	// Load a default certificate and key
	defaultCertKeyPair := certKeyPairs["default"]
	if err := loadCertAndKey(ctx, defaultCertKeyPair); err != nil {
		log.Println(err)
		return nil, err
	}

	// Listen for incoming connections
	lis, err := ts.Listen("tcp", acceptAddr, ctx)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return lis, nil
}

// Load certificate and key for SSL
func loadCertAndKeyForSSL(ssl *ts.SSL, certKeyPair crypto.GMDoubleCertKey) error {
	ctx, err := ts.NewCtx()
	if err != nil {
		return err
	}

	encCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.EncCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptCertificate(encCert)
	if err != nil {
		return err
	}

	signCertPEM, err := crypto.LoadPEMFromFile(certKeyPair.SignCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignCertificate(signCert)
	if err != nil {
		return err
	}

	encKeyPEM, err := os.ReadFile(certKeyPair.EncKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptPrivateKey(encKey)
	if err != nil {
		return err
	}

	signKeyPEM, err := os.ReadFile(certKeyPair.SignKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignPrivateKey(signKey)
	if err != nil {
		return err
	}

	ssl.SetSSLCtx(ctx)

	return nil
}

// Load certificate and key for context
func loadCertAndKey(ctx *ts.Ctx, pair crypto.GMDoubleCertKey) (err error) {
	encCertPEM, err := crypto.LoadPEMFromFile(pair.EncCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encCert, err := crypto.LoadCertificateFromPEM(encCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptCertificate(encCert)
	if err != nil {
		return err
	}

	signCertPEM, err := crypto.LoadPEMFromFile(pair.SignCertFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signCert, err := crypto.LoadCertificateFromPEM(signCertPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignCertificate(signCert)
	if err != nil {
		return err
	}

	encKeyPEM, err := os.ReadFile(pair.EncKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	encKey, err := crypto.LoadPrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseEncryptPrivateKey(encKey)
	if err != nil {
		return err
	}

	signKeyPEM, err := os.ReadFile(pair.SignKeyFile)
	if err != nil {
		log.Println(err)
		return err
	}
	signKey, err := crypto.LoadPrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		log.Println(err)
		return err
	}
	err = ctx.UseSignPrivateKey(signKey)
	if err != nil {
		return err
	}

	return nil

}

func main() {
	signCertFile := ""
	signKeyFile := ""
	encCertFile := ""
	encKeyFile := ""
	caFile := ""
	acceptAddr := ""

	flag.StringVar(&acceptAddr, "accept", "127.0.0.1:4438", "host:port")
	flag.StringVar(&signCertFile, "sign_cert", "test/certs/sm2/server_sign.crt", "sign certificate file")
	flag.StringVar(&signKeyFile, "sign_key", "test/certs/sm2/server_sign.key", "sign private key file")
	flag.StringVar(&encCertFile, "enc_cert", "test/certs/sm2/server_enc.crt", "encrypt certificate file")
	flag.StringVar(&encKeyFile, "enc_key", "test/certs/sm2/server_enc.key", "encrypt private key file")
	flag.StringVar(&caFile, "CAfile", "test/certs/sm2/chain-ca.crt", "CA certificate file")

	flag.Parse()

	certFiles, err := ReadCertificateFiles("test/sni_certs")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	server, err := newNTLSServerWithSNI(acceptAddr, certFiles, caFile)
	if err != nil {
		return
	}
	defer func(server net.Listener) {
		err := server.Close()
		if err != nil {
			log.Println("failed close: ", err)
		}
	}(server)

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Println("failed accept: ", err)
			continue
		}

		go handleConn(conn)
	}
}
