package main

import (
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"math/big"
	"path/filepath"
	"time"
)

const genPath = "./examples/cert_gen/"

func main() {
	// Helper function: unified error handling
	check := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	// Helper function: generate and save key
	generateAndSaveKey := func(filename string) crypto.PrivateKey {
		key, err := crypto.GenerateECKey(crypto.Sm2Curve)
		check(err)
		pem, err := key.MarshalPKCS8PrivateKeyPEM()
		check(err)
		check(crypto.SavePEMToFile(pem, filename))
		return key
	}

	// Helper function: create certificate
	createCertificate := func(info crypto.CertificateInfo, key crypto.PrivateKey, extensions map[crypto.NID]string) *crypto.Certificate {
		cert, err := crypto.NewCertificate(&info, key)
		check(err)
		check(cert.AddExtensions(extensions))
		return cert
	}

	// Helper function: sign and save certificate
	signAndSaveCert := func(cert *crypto.Certificate, caKey crypto.PrivateKey, filename string) {
		check(cert.Sign(caKey, crypto.EVP_SM3))
		certPem, err := cert.MarshalPEM()
		check(err)
		check(crypto.SavePEMToFile(certPem, filename))
	}

	// Create CA certificate
	caKey, err := crypto.GenerateECKey(crypto.Sm2Curve)
	check(err)
	caInfo := crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Expires:      87600 * time.Hour, // 10 years
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	caExtensions := map[crypto.NID]string{
		crypto.NID_basic_constraints:        "critical,CA:TRUE",
		crypto.NID_key_usage:                "critical,digitalSignature,keyCertSign,cRLSign",
		crypto.NID_subject_key_identifier:   "hash",
		crypto.NID_authority_key_identifier: "keyid:always,issuer:always",
	}
	ca := createCertificate(caInfo, caKey, caExtensions)
	caFile := filepath.Join(genPath, "chain-ca.crt")
	signAndSaveCert(ca, caKey, caFile)

	// Define additional certificate information
	certInfos := []struct {
		name     string
		keyUsage string
	}{
		{"server_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
		{"server_sign", "nonRepudiation, digitalSignature"},
		{"client_sign", "nonRepudiation, digitalSignature"},
		{"client_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
	}

	// Create additional certificates
	for _, info := range certInfos {
		keyFile := filepath.Join(genPath, info.name+".key")
		key := generateAndSaveKey(keyFile)
		certInfo := crypto.CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[crypto.NID]string{
			crypto.NID_basic_constraints: "critical,CA:FALSE",
			crypto.NID_key_usage:         info.keyUsage,
		}
		cert := createCertificate(certInfo, key, extensions)

		check(cert.SetIssuer(ca))
		certFile := filepath.Join(genPath, info.name+".crt")
		signAndSaveCert(cert, caKey, certFile)
	}
}
