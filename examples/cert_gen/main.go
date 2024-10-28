package main

import (
	"math/big"
	"path/filepath"
	"time"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const genPath = "./examples/cert_gen/"

func main() {
	// Helper function: generate and save key
	generateAndSaveKey := func(filename string) crypto.PrivateKey {
		key, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			panic(err)
		}

		pem, err := key.MarshalPKCS8PrivateKeyPEM()
		if err != nil {
			panic(err)
		}

		err = crypto.SavePEMToFile(pem, filename)
		if err != nil {
			panic(err)
		}

		return key
	}

	// Helper function: create certificate
	createCertificate := func(info crypto.CertificateInfo, key crypto.PrivateKey, extensions map[crypto.NID]string) *crypto.Certificate {
		cert, err := crypto.NewCertificate(&info, key)
		if err != nil {
			panic(err)
		}

		err = cert.AddExtensions(extensions)
		if err != nil {
			panic(err)
		}

		return cert
	}

	// Helper function: sign and save certificate
	signAndSaveCert := func(cert *crypto.Certificate, caKey crypto.PrivateKey, filename string) {
		err := cert.Sign(caKey, crypto.MDSM3)
		if err != nil {
			panic(err)
		}

		certPem, err := cert.MarshalPEM()
		if err != nil {
			panic(err)
		}

		err = crypto.SavePEMToFile(certPem, filename)
		if err != nil {
			panic(err)
		}
	}

	// Create CA certificate
	caKey, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		panic(err)
	}

	caInfo := crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Expires:      87600 * time.Hour, // 10 years
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	caExtensions := map[crypto.NID]string{
		crypto.NidBasicConstraints:       "critical,CA:TRUE",
		crypto.NidKeyUsage:               "critical,digitalSignature,keyCertSign,cRLSign",
		crypto.NidSubjectKeyIdentifier:   "hash",
		crypto.NidAuthorityKeyIdentifier: "keyid:always,issuer",
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
			crypto.NidBasicConstraints: "critical,CA:FALSE",
			crypto.NidKeyUsage:         info.keyUsage,
		}
		cert := createCertificate(certInfo, key, extensions)

		err = cert.SetIssuer(ca)
		if err != nil {
			panic(err)
		}

		certFile := filepath.Join(genPath, info.name+".crt")
		signAndSaveCert(cert, caKey, certFile)
	}
}
