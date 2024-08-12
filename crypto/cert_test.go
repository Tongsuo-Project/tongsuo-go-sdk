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

package crypto

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertGenerate(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(key, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCertGenerateSM2(t *testing.T) {
	key, err := GenerateECKey(Sm2Curve)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(key, EVP_SM3); err != nil {
		t.Fatal(err)
	}
}

func TestCAGenerate(t *testing.T) {
	cakey, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}
	ca, err := NewCertificate(info, cakey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.AddExtensions(map[NID]string{
		NID_basic_constraints:      "critical,CA:TRUE",
		NID_key_usage:              "critical,keyCertSign,cRLSign",
		NID_subject_key_identifier: "hash",
		NID_netscape_cert_type:     "sslCA",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign(cakey, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info = &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensions(map[NID]string{
		NID_basic_constraints: "critical,CA:FALSE",
		NID_key_usage:         "keyEncipherment",
		NID_ext_key_usage:     "serverAuth",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(ca); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(cakey, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCAGenerateSM2(t *testing.T) {
	dirName := filepath.Join("test-runs", "TestCAGenerateSM2")
	_, err := os.Stat(dirName)
	if os.IsNotExist(err) {
		// 目录不存在，创建它
		err := os.MkdirAll(dirName, 0755)
		if err != nil {
			t.Logf("创建目录失败: %v\n", err)
		}
	} else if err != nil {
		// 其他错误
		t.Logf("检查目录时发生错误: %v\n", err)
	}

	// Helper function: generate and save key
	generateAndSaveKey := func(filename string) PrivateKey {
		key, err := GenerateECKey(Sm2Curve)
		if err != nil {
			t.Fatal(err)
		}
		pem, err := key.MarshalPKCS8PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		err = SavePEMToFile(pem, filename)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}

	// Helper function: sign and save certificate
	signAndSaveCert := func(cert *Certificate, caKey PrivateKey, filename string) {
		err := cert.Sign(caKey, EVP_SM3)
		if err != nil {
			t.Fatal(err)
		}
		certPem, err := cert.MarshalPEM()
		if err != nil {
			t.Fatal(err)
		}
		err = SavePEMToFile(certPem, filename)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create CA certificate
	caKey, err := GenerateECKey(Sm2Curve)
	if err != nil {
		t.Fatal(err)
	}
	caInfo := CertificateInfo{
		big.NewInt(1),
		0,
		87600 * time.Hour, // 10 years
		"US",
		"Test CA",
		"CA",
	}
	caExtensions := map[NID]string{
		NID_basic_constraints:        "critical,CA:TRUE",
		NID_key_usage:                "critical,digitalSignature,keyCertSign,cRLSign",
		NID_subject_key_identifier:   "hash",
		NID_authority_key_identifier: "keyid:always,issuer",
	}
	ca, err := NewCertificate(&caInfo, caKey)
	if err != nil {
		t.Fatal(err)
	}
	err = ca.AddExtensions(caExtensions)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dirName, "chain-ca.crt")
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
		keyFile := filepath.Join(dirName, info.name+".key")
		key := generateAndSaveKey(keyFile)
		certInfo := CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[NID]string{
			NID_basic_constraints: "critical,CA:FALSE",
			NID_key_usage:         info.keyUsage,
		}
		cert, err := NewCertificate(&certInfo, key)
		if err != nil {
			t.Fatal(err)
		}
		err = cert.AddExtensions(extensions)
		if err != nil {
			t.Fatal(err)
		}
		err = cert.SetIssuer(ca)
		if err != nil {
			t.Fatal(err)
		}
		certFile := filepath.Join(dirName, info.name+".crt")
		signAndSaveCert(cert, caKey, certFile)
	}
}

func TestCertGetNameEntry(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	name, err := cert.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := name.GetEntry(NID_commonName)
	if !ok {
		t.Fatal("no common name")
	}
	if entry != "localhost" {
		t.Fatalf("expected localhost; got %q", entry)
	}
	entry, ok = name.GetEntry(NID_localityName)
	if ok {
		t.Fatal("did not expect a locality name")
	}
	if entry != "" {
		t.Fatalf("entry should be empty; got %q", entry)
	}
}

func TestCertVersion(t *testing.T) {
	key, err := GenerateRSAKey(768)
	if err != nil {
		t.Fatal(err)
	}
	info := &CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}
	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SetVersion(X509_V3); err != nil {
		t.Fatal(err)
	}
	if vers := cert.GetVersion(); vers != X509_V3 {
		t.Fatalf("bad version: %d", vers)
	}
}
