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
	"fmt"
	"io"
	"math/big"
	"os"
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
	// 辅助函数：统一错误处理
	check := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	// 辅助函数：生成密钥并保存
	generateAndSaveKey := func(filename string) PrivateKey {
		key, err := GenerateECKey(Sm2Curve)
		check(err)
		pem, err := key.MarshalPKCS8PrivateKeyPEM() // 使用 PKCS8 格式
		check(err)
		check(SavePEMToFile(pem, filename))
		return key
	}

	// 辅助函数：创建证书
	createCertificate := func(info CertificateInfo, key PrivateKey, isCA bool, extensions map[NID]string) *Certificate {
		cert, err := NewCertificate(&info, key)
		check(err)
		check(cert.AddExtensions(extensions))
		return cert
	}

	// 辅助函数：签名并保存证书
	signAndSaveCert := func(cert *Certificate, caKey PrivateKey, filename string) {
		check(cert.Sign(caKey, EVP_SM3))
		certPem, err := cert.MarshalPEM()
		check(err)
		check(SavePEMToFile(certPem, filename))
	}

	// 创建 CA 证书
	caKey := generateAndSaveKey("./../test/certs/sm2/ca.key")
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
	ca := createCertificate(caInfo, caKey, true, caExtensions)
	if err := ca.SetVersion(X509_V3); err != nil {
		t.Fatal(err)
	}
	signAndSaveCert(ca, caKey, "./../test/certs/sm2/chain-ca1.crt")

	// 定义其他证书信息
	certInfos := []struct {
		name        string
		keyUsage    string
		extKeyUsage string
	}{
		{"server_enc", "keyAgreement, keyEncipherment, dataEncipherment", "serverAuth"},
		{"server_sign", "nonRepudiation, digitalSignature", "emailProtection"},
		{"client_sign", "nonRepudiation, digitalSignature", "emailProtection"},
		{"client_enc", "keyAgreement, keyEncipherment, dataEncipherment", "serverAuth"},
	}

	// 创建其他证书
	for _, info := range certInfos {
		key := generateAndSaveKey(fmt.Sprintf("./../test/certs/sm2/%s1.key", info.name))
		certInfo := CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[NID]string{
			NID_basic_constraints:        "critical,CA:FALSE",
			NID_key_usage:                info.keyUsage,
			NID_ext_key_usage:            info.extKeyUsage,
			NID_subject_key_identifier:   "hash",
			NID_authority_key_identifier: "keyid:always,issuer",
		}
		cert := createCertificate(certInfo, key, false, extensions)
		if err := cert.SetVersion(X509_V3); err != nil {
			t.Fatal(err)
		}
		check(cert.SetIssuer(ca))
		signAndSaveCert(cert, caKey, fmt.Sprintf("./../test/certs/sm2/%s1.crt", info.name))
	}
}

func SavePEMToFile(pemBlock []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(pemBlock)
	if err != nil {
		return err
	}

	return nil
}

// LoadPEMFromFile loads a PEM file and returns the []byte format.
func LoadPEMFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemBlock, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return pemBlock, nil
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
