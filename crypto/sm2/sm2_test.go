// Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm2_test

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

const sm2Key1 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----
`

const sm2Pubkey1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX
F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==
-----END PUBLIC KEY-----
`

func TestSM2PublicKeyVerifyASN1(t *testing.T) {
	t.Parallel()

	pub, err := crypto.LoadPublicKeyFromPEM([]byte(sm2Pubkey1))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	hexSig := `3046022100ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c402210097b59fd56d41317d490dd300e
7e69d7909a0885414ac3b2c5a24bdfc1588cb55`
	sig, _ := hex.DecodeString(strings.ReplaceAll(hexSig, "\n", ""))

	if sm2.VerifyASN1(pub, data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2PrivateKey2PublicVerifyASN1(t *testing.T) {
	t.Parallel()

	priv, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2Key1))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	hexSig := `3046022100ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c402210097b59fd56d41317d490dd300e
7e69d7909a0885414ac3b2c5a24bdfc1588cb55`
	sig, _ := hex.DecodeString(strings.ReplaceAll(hexSig, "\n", ""))

	if sm2.VerifyASN1(priv.Public(), data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2PrivateKey2PublicVerify(t *testing.T) {
	t.Parallel()

	priv, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2Key1))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	rBytes, _ := hex.DecodeString("ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c4")
	sBytes, _ := hex.DecodeString("97b59fd56d41317d490dd300e7e69d7909a0885414ac3b2c5a24bdfc1588cb55")
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if sm2.Verify(priv.Public(), data, r, s) != nil {
		t.Fatal()
	}
}

func TestSM2VerifySignASN1(t *testing.T) {
	t.Parallel()

	priv, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2Key1))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")

	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if sm2.VerifyASN1(priv.Public(), data, sig) != nil {
		t.Fatal()
	}
}

func TestNewSM2VerifySignASN1(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	data := []byte("hello world")

	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if sm2.VerifyASN1(pub, data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2VerifySign(t *testing.T) {
	t.Parallel()

	priv, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2Key1))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")

	r, s, err := sm2.Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if sm2.Verify(priv.Public(), data, r, s) != nil {
		t.Fatal()
	}
}

func TestNewSM2VerifySign(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	data := []byte("hello world")

	r, s, err := sm2.Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if sm2.Verify(pub, data, r, s) != nil {
		t.Fatal()
	}
}

func TestSM2DecryptEncrypt(t *testing.T) {
	t.Parallel()

	priv, err := crypto.LoadPrivateKeyFromPEM([]byte(sm2Key1))
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	data := []byte("hello world")

	ciphertext, err := sm2.Encrypt(pub, data)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := sm2.Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != string(data) {
		t.Fatal()
	}
}

func TestNewSM2DecryptEncrypt(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	data := []byte("hello world")

	ciphertext, err := sm2.Encrypt(pub, data)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := sm2.Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != string(data) {
		t.Fatal()
	}
}
