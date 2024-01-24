// Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm2

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

var sm2_key1 = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----
`)

var sm2_pubkey1 = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOToq2eJ+Q6yqq4WhnTuFWR4UQGFX
F1rd03v3f/DK+e03/POotPVcA4UjJh/KZjav5qevoqFIKmBvXLOhiy4qHg==
-----END PUBLIC KEY-----
`)

func TestSM2PublicKeyVerifyASN1(t *testing.T) {
	pub, err := crypto.LoadPublicKeyFromPEM(sm2_pubkey1)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	sig, _ := hex.DecodeString("3046022100ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c402210097b59fd56d41317d490dd300e7e69d7909a0885414ac3b2c5a24bdfc1588cb55")

	if VerifyASN1(pub, data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2PrivateKey2PublicVerifyASN1(t *testing.T) {
	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	sig, _ := hex.DecodeString("3046022100ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c402210097b59fd56d41317d490dd300e7e69d7909a0885414ac3b2c5a24bdfc1588cb55")
	if VerifyASN1(priv.Public(), data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2PrivateKey2PublicVerify(t *testing.T) {
	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	rBytes, _ := hex.DecodeString("ba37b776135afbf5bf36b21f4a65889bcd0037092be47f6429f877790b8cb9c4")
	sBytes, _ := hex.DecodeString("97b59fd56d41317d490dd300e7e69d7909a0885414ac3b2c5a24bdfc1588cb55")
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if Verify(priv.Public(), data, r, s) != nil {
		t.Fatal()
	}
}

func TestSM2VerifySignASN1(t *testing.T) {
	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	sig, err := SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if VerifyASN1(priv.Public(), data, sig) != nil {
		t.Fatal()
	}
}

func TestNewSM2VerifySignASN1(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()

	data := []byte("hello world")
	sig, err := SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if VerifyASN1(pub, data, sig) != nil {
		t.Fatal()
	}
}

func TestSM2VerifySign(t *testing.T) {
	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	r, s, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if Verify(priv.Public(), data, r, s) != nil {
		t.Fatal()
	}
}

func TestNewSM2VerifySign(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	data := []byte("hello world")
	r, s, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if Verify(pub, data, r, s) != nil {
		t.Fatal()
	}
}
