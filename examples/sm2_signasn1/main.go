// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

var sm2_key1 = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----
`)

func main() {
	data := []byte("hello world")
	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		panic(err)
	}

	// Sign data
	signature, err := sm2.SignASN1(priv, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("SM2withSM3(%s)=%s\n", data, hex.EncodeToString(signature))

	pub := priv.Public()

	// Verify signature
	if sm2.VerifyASN1(pub, data, signature) != nil {
		panic("Verification failure")
	}

	fmt.Println("Verification OK")
}
