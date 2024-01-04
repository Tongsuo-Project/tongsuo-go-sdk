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

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

func main() {
	data := []byte("hello world")
	sm2Key, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
	}

	pem, err := sm2Key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Private Key:\n%s\n", pem)

	// Sign data
	signature, err := sm2Key.SignASN1(data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("SM2withSM3(%s)=%s\n", data, hex.EncodeToString(signature))

	// Verify signature
	if sm2Key.VerifyASN1(data, signature) != true {
		panic("Verification failure")
	}

	r, s, err := sm2Key.Sign(data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("r=%s\n", hex.EncodeToString(r.Bytes()))
	fmt.Printf("s=%s\n", hex.EncodeToString(s.Bytes()))

	if sm2Key.Verify(data, r, s) != true {
		panic("Verification failure")
	}

	fmt.Println("Verification OK")
}
