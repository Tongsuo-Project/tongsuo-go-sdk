// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"fmt"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

func main() {
	priv, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
	}

	pem, err := priv.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Private Key:\n%s\n", pem)

	pub := priv.Public()

	pem, err = pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public Key:\n%s\n", pem)
}
