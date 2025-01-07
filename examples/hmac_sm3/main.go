// Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"fmt"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

func main() {
	key := []byte("1234567890123456")

	h, err := crypto.NewHMAC(key, crypto.DigestSM3)
	if err != nil {
		panic(err)
	}

	_, err = h.Write([]byte("hello"))
	if err != nil {
		panic(err)
	}

	_, err = h.Write([]byte(" world"))
	if err != nil {
		panic(err)
	}

	res, err := h.Final()
	if err != nil {
		panic(err)
	}

	fmt.Printf("HMAC-SM3(hello world)=%x\n", res)
}
