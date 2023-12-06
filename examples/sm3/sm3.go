// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"fmt"
	"log"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm3"
)

func main() {
	msg := "hello world"
	fmt.Printf("%x\n", sm3.SM3Sum([]byte(msg)))

	h, err := sm3.New()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := h.Write([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	if _, err := h.Write([]byte(" world")); err != nil {
		log.Fatal(err)
	}

	var res [sm3.SM3_DIGEST_LENGTH]byte

	fmt.Printf("%x\n", h.Sum(res[:0]))
}
