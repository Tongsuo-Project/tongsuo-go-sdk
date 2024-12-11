// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm4"
)

func sm4CBCEncrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	block, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create SM4 cipher: ", err)
	}

	cipherText1 := make([]byte, len(plainText))

	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(cipherText1, plainText)

	if !bytes.Equal(cipherText1, cipherText) {
		log.Fatalf("exp:%x got:%x", cipherText, cipherText1)
	}

	fmt.Println("[sm4CBCEncrypt]")
	fmt.Println("Key=", hex.EncodeToString(key))
	fmt.Println("IV=", hex.EncodeToString(iv))
	fmt.Println("plainText=", hex.EncodeToString(plainText))
	fmt.Println("cipherText=", hex.EncodeToString(cipherText))
}

func sm4CBCDecrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	block, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create SM4 cipher: ", err)
	}

	plainText1 := make([]byte, len(cipherText))

	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(plainText1, cipherText)

	if !bytes.Equal(plainText, plainText1) {
		log.Fatalf("exp:%x got:%x", plainText, plainText1)
	}

	fmt.Println("[sm4CBCDecrypt]")
	fmt.Println("Key=", hex.EncodeToString(key))
	fmt.Println("IV=", hex.EncodeToString(iv))
	fmt.Println("cipherText=", hex.EncodeToString(cipherText))
	fmt.Println("plainText=", hex.EncodeToString(plainText))
}

func sm4GCMEncrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")

	block, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create SM4 cipher: ", err)
	}

	stream, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to create GCM: ", err)
	}

	cipherText1 := stream.Seal(nil, iv, plainText, aad)

	if !bytes.Equal(cipherText1, append(cipherText, tag...)) {
		log.Fatalf("exp:%x got:%x", cipherText1, append(cipherText, tag...))
	}

	fmt.Println("[sm4GCMEncrypt]")
	fmt.Println("Key=", hex.EncodeToString(key))
	fmt.Println("IV=", hex.EncodeToString(iv))
	fmt.Println("AAD=", hex.EncodeToString(aad))
	fmt.Println("plainText=", hex.EncodeToString(plainText))
	fmt.Println("cipherText=", hex.EncodeToString(cipherText))
	fmt.Println("tag=", hex.EncodeToString(tag))
}

func sm4GCMDecrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")

	block, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal("failed to create SM4 cipher: ", err)
	}

	stream, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to create GCM: ", err)
	}

	plainText1, err := stream.Open(nil, iv, append(cipherText, tag...), aad)
	if err != nil {
		log.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText1, plainText) {
		log.Fatalf("exp:%x got:%x", plainText1, plainText)
	}

	fmt.Println("[sm4GCMDecrypt]")
	fmt.Println("Key=", hex.EncodeToString(key))
	fmt.Println("IV=", hex.EncodeToString(iv))
	fmt.Println("AAD=", hex.EncodeToString(aad))
	fmt.Println("tag=", hex.EncodeToString(tag))
	fmt.Println("cipherText=", hex.EncodeToString(cipherText))
	fmt.Println("plainText=", hex.EncodeToString(plainText))
}

func main() {
	sm4CBCEncrypt()
	sm4CBCDecrypt()
	sm4GCMEncrypt()
	sm4GCMDecrypt()
}
