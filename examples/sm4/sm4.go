// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package main

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm4"
)

func sm4CBCEncrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	enc, err := sm4.NewSM4Encrypter(crypto.CIPHER_MODE_CBC, key, iv)
	if err != nil {
		log.Fatal("failed to create encrypter: ", err)
	}

	enc.SetPadding(false)

	actualCipherText, err := enc.EncryptAll(plainText)
	if err != nil {
		log.Fatal("failed to encrypt: ", err)
	}

	if !bytes.Equal(cipherText, actualCipherText) {
		log.Fatalf("exp:%x got:%x", cipherText, actualCipherText)
	}
}

func sm4CBCDecrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	enc, err := sm4.NewSM4Decrypter(crypto.CIPHER_MODE_CBC, key, iv)
	if err != nil {
		log.Fatal("failed to create decrypter: ", err)
	}

	enc.SetPadding(false)

	actualPlainText, err := enc.DecryptAll(cipherText)
	if err != nil {
		log.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText, actualPlainText) {
		log.Fatalf("exp:%x got:%x", plainText, actualPlainText)
	}
}

func sm4GCMEncrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")

	enc, err := sm4.NewSM4Encrypter(crypto.CIPHER_MODE_GCM, key, iv)
	if err != nil {
		log.Fatal("failed to create encrypter: ", err)
	}

	enc.SetAAD(aad)

	actualCipherText, err := enc.EncryptAll(plainText)
	if err != nil {
		log.Fatal("failed to encrypt: ", err)
	}

	if !bytes.Equal(cipherText, actualCipherText) {
		log.Fatalf("exp:%x got:%x", cipherText, actualCipherText)
	}

	actualTag, err := enc.GetTag()
	if err != nil {
		log.Fatal("failed to get tag: ", err)
	}

	if !bytes.Equal(tag, actualTag) {
		log.Fatalf("exp:%x got:%x", tag, actualTag)
	}
}

func sm4GCMDecrypt() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")

	dec, err := sm4.NewSM4Decrypter(crypto.CIPHER_MODE_GCM, key, iv)
	if err != nil {
		log.Fatal("failed to create decrypter: ", err)
	}

	dec.SetTag(tag)
	dec.SetAAD(aad)

	actualPlainText, err := dec.DecryptAll(cipherText)
	if err != nil {
		log.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText, actualPlainText) {
		log.Fatalf("exp:%x got:%x", plainText, actualPlainText)
	}
}

func main() {
	sm4CBCEncrypt()
	sm4CBCDecrypt()
	sm4GCMEncrypt()
	sm4GCMDecrypt()
}
