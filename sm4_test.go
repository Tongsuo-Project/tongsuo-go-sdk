// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package tongsuogo

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func doEncrypt(mode int, key, iv, plainText, cipherText []byte, t *testing.T) {
	enc, err := NewSM4Encrypter(mode, key, iv)
	if err != nil {
		t.Fatal("failed to create encrypter: ", err)
	}

	enc.SetPadding(false)

	actualCipherText, err := enc.EncryptAll(plainText)
	if err != nil {
		t.Fatal("failed to encrypt: ", err)
	}

	if !bytes.Equal(cipherText, actualCipherText) {
		t.Fatalf("exp:%x got:%x", cipherText, actualCipherText)
	}
}

func doDecrypt(mode int, key, iv, plainText, cipherText []byte, t *testing.T) {
	dec, err := NewSM4Decrypter(mode, key, iv)
	if err != nil {
		t.Fatal("failed to create decrypter: ", err)
	}

	dec.SetPadding(false)

	actualPlainText, err := dec.DecryptAll(cipherText)
	if err != nil {
		t.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText, actualPlainText) {
		t.Fatalf("exp:%x got:%x", plainText, actualPlainText)
	}
}

func doAEADEncrypt(mode int, key, iv, aad, tag, plainText, cipherText []byte, t *testing.T) {
	enc, err := NewSM4Encrypter(mode, key, iv)
	if err != nil {
		t.Fatal("failed to create encrypter: ", err)
	}

	enc.SetTagLen(len(tag))
	enc.SetAAD(aad)

	actualCipherText, err := enc.EncryptAll(plainText)
	if err != nil {
		t.Fatal("failed to encrypt: ", err)
	}

	if !bytes.Equal(cipherText, actualCipherText) {
		t.Fatalf("exp:%x got:%x", cipherText, actualCipherText)
	}

	actualTag, err := enc.GetTag()
	if err != nil {
		t.Fatal("failed to get tag: ", err)
	}

	if !bytes.Equal(tag, actualTag) {
		t.Fatalf("exp:%x got:%x", tag, actualTag)
	}
}

func doAEADDecrypt(mode int, key, iv, aad, tag, plainText, cipherText []byte, t *testing.T) {
	dec, err := NewSM4Decrypter(mode, key, iv)
	if err != nil {
		t.Fatal("failed to create decrypter: ", err)
	}

	dec.SetTag(tag)
	dec.SetAAD(aad)

	actualPlainText, err := dec.DecryptAll(cipherText)
	if err != nil {
		t.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText, actualPlainText) {
		t.Fatalf("exp:%x got:%x", plainText, actualPlainText)
	}
}

func TestSM4ECB(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	doEncrypt(CIPHER_MODE_ECB, key, nil, plainText, cipherText, t)
	doDecrypt(CIPHER_MODE_ECB, key, nil, plainText, cipherText, t)
}

func TestSM4CBC(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	doEncrypt(CIPHER_MODE_CBC, key, iv, plainText, cipherText, t)
	doDecrypt(CIPHER_MODE_CBC, key, iv, plainText, cipherText, t)
}

func TestSM4CFB(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A70569ED258A85A0467CC92AAB393DD978995")

	doEncrypt(CIPHER_MODE_CFB, key, iv, plainText, cipherText, t)
	doDecrypt(CIPHER_MODE_CFB, key, iv, plainText, cipherText, t)
}

func TestSM4OFB(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A7056F2075D28B5235F58D50027E4177D2BCE")

	doEncrypt(CIPHER_MODE_OFB, key, iv, plainText, cipherText, t)
	doDecrypt(CIPHER_MODE_OFB, key, iv, plainText, cipherText, t)
}

func TestSM4CTR(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("C2B4759E78AC3CF43D0852F4E8D5F9FD7256E8A5FCB65A350EE00630912E44492A0B17E1B85B060D0FBA612D8A95831638B361FD5FFACD942F081485A83CA35D")

	doEncrypt(CIPHER_MODE_CTR, key, iv, plainText, cipherText, t)
	doDecrypt(CIPHER_MODE_CTR, key, iv, plainText, cipherText, t)
}

func TestSM4GCM(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D")

	doAEADEncrypt(CIPHER_MODE_GCM, key, iv, aad, tag, plainText, cipherText, t)
	doAEADDecrypt(CIPHER_MODE_GCM, key, iv, aad, tag, plainText, cipherText, t)
}

func TestSM4CCM(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("16842D4FA186F56AB33256971FA110F4")
	plainText, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
	cipherText, _ := hex.DecodeString("48AF93501FA62ADBCD414CCE6034D895DDA1BF8F132F042098661572E7483094FD12E518CE062C98ACEE28D95DF4416BED31A2F04476C18BB40C84A74B97DC5B")

	doAEADEncrypt(CIPHER_MODE_CCM, key, iv, aad, tag, plainText, cipherText, t)
	doAEADDecrypt(CIPHER_MODE_CCM, key, iv, aad, tag, plainText, cipherText, t)
}
