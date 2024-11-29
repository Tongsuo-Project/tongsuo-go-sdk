// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm4_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm4"
)

const hexPlainText1 = `AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFE
EEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA`

func TestSM4ECBWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal("failed to create SM4 cipher: ", err)
	}

	cipherText1 := make([]byte, len(plainText))

	for i := 0; i < len(plainText); i += block.BlockSize() {
		block.Encrypt(cipherText1[i:i+block.BlockSize()], plainText[i:i+block.BlockSize()])
	}

	if !bytes.Equal(cipherText1, cipherText) {
		t.Fatalf("exp:%x got:%x", cipherText, cipherText1)
	}

	plainText1 := make([]byte, len(cipherText1))

	for i := 0; i < len(cipherText1); i += block.BlockSize() {
		block.Decrypt(plainText1[i:i+block.BlockSize()], cipherText1[i:i+block.BlockSize()])
	}

	if !bytes.Equal(plainText, plainText1) {
		t.Fatalf("exp:%x got:%x", plainText, plainText1)
	}
}

func testCryptWithCipherBlock(t *testing.T, mode string, key, iv, plainText, cipherText []byte) {
	t.Helper()

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal("failed to create SM4 cipher: ", err)
	}

	cipherText1 := make([]byte, len(plainText))

	switch mode {
	case "CBC":
		stream := cipher.NewCBCEncrypter(block, iv)
		stream.CryptBlocks(cipherText1, plainText)
	case "CFB":
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherText1, plainText)
	case "OFB":
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(cipherText1, plainText)
	case "CTR":
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(cipherText1, plainText)
	}

	if !bytes.Equal(cipherText1, cipherText) {
		t.Fatalf("exp:%x got:%x", cipherText, cipherText1)
	}

	plainText1 := make([]byte, len(plainText))

	switch mode {
	case "CBC":
		stream := cipher.NewCBCDecrypter(block, iv)
		stream.CryptBlocks(plainText1, cipherText1)
	case "CFB":
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(plainText1, cipherText1)
	case "OFB":
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(plainText1, cipherText1)
	case "CTR":
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(plainText1, cipherText1)
	}

	if !bytes.Equal(plainText, plainText1) {
		t.Fatalf("exp:%x got:%x", plainText, plainText1)
	}
}

func TestSM4CBCWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	testCryptWithCipherBlock(t, "CBC", key, iv, plainText, cipherText)
}

func TestSM4CFBWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A70569ED258A85A0467CC92AAB393DD978995")

	testCryptWithCipherBlock(t, "CFB", key, iv, plainText, cipherText)
}

func TestSM4OFBWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A7056F2075D28B5235F58D50027E4177D2BCE")

	testCryptWithCipherBlock(t, "OFB", key, iv, plainText, cipherText)
}

func TestSM4CTRWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	hexCipherText := `C2B4759E78AC3CF43D0852F4E8D5F9FD7256E8A5FCB65A350EE00630912E44492A0B17E1B85B060D0FBA612D8A95831638
B361FD5FFACD942F081485A83CA35D`
	plainText, _ := hex.DecodeString(strings.ReplaceAll(hexPlainText1, "\n", ""))
	cipherText, _ := hex.DecodeString(strings.ReplaceAll(hexCipherText, "\n", ""))

	testCryptWithCipherBlock(t, "CTR", key, iv, plainText, cipherText)
}

func TestSM4GCMWithCipherBlock(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	hexCipherText := `17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A5
6834CBCF98C397B4024A2691233B8D`
	plainText, _ := hex.DecodeString(strings.ReplaceAll(hexPlainText1, "\n", ""))
	cipherText, _ := hex.DecodeString(strings.ReplaceAll(hexCipherText, "\n", ""))

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal("failed to create SM4 cipher: ", err)
	}

	stream, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("failed to create GCM: ", err)
	}

	cipherText1 := stream.Seal(nil, iv, plainText, aad)

	if !bytes.Equal(cipherText1, append(cipherText, tag...)) {
		t.Fatalf("exp:%x got:%x", cipherText1, append(cipherText, tag...))
	}

	stream2, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("failed to create GCM: ", err)
	}

	plainText1, err := stream2.Open(nil, iv, cipherText1, aad)
	if err != nil {
		t.Fatal("failed to decrypt: ", err)
	}

	if !bytes.Equal(plainText1, plainText) {
		t.Fatalf("exp:%x got:%x", plainText1, plainText)
	}
}

func doEncrypt(t *testing.T, mode int, key, iv, plainText, cipherText []byte) {
	t.Helper()

	enc, err := sm4.NewEncrypter(mode, key, iv)
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

func doDecrypt(t *testing.T, mode int, key, iv, plainText, cipherText []byte) {
	t.Helper()

	dec, err := sm4.NewDecrypter(mode, key, iv)
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

func doAEADEncrypt(t *testing.T, mode int, key, iv, aad, tag, plainText, cipherText []byte) {
	t.Helper()

	enc, err := sm4.NewEncrypter(mode, key, iv)
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

func doAEADDecrypt(t *testing.T, mode int, key, iv, aad, tag, plainText, cipherText []byte) {
	t.Helper()

	dec, err := sm4.NewDecrypter(mode, key, iv)
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
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	doEncrypt(t, crypto.CipherModeECB, key, nil, plainText, cipherText)
	doDecrypt(t, crypto.CipherModeECB, key, nil, plainText, cipherText)
}

func TestSM4CBC(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	doEncrypt(t, crypto.CipherModeCBC, key, iv, plainText, cipherText)
	doDecrypt(t, crypto.CipherModeCBC, key, iv, plainText, cipherText)
}

func TestSM4CFB(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A70569ED258A85A0467CC92AAB393DD978995")

	doEncrypt(t, crypto.CipherModeCFB, key, iv, plainText, cipherText)
	doDecrypt(t, crypto.CipherModeCFB, key, iv, plainText, cipherText)
}

func TestSM4OFB(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plainText, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	cipherText, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A7056F2075D28B5235F58D50027E4177D2BCE")

	doEncrypt(t, crypto.CipherModeOFB, key, iv, plainText, cipherText)
	doDecrypt(t, crypto.CipherModeOFB, key, iv, plainText, cipherText)
}

func TestSM4CTR(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	hexCipherText := `C2B4759E78AC3CF43D0852F4E8D5F9FD7256E8A5FCB65A350EE00630912E44492A0B17E1B85B060D0FBA612D8A95831638
B361FD5FFACD942F081485A83CA35D`
	plainText, _ := hex.DecodeString(strings.ReplaceAll(hexPlainText1, "\n", ""))
	cipherText, _ := hex.DecodeString(strings.ReplaceAll(hexCipherText, "\n", ""))

	doEncrypt(t, crypto.CipherModeCTR, key, iv, plainText, cipherText)
	doDecrypt(t, crypto.CipherModeCTR, key, iv, plainText, cipherText)
}

func TestSM4GCM(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("83DE3541E4C2B58177E065A9BF7B62EC")
	hexCipherText := `17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A5
6834CBCF98C397B4024A2691233B8D`
	plainText, _ := hex.DecodeString(strings.ReplaceAll(hexPlainText1, "\n", ""))
	cipherText, _ := hex.DecodeString(strings.ReplaceAll(hexCipherText, "\n", ""))

	doAEADEncrypt(t, crypto.CipherModeGCM, key, iv, aad, tag, plainText, cipherText)
	doAEADDecrypt(t, crypto.CipherModeGCM, key, iv, aad, tag, plainText, cipherText)
}

func TestSM4CCM(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00001234567800000000ABCD")
	aad, _ := hex.DecodeString("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
	tag, _ := hex.DecodeString("16842D4FA186F56AB33256971FA110F4")
	hexCipherText := `48AF93501FA62ADBCD414CCE6034D895DDA1BF8F132F042098661572E7483094FD12E518CE062C98ACEE28D95DF4416BED
31A2F04476C18BB40C84A74B97DC5B`
	plainText, _ := hex.DecodeString(strings.ReplaceAll(hexPlainText1, "\n", ""))
	cipherText, _ := hex.DecodeString(strings.ReplaceAll(hexCipherText, "\n", ""))

	doAEADEncrypt(t, crypto.CipherModeCCM, key, iv, aad, tag, plainText, cipherText)
	doAEADDecrypt(t, crypto.CipherModeCCM, key, iv, aad, tag, plainText, cipherText)
}
