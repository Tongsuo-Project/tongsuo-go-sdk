// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package tongsuogo

// #include "shim.h"
import "C"

import (
	"bytes"
	"errors"
	"fmt"
)

type SM4Encrypter interface {
	EncryptionCipherCtx
	SetPadding(pad bool)
	EncryptAll(input []byte) ([]byte, error)
	SetAAD([]byte)
	SetTagLen(int)
	GetTag() ([]byte, error)
}

type SM4Decrypter interface {
	DecryptionCipherCtx
	SetPadding(pad bool)
	DecryptAll(input []byte) ([]byte, error)
	SetAAD([]byte)
	SetTag([]byte)
}

type sm4Encrypter struct {
	*encryptionCipherCtx
	key    []byte
	iv     []byte
	aad    []byte
	tagLen int
}

type sm4Decrypter struct {
	*decryptionCipherCtx
	key []byte
	iv  []byte
	aad []byte
	tag []byte
}

func getSM4Cipher(mode int) (*Cipher, error) {
	var cipher *Cipher
	var err error

	switch mode {
	case CIPHER_MODE_ECB:
		cipher, err = GetCipherByName("SM4-ECB")
	case CIPHER_MODE_CBC:
		cipher, err = GetCipherByName("SM4-CBC")
	case CIPHER_MODE_CFB:
		cipher, err = GetCipherByName("SM4-CFB")
	case CIPHER_MODE_OFB:
		cipher, err = GetCipherByName("SM4-OFB")
	case CIPHER_MODE_CTR:
		cipher, err = GetCipherByName("SM4-CTR")
	case CIPHER_MODE_GCM:
		cipher, err = GetCipherByName("SM4-GCM")
	case CIPHER_MODE_CCM:
		cipher, err = GetCipherByName("SM4-CCM")
	default:
		return nil, errors.New("unsupported sm4 mode")
	}

	return cipher, err
}

func NewSM4Decrypter(mode int, key []byte, iv []byte) (SM4Decrypter, error) {
	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	eCtx, err := newDecryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption cipher ctx %s", err)
	}

	if len(iv) > 0 {
		if mode == CIPHER_MODE_GCM || mode == CIPHER_MODE_CCM {
			err := eCtx.cipherCtx.setCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("could not set IV len to %d: %s", len(iv), err)
			}
		}
	}

	return &sm4Decrypter{decryptionCipherCtx: eCtx, key: key, iv: iv}, nil
}

func (ctx *sm4Decrypter) SetPadding(pad bool) {
	ctx.decryptionCipherCtx.SetPadding(pad)
}

func NewSM4Encrypter(mode int, key []byte, iv []byte) (SM4Encrypter, error) {
	var tagLen int

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	if mode == CIPHER_MODE_GCM {
		tagLen = 16
	}
	if mode == CIPHER_MODE_CCM {
		tagLen = 12
	}

	eCtx, err := newEncryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher ctx %s", err)
	}

	if len(iv) > 0 {
		if mode == CIPHER_MODE_GCM || mode == CIPHER_MODE_CCM {
			err := eCtx.cipherCtx.setCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("could not set IV len to %d: %s", len(iv), err)
			}
		}
	}

	return &sm4Encrypter{encryptionCipherCtx: eCtx, tagLen: tagLen, key: key, iv: iv}, nil
}

func (ctx *sm4Encrypter) GetTag() ([]byte, error) {
	return ctx.getCtrlBytes(C.EVP_CTRL_AEAD_GET_TAG, ctx.tagLen, ctx.tagLen)
}

func (ctx *sm4Encrypter) SetTagLen(len int) {
	ctx.tagLen = len
}

func (ctx *sm4Encrypter) SetPadding(pad bool) {
	ctx.encryptionCipherCtx.cipherCtx.SetPadding(pad)
}

func (ctx *sm4Encrypter) SetAAD(aad []byte) {
	ctx.aad = aad
}

func (ctx *sm4Decrypter) SetAAD(aad []byte) {
	ctx.aad = aad
}

func (ctx *sm4Decrypter) SetTag(tag []byte) {
	ctx.tag = tag
}

func (ctx *sm4Decrypter) DecryptAll(src []byte) ([]byte, error) {
	if ctx.tag != nil {
		err := ctx.setCtrlBytes(C.EVP_CTRL_AEAD_SET_TAG, len(ctx.tag), ctx.tag)
		if err != nil {
			return nil, err
		}
	}

	err := ctx.cipherCtx.applyKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv:%s", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		is_ccm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher(ctx.ctx)) & C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

		if is_ccm {
			res := C.EVP_DecryptUpdate(ctx.ctx, nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length [result %d]", res)
			}
		}

		res := C.EVP_DecryptUpdate(ctx.ctx, nil, &tmplen, (*C.uchar)(&ctx.aad[0]), C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set CCM AAD [result %d]", res)
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.DecryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("Failed to perform decryption: %s", err)
	}
	res.Write(buf)

	buf2, err := ctx.DecryptFinal()
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize decryption: %s", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}

func (ctx *sm4Encrypter) EncryptAll(src []byte) ([]byte, error) {

	is_ccm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher(ctx.ctx)) & C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

	if is_ccm {
		err := ctx.setCtrl(C.EVP_CTRL_AEAD_SET_TAG, ctx.tagLen)
		if err != nil {
			return nil, err
		}
	}

	err := ctx.cipherCtx.applyKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv:%s", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		if is_ccm {
			res := C.EVP_EncryptUpdate(ctx.ctx, nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length [result %d]", res)
			}
		}

		res := C.EVP_EncryptUpdate(ctx.ctx, nil, &tmplen, (*C.uchar)(&ctx.aad[0]), C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set AAD [result %d]", res)
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.EncryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("Failed to perform encryption: %s", err)
	}
	res.Write(buf)

	buf2, err := ctx.EncryptFinal()
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize encryption: %s", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}
