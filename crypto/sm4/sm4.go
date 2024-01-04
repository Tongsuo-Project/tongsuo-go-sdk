// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm4

// #include "../shim.h"
// #cgo linux LDFLAGS: -lcrypto
// #cgo darwin LDFLAGS: -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
// #cgo windows pkg-config: libcrypto
import "C"

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

type SM4Encrypter interface {
	// crypto.EncryptionCipherCtx
	SetPadding(pad bool)
	EncryptAll(input []byte) ([]byte, error)
	SetAAD([]byte)
	SetTagLen(int)
	GetTag() ([]byte, error)
}

type SM4Decrypter interface {
	// crypto.DecryptionCipherCtx
	SetPadding(pad bool)
	DecryptAll(input []byte) ([]byte, error)
	SetAAD([]byte)
	SetTag([]byte)
}

type sm4Encrypter struct {
	cctx   crypto.EncryptionCipherCtx
	key    []byte
	iv     []byte
	aad    []byte
	tagLen int
}

type sm4Decrypter struct {
	cctx crypto.DecryptionCipherCtx
	key  []byte
	iv   []byte
	aad  []byte
	tag  []byte
}

func getSM4Cipher(mode int) (*crypto.Cipher, error) {
	var cipher *crypto.Cipher
	var err error

	switch mode {
	case crypto.CIPHER_MODE_ECB:
		cipher, err = crypto.GetCipherByName("SM4-ECB")
	case crypto.CIPHER_MODE_CBC:
		cipher, err = crypto.GetCipherByName("SM4-CBC")
	case crypto.CIPHER_MODE_CFB:
		cipher, err = crypto.GetCipherByName("SM4-CFB")
	case crypto.CIPHER_MODE_OFB:
		cipher, err = crypto.GetCipherByName("SM4-OFB")
	case crypto.CIPHER_MODE_CTR:
		cipher, err = crypto.GetCipherByName("SM4-CTR")
	case crypto.CIPHER_MODE_GCM:
		cipher, err = crypto.GetCipherByName("SM4-GCM")
	case crypto.CIPHER_MODE_CCM:
		cipher, err = crypto.GetCipherByName("SM4-CCM")
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

	cctx, err := crypto.NewDecryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption cipher ctx %s", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CIPHER_MODE_GCM || mode == crypto.CIPHER_MODE_CCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("failed to set IV len to %d: %s", len(iv), err)
			}
		}
	}

	return &sm4Decrypter{cctx: cctx, key: key, iv: iv}, nil
}

func (ctx *sm4Decrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
}

func NewSM4Encrypter(mode int, key []byte, iv []byte) (SM4Encrypter, error) {
	var tagLen int

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	if mode == crypto.CIPHER_MODE_GCM {
		tagLen = 16
	}
	if mode == crypto.CIPHER_MODE_CCM {
		tagLen = 12
	}

	cctx, err := crypto.NewEncryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher ctx %s", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CIPHER_MODE_GCM || mode == crypto.CIPHER_MODE_CCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("could not set IV len to %d: %s", len(iv), err)
			}
		}
	}

	return &sm4Encrypter{cctx: cctx, tagLen: tagLen, key: key, iv: iv}, nil
}

func (ctx *sm4Encrypter) GetTag() ([]byte, error) {
	return ctx.cctx.GetCtrlBytes(C.EVP_CTRL_AEAD_GET_TAG, ctx.tagLen, ctx.tagLen)
}

func (ctx *sm4Encrypter) SetTagLen(len int) {
	ctx.tagLen = len
}

func (ctx *sm4Encrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
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
		err := ctx.cctx.SetCtrlBytes(C.EVP_CTRL_AEAD_SET_TAG, len(ctx.tag), ctx.tag)
		if err != nil {
			return nil, err
		}
	}

	err := ctx.cctx.SetKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv:%s", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		is_ccm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()))) & C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

		if is_ccm {
			res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length [result %d]", res)
			}
		}

		res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&ctx.aad[0]), C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set CCM AAD [result %d]", res)
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.cctx.DecryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("Failed to perform decryption: %s", err)
	}
	res.Write(buf)

	buf2, err := ctx.cctx.DecryptFinal()
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize decryption: %s", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}

func (sm4 *sm4Encrypter) EncryptAll(src []byte) ([]byte, error) {

	is_ccm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(sm4.cctx.Ctx()))) & C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

	if is_ccm {
		err := sm4.cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_TAG, sm4.tagLen)
		if err != nil {
			return nil, err
		}
	}

	err := sm4.cctx.SetKeyAndIV(sm4.key, sm4.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv:%s", err)
	}

	var tmplen C.int
	if sm4.aad != nil {
		if is_ccm {
			res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(sm4.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length [result %d]", res)
			}
		}

		res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(sm4.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&sm4.aad[0]), C.int(len(sm4.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set AAD [result %d]", res)
		}
	}

	res := new(bytes.Buffer)
	buf, err := sm4.cctx.EncryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("Failed to perform encryption: %s", err)
	}
	res.Write(buf)

	buf2, err := sm4.cctx.EncryptFinal()
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize encryption: %s", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}
