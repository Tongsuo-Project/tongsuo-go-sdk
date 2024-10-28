// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm4

// #include "../shim.h"
import "C"

import (
	"bytes"
	"fmt"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

type Encrypter interface {
	// crypto.EncryptionCipherCtx
	SetPadding(pad bool)
	EncryptAll(input []byte) ([]byte, error)
	SetAAD(aad []byte)
	SetTagLen(length int)
	GetTag() ([]byte, error)
}

type Decrypter interface {
	// crypto.DecryptionCipherCtx
	SetPadding(pad bool)
	DecryptAll(input []byte) ([]byte, error)
	SetAAD(aad []byte)
	SetTag(tag []byte)
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
	case crypto.CipherModeECB:
		cipher, err = crypto.GetCipherByName("SM4-ECB")
	case crypto.CipherModeCBC:
		cipher, err = crypto.GetCipherByName("SM4-CBC")
	case crypto.CipherModeCFB:
		cipher, err = crypto.GetCipherByName("SM4-CFB")
	case crypto.CipherModeOFB:
		cipher, err = crypto.GetCipherByName("SM4-OFB")
	case crypto.CipherModeCTR:
		cipher, err = crypto.GetCipherByName("SM4-CTR")
	case crypto.CipherModeGCM:
		cipher, err = crypto.GetCipherByName("SM4-GCM")
	case crypto.CipherModeCCM:
		cipher, err = crypto.GetCipherByName("SM4-CCM")
	default:
		return nil, fmt.Errorf("unsupported sm4 mode: %w", crypto.ErrUnsupportedMode)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get cipher: %w", err)
	}

	return cipher, nil
}

func NewDecrypter(mode int, key []byte, iv []byte) (Decrypter, error) {
	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	cctx, err := crypto.NewDecryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption cipher ctx %w", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("failed to set IV len to %d: %w", len(iv), err)
			}
		}
	}

	return &sm4Decrypter{cctx: cctx, key: key, iv: iv, aad: nil, tag: nil}, nil
}

func (ctx *sm4Decrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
}

func NewEncrypter(mode int, key []byte, iv []byte) (Encrypter, error) {
	var tagLen int

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	if mode == crypto.CipherModeGCM {
		tagLen = 16
	}
	if mode == crypto.CipherModeCCM {
		tagLen = 12
	}

	cctx, err := crypto.NewEncryptionCipherCtx(cipher, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher ctx %w", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("could not set IV len to %d: %w", len(iv), err)
			}
		}
	}

	return &sm4Encrypter{cctx: cctx, tagLen: tagLen, key: key, iv: iv, aad: nil}, nil
}

func (ctx *sm4Encrypter) GetTag() ([]byte, error) {
	tag, err := ctx.cctx.GetCtrlBytes(C.EVP_CTRL_AEAD_GET_TAG, ctx.tagLen, ctx.tagLen)
	if err != nil {
		return nil, fmt.Errorf("failed to get tag: %w", err)
	}

	return tag, nil
}

func (ctx *sm4Encrypter) SetTagLen(length int) {
	ctx.tagLen = length
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
			return nil, fmt.Errorf("failed to set tag: %w", err)
		}
	}

	err := ctx.cctx.SetKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv: %w", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		isCcm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()))) &
			C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

		if isCcm {
			res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length: %w", crypto.PopError())
			}
		}

		res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&ctx.aad[0]),
			C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to decrypt: %w", crypto.PopError())
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.cctx.DecryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("failed to perform decryption: %w", err)
	}
	res.Write(buf)

	buf2, err := ctx.cctx.DecryptFinal()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize decryption: %w", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}

func (ctx *sm4Encrypter) EncryptAll(src []byte) ([]byte, error) {
	isCcm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()))) & C.EVP_CIPH_MODE) ==
		C.EVP_CIPH_CCM_MODE

	if isCcm {
		err := ctx.cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_TAG, ctx.tagLen)
		if err != nil {
			return nil, fmt.Errorf("failed to set CCM tag: %w", err)
		}
	}

	err := ctx.cctx.SetKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv: %w", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		if isCcm {
			res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length: %w", crypto.PopError())
			}
		}

		res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&ctx.aad[0]),
			C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set AAD: %w", crypto.PopError())
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.cctx.EncryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("failed to perform encryption: %w", err)
	}
	res.Write(buf)

	buf2, err := ctx.cctx.EncryptFinal()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}
