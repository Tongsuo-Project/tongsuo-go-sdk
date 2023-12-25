// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm3

// #include "../shim.h"
// #cgo linux CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
// #cgo linux LDFLAGS: -L/opt/tongsuo/lib -lcrypto
// #cgo darwin CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L/opt/tongsuo/lib -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
// #cgo windows pkg-config: libcrypto
import "C"

import (
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	SM3_DIGEST_LENGTH = 32
	SM3_CBLOCK        = 64
)

var _ hash.Hash = new(SM3)

type SM3 struct {
	ctx    *C.EVP_MD_CTX
	engine *crypto.Engine
}

func New() (*SM3, error) { return NewWithEngine(nil) }

func NewWithEngine(e *crypto.Engine) (*SM3, error) {
	h, err := newWithEngine(e)
	if err != nil {
		return nil, err
	}
	h.Reset()
	return h, nil
}

func newWithEngine(e *crypto.Engine) (*SM3, error) {
	hash := &SM3{engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, errors.New("openssl: sm3: unable to allocate ctx")
	}
	runtime.SetFinalizer(hash, func(hash *SM3) { hash.Close() })
	return hash, nil
}

func (s *SM3) BlockSize() int {
	return SM3_CBLOCK
}

func (s *SM3) Size() int {
	return SM3_DIGEST_LENGTH
}

func (s *SM3) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SM3) Reset() {
	C.X_EVP_DigestInit_ex(s.ctx, C.EVP_sm3(), (*C.ENGINE)(s.engine.Engine()))
}

func (s *SM3) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) {
		return 0, errors.New("openssl: sm3: cannot update digest")
	}
	return len(p), nil
}

func (s *SM3) Sum(in []byte) []byte {
	hash, err := NewWithEngine(s.engine)
	if err != nil {
		panic("NewSM3 fail " + err.Error())
	}

	if C.X_EVP_MD_CTX_copy_ex(hash.ctx, s.ctx) == 0 {
		panic("NewSM3 X_EVP_MD_CTX_copy_ex fail")
	}

	result := hash.checkSum()
	return append(in, result[:]...)
}

func (s *SM3) checkSum() (result [SM3_DIGEST_LENGTH]byte) {
	C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)
	return result
}

func SM3Sum(data []byte) (result [SM3_DIGEST_LENGTH]byte) {
	C.X_EVP_Digest(
		unsafe.Pointer(&data[0]),
		C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&result[0])),
		nil,
		C.EVP_sm3(),
		nil,
	)
	return
}
