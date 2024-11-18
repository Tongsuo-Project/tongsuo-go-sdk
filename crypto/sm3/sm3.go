// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm3

// #include "../shim.h"
import "C"

import (
	"fmt"
	"hash"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	MDSize    = 32
	sm3Cblock = 64
)

var _ hash.Hash = new(SM3)

type SM3 struct {
	ctx    *C.EVP_MD_CTX
	engine *crypto.Engine
}

func New() (*SM3, error) { return NewWithEngine(nil) }

func NewWithEngine(e *crypto.Engine) (*SM3, error) {
	hash, err := newWithEngine(e)
	if err != nil {
		return nil, err
	}
	hash.Reset()

	return hash, nil
}

func newWithEngine(e *crypto.Engine) (*SM3, error) {
	hash := &SM3{ctx: nil, engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx: %w", crypto.ErrMallocFailure)
	}
	runtime.SetFinalizer(hash, func(hash *SM3) { hash.Close() })

	return hash, nil
}

func (s *SM3) BlockSize() int {
	return sm3Cblock
}

func (s *SM3) Size() int {
	return MDSize
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

func (s *SM3) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update digest: %w", crypto.PopError())
	}
	return len(data), nil
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

func (s *SM3) checkSum() [MDSize]byte {
	var result [MDSize]byte

	C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)

	return result
}

func Sum(data []byte) [MDSize]byte {
	var result [MDSize]byte

	C.X_EVP_Digest(unsafe.Pointer(&data[0]), C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])), nil,
		C.EVP_sm3(), nil)

	return result
}
