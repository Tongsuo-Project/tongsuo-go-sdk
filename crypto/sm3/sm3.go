// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sm3

// #include "../../shim.h"
import "C"

import (
	"errors"
	"hash"
	"runtime"
	"unsafe"

	tongsuogo "github.com/tongsuo-project/tongsuo-go-sdk"
)

const (
	SM3_DIGEST_LENGTH = 32
	SM3_CBLOCK        = 64
)

var _ hash.Hash = new(SM3)

type SM3 struct {
	ctx    *C.EVP_MD_CTX
	engine *tongsuogo.Engine
}

func New() (*SM3, error) { return NewWithEngine(nil) }

func NewWithEngine(e *tongsuogo.Engine) (*SM3, error) {
	h, err := newWithEngine(e)
	if err != nil {
		return nil, err
	}
	h.Reset()
	return h, nil
}

func newWithEngine(e *tongsuogo.Engine) (*SM3, error) {
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
