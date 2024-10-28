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

package md5

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
	MDSize    = 16
	md5Cblock = 64
)

var _ hash.Hash = new(MD5)

type MD5 struct {
	ctx    *C.EVP_MD_CTX
	engine *crypto.Engine
}

func New() (*MD5, error) { return NewWithEngine(nil) }

func NewWithEngine(e *crypto.Engine) (*MD5, error) {
	hash, err := newMD5WithEngine(e)
	if err != nil {
		return nil, err
	}

	hash.Reset()

	return hash, nil
}

func newMD5WithEngine(e *crypto.Engine) (*MD5, error) {
	hash := &MD5{ctx: nil, engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx: %w", crypto.ErrMallocFailure)
	}

	runtime.SetFinalizer(hash, func(hash *MD5) { hash.Close() })

	return hash, nil
}

func (s *MD5) BlockSize() int {
	return md5Cblock
}

func (s *MD5) Size() int {
	return MDSize
}

func (s *MD5) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *MD5) Reset() {
	C.X_EVP_DigestInit_ex(s.ctx, C.X_EVP_md5(), (*C.ENGINE)(s.engine.Engine()))
}

func (s *MD5) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	if C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update digest: %w", crypto.PopError())
	}

	return len(data), nil
}

func (s *MD5) Sum(in []byte) []byte {
	hash, err := NewWithEngine(s.engine)
	if err != nil {
		panic("New fail " + err.Error())
	}

	if C.X_EVP_MD_CTX_copy_ex(hash.ctx, s.ctx) == 0 {
		panic("New X_EVP_MD_CTX_copy_ex fail")
	}

	result := hash.checkSum()
	return append(in, result[:]...)
}

func (s *MD5) checkSum() [MDSize]byte {
	var result [MDSize]byte

	C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)

	return result
}

func Sum(data []byte) [MDSize]byte {
	var result [MDSize]byte

	C.X_EVP_Digest(unsafe.Pointer(&data[0]), C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])), nil,
		C.X_EVP_md5(), nil)

	return result
}
