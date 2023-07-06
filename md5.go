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

package tongsuogo

// #include "shim.h"
import "C"

import (
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

const (
	MD5_DIGEST_LENGTH = 16
	MD5_CBLOCK        = 64
)

var _ hash.Hash = new(MD5Hash)

type MD5Hash struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
}

func NewMD5Hash() (*MD5Hash, error) { return NewMD5HashWithEngine(nil) }

func NewMD5HashWithEngine(e *Engine) (*MD5Hash, error) {
	h, err := newMD5HashWithEngine(e)
	if err != nil {
		return nil, err
	}
	h.Reset()
	return h, nil
}

func newMD5HashWithEngine(e *Engine) (*MD5Hash, error) {
	hash := &MD5Hash{engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, errors.New("openssl: md5: unable to allocate ctx")
	}
	runtime.SetFinalizer(hash, func(hash *MD5Hash) { hash.Close() })
	return hash, nil
}

func (s *MD5Hash) BlockSize() int {
	return MD5_CBLOCK
}

func (s *MD5Hash) Size() int {
	return MD5_DIGEST_LENGTH
}

func (s *MD5Hash) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *MD5Hash) Reset() {
	C.X_EVP_DigestInit_ex(s.ctx, C.X_EVP_md5(), engineRef(s.engine))
}

func (s *MD5Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p))) {
		return 0, errors.New("openssl: md5: cannot update digest")
	}
	return len(p), nil
}

func (s *MD5Hash) Sum(in []byte) []byte {
	hash, err := NewMD5HashWithEngine(s.engine)
	if err != nil {
		panic("NewMD5Hash fail " + err.Error())
	}

	if C.X_EVP_MD_CTX_copy_ex(hash.ctx, s.ctx) == 0 {
		panic("NewMD5Hash X_EVP_MD_CTX_copy_ex fail")
	}

	result := hash.checkSum()
	return append(in, result[:]...)
}

func (s *MD5Hash) checkSum() (result [MD5_DIGEST_LENGTH]byte) {
	C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)
	return result
}

func MD5Sum(data []byte) (result [MD5_DIGEST_LENGTH]byte) {
	C.X_EVP_Digest(
		unsafe.Pointer(&data[0]),
		C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&result[0])),
		nil,
		C.X_EVP_md5(),
		nil,
	)
	return
}
