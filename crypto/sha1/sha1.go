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

package sha1

// #include "../shim.h"
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const MDSize = 20

type SHA1 struct {
	ctx    *C.EVP_MD_CTX
	engine *crypto.Engine
}

func New() (*SHA1, error) { return NewWithEngine(nil) }

func NewWithEngine(e *crypto.Engine) (*SHA1, error) {
	hash := &SHA1{ctx: nil, engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx: %w", crypto.ErrMallocFailure)
	}
	runtime.SetFinalizer(hash, func(hash *SHA1) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}

	return hash, nil
}

func (s *SHA1) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SHA1) Reset() error {
	if C.X_EVP_DigestInit_ex(s.ctx, C.X_EVP_sha1(), (*C.ENGINE)(s.engine.Engine())) != 1 {
		return fmt.Errorf("failed to init digest ctx %w", crypto.PopError())
	}

	return nil
}

func (s *SHA1) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update digest: %w", crypto.PopError())
	}

	return len(data), nil
}

func (s *SHA1) Sum() ([MDSize]byte, error) {
	var result [MDSize]byte

	if C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil) != 1 {
		return result, fmt.Errorf("failed to finalize digest: %w", crypto.PopError())
	}

	return result, s.Reset()
}

func Sum(data []byte) ([MDSize]byte, error) {
	hash, err := New()
	if err != nil {
		return [MDSize]byte{}, err
	}

	defer hash.Close()

	if _, err := hash.Write(data); err != nil {
		return [MDSize]byte{}, err
	}
	return hash.Sum()
}
