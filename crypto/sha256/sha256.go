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

package sha256

// #include "../shim.h"
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

type SHA256 struct {
	ctx    *C.EVP_MD_CTX
	engine *crypto.Engine
}

func New() (*SHA256, error) { return NewWithEngine(nil) }

func NewWithEngine(e *crypto.Engine) (*SHA256, error) {
	hash := &SHA256{ctx: nil, engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx %w", crypto.ErrMallocFailure)
	}
	runtime.SetFinalizer(hash, func(hash *SHA256) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}

	return hash, nil
}

func (s *SHA256) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SHA256) Reset() error {
	if C.X_EVP_DigestInit_ex(s.ctx, C.X_EVP_sha256(), (*C.ENGINE)(s.engine.Engine())) != 1 {
		return fmt.Errorf("failed to init digest ctx: %w", crypto.PopError())
	}

	return nil
}

func (s *SHA256) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update digest: %w", crypto.PopError())
	}

	return len(data), nil
}

func (s *SHA256) Sum() ([32]byte, error) {
	var result [32]byte

	if C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil) != 1 {
		return result, fmt.Errorf("failed to finalize digest: %w", crypto.PopError())
	}

	return result, s.Reset()
}

func Sum(data []byte) ([32]byte, error) {
	hash, err := New()
	if err != nil {
		return [32]byte{}, err
	}

	defer hash.Close()

	if _, err := hash.Write(data); err != nil {
		return [32]byte{}, err
	}

	return hash.Sum()
}
