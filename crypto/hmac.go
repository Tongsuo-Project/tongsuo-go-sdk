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

package crypto

// #include "shim.h"
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type HMAC struct {
	ctx    *C.HMAC_CTX
	engine *Engine
	md     *C.EVP_MD
}

func NewHMAC(key []byte, digestAlgorithm MDAlgo) (*HMAC, error) {
	return NewHMACWithEngine(key, digestAlgorithm, nil)
}

func NewHMACWithEngine(key []byte, digestAlgorithm MDAlgo, e *Engine) (*HMAC, error) {
	var md *C.EVP_MD = getDigestFunction(digestAlgorithm)
	hmac := &HMAC{ctx: nil, engine: e, md: md}
	hmac.ctx = C.X_HMAC_CTX_new()
	if hmac.ctx == nil {
		return nil, ErrMallocFailure
	}

	var cEngine *C.ENGINE
	if e != nil {
		cEngine = e.Engine()
	}
	if rc := C.X_HMAC_Init_ex(hmac.ctx, unsafe.Pointer(&key[0]), C.int(len(key)), md, cEngine); rc != 1 {
		C.X_HMAC_CTX_free(hmac.ctx)
		return nil, fmt.Errorf("failed to init HMAC_CTX: %w", PopError())
	}

	runtime.SetFinalizer(hmac, func(h *HMAC) { h.Close() })
	return hmac, nil
}

func (h *HMAC) Close() {
	C.X_HMAC_CTX_free(h.ctx)
}

func (h *HMAC) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if C.X_HMAC_Update(h.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update HMAC: %w", PopError())
	}
	return len(data), nil
}

func (h *HMAC) Reset() error {
	if C.X_HMAC_Init_ex(h.ctx, nil, 0, nil, nil) != 1 {
		return fmt.Errorf("failed to reset HMAC_CTX: %w", PopError())
	}
	return nil
}

func (h *HMAC) Final() ([]byte, error) {
	mdLength := C.X_EVP_MD_size(h.md)
	result := make([]byte, mdLength)
	if rc := C.X_HMAC_Final(h.ctx, (*C.uchar)(unsafe.Pointer(&result[0])),
		(*C.uint)(unsafe.Pointer(&mdLength))); rc != 1 {
		return nil, fmt.Errorf("failed to final HMAC: %w", PopError())
	}
	return result, h.Reset()
}
