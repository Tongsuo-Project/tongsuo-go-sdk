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
	"runtime"
	"unsafe"
)

type DH struct {
	dh *C.DH
}

func (dh *DH) GetDH() *C.DH {
	return dh.dh
}

// LoadDHParametersFromPEM loads the Diffie-Hellman parameters from
// a PEM-encoded block.
func LoadDHParametersFromPEM(pemBlock []byte) (*DH, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCert
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	params := C.PEM_read_bio_DHparams(bio, nil, nil, nil)
	if params == nil {
		return nil, PopError()
	}
	dhparams := &DH{dh: params}
	runtime.SetFinalizer(dhparams, func(dhparams *DH) {
		C.DH_free(dhparams.dh)
	})
	return dhparams, nil
}
