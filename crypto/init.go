// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package crypto

// #include "shim.h"
import "C"

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrMallocFailure       = errors.New("malloc failure")
	ErrNilParameter        = errors.New("nil parameter")
	ErrNoCipher            = errors.New("no cipher")
	ErrNoVersion           = errors.New("no version")
	ErrUnexpectedEOF       = errors.New("unexpected EOF")
	ErrNoPeerCert          = errors.New("no peer certificate")
	ErrShutdown            = errors.New("shutdown")
	ErrNoSession           = errors.New("no session")
	ErrSessionLength       = errors.New("session length error")
	ErrEmptySession        = errors.New("empty session")
	ErrNoALPN              = errors.New("no ALPN negotiated")
	ErrWrongKeyType        = errors.New("wrong key type")
	ErrUnknownTLSVersion   = errors.New("unknown TLS version")
	ErrNoCert              = errors.New("no certificate")
	ErrNoKey               = errors.New("no key")
	ErrUnsupportedMode     = errors.New("unsupported cipher mode")
	ErrPartialWrite        = errors.New("partial write")
	ErrUnsupportedDigest   = errors.New("unsupported digest")
	ErrInvalidNid          = errors.New("invalid NID")
	ErrEmptyExtensionValue = errors.New("empty extension value")
	ErrNoPubKey            = errors.New("no public key")
	ErrCipherNotFound      = errors.New("cipher not found")
	ErrBadKeySize          = errors.New("bad key size")
	ErrBadIvSize           = errors.New("bad IV size")
	ErrUknownBlockSize     = errors.New("unknown block size")
	ErrNoEngine            = errors.New("engine not found")
	ErrMatchFailed         = errors.New("match failed")
	ErrInputInvalid        = errors.New("input invalid")
	ErrInternalError       = errors.New("internal error")
	ErrEmptyKey            = errors.New("empty key")
	ErrNoData              = errors.New("no data")
)

func init() {
	if rc := C.X_tscrypto_init(); rc != 0 {
		panic(fmt.Sprintf("X_tscrypto_init failed with %d", rc))
	}
}

// PopError needs to run in the same OS thread as the operation
// that caused the possible error
func PopError() error {
	var errs []string
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		errs = append(errs, fmt.Sprintf("%s:%s:%s",
			C.GoString(C.ERR_lib_error_string(err)),
			C.GoString(C.ERR_func_error_string(err)),
			C.GoString(C.ERR_reason_error_string(err))))
	}

	return errors.New("error string: " + strings.Join(errs, "\n"))
}
