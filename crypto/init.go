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

func init() {
	if rc := C.X_tscrypto_init(); rc != 0 {
		panic(fmt.Errorf("X_tscrypto_init failed with %d", rc))
	}
}

// ErrorFromErrorQueue needs to run in the same OS thread as the operation
// that caused the possible error
func ErrorFromErrorQueue() error {
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
	return errors.New(fmt.Sprintf("SSL errors: %s", strings.Join(errs, "\n")))
}
