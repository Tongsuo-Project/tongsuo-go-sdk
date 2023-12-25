// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

//go:build static
// +build static

package crypto

// #cgo linux CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
// #cgo linux LDFLAGS: -extldflags -static -L/opt/tongsuo/lib -lcrypto
// #cgo darwin CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L/opt/tongsuo/lib -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
// #cgo windows pkg-config: libcrypto
import "C"
