// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm2

// #include "../shim.h"
// #cgo linux LDFLAGS: -lcrypto
// #cgo darwin LDFLAGS: -lcrypto
// #cgo windows CFLAGS: -Wall -DWIN32_LEAN_AND_MEAN
// #cgo windows pkg-config: libcrypto
import "C"

import (
	"errors"
	"math/big"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// VerifyASN1 verifies ASN.1 encoded signature. Returns nil on success.
func VerifyASN1(pub crypto.PublicKey, data, sig []byte) error {
	if pub.KeyType() != crypto.NID_sm2 {
		return errors.New("SM2: key type is not sm2")
	}

	return pub.VerifyPKCS1v15(crypto.SM3_Method, data, sig)
}

// SignASN1 signs the data with priv and returns ASN.1 encoded signature.
func SignASN1(priv crypto.PrivateKey, data []byte) ([]byte, error) {
	if priv.KeyType() != crypto.NID_sm2 {
		return nil, errors.New("SM2: key type is not sm2")
	}

	return priv.SignPKCS1v15(crypto.SM3_Method, data)
}

// Verify verifies the signature in r, s of data using the public key, pub.
// Returns nil on success.
func Verify(pub crypto.PublicKey, data []byte, r, s *big.Int) error {
	if pub.KeyType() != crypto.NID_sm2 {
		return errors.New("SM2: key type is not sm2")
	}

	sm2Sig := C.ECDSA_SIG_new()
	defer C.ECDSA_SIG_free(sm2Sig)

	rBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&r.Bytes()[0])), C.int(len(r.Bytes())), nil)
	sBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&s.Bytes()[0])), C.int(len(s.Bytes())), nil)

	ret := C.ECDSA_SIG_set0(sm2Sig, rBig, sBig)
	if ret != 1 {
		return errors.New("SM2: set r,s failed")
	}

	len := C.i2d_ECDSA_SIG(sm2Sig, nil)

	buf := (*C.uchar)(C.malloc(C.size_t(len)))
	defer C.free(unsafe.Pointer(buf))

	tmp := buf
	len2 := C.i2d_ECDSA_SIG(sm2Sig, &tmp)

	return VerifyASN1(pub, data, C.GoBytes(unsafe.Pointer(buf), C.int(len2)))
}

// Sign signs the data with the private key, priv.
func Sign(priv crypto.PrivateKey, data []byte) (r, s *big.Int, err error) {
	if priv.KeyType() != crypto.NID_sm2 {
		return nil, nil, errors.New("SM2: key type is not sm2")
	}

	sig, err := priv.SignPKCS1v15(crypto.SM3_Method, data)
	if err != nil {
		return nil, nil, err
	}

	buf := (*C.uchar)(C.malloc(C.size_t(len(sig))))
	defer C.free(unsafe.Pointer(buf))
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))

	sm2Sig := C.d2i_ECDSA_SIG(nil, &buf, C.long(len(sig)))
	if sm2Sig == nil {
		return nil, nil, err
	}
	defer C.ECDSA_SIG_free(sm2Sig)

	var rBig, sBig *C.BIGNUM
	C.ECDSA_SIG_get0(sm2Sig, &rBig, &sBig)

	rBytes := make([]byte, C.X_BN_num_bytes(rBig))
	sBytes := make([]byte, C.X_BN_num_bytes(sBig))

	rLen := C.BN_bn2bin(rBig, (*C.uchar)(unsafe.Pointer(&rBytes[0])))
	sLen := C.BN_bn2bin(sBig, (*C.uchar)(unsafe.Pointer(&sBytes[0])))

	r = new(big.Int).SetBytes(rBytes[:rLen])
	s = new(big.Int).SetBytes(sBytes[:sLen])

	return r, s, nil
}

// GenerateKey generates a new SM2 key pair.
func GenerateKey() (crypto.PrivateKey, error) {
	priv, err := crypto.GenerateECKey(crypto.Sm2Curve)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// Encrypt encrypts the data with the private key, priv.
