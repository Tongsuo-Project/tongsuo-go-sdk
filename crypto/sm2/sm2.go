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
	"math/big"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

type PublicKey struct {
	crypto.PublicKey
}

type PrivateKey struct {
	crypto.PrivateKey
}

func (k *PublicKey) VerifyASN1(data, sig []byte) bool {
	err := k.VerifyPKCS1v15(crypto.SM3_Method, data, sig)
	if err != nil {
		return false
	}
	return true
}

func (k *PrivateKey) VerifyASN1(data, sig []byte) bool {
	err := k.VerifyPKCS1v15(crypto.SM3_Method, data, sig)
	if err != nil {
		return false
	}
	return true
}

func (k *PrivateKey) SignASN1(data []byte) ([]byte, error) {
	return k.SignPKCS1v15(crypto.SM3_Method, data)
}

func (k *PublicKey) Verify(data []byte, r, s *big.Int) bool {
	sm2Sig := C.ECDSA_SIG_new()
	defer C.ECDSA_SIG_free(sm2Sig)

	rBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&r.Bytes()[0])), C.int(len(r.Bytes())), nil)
	sBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&s.Bytes()[0])), C.int(len(s.Bytes())), nil)

	ret := C.ECDSA_SIG_set0(sm2Sig, rBig, sBig)
	if ret != 1 {
		return false
	}

	len := C.i2d_ECDSA_SIG(sm2Sig, nil)

	buf := (*C.uchar)(C.malloc(C.size_t(len)))
	defer C.free(unsafe.Pointer(buf))

	tmp := buf
	len2 := C.i2d_ECDSA_SIG(sm2Sig, &tmp)

	return k.VerifyASN1(data, C.GoBytes(unsafe.Pointer(buf), C.int(len2)))
}

func (k *PrivateKey) Verify(data []byte, r, s *big.Int) bool {
	sm2Sig := C.ECDSA_SIG_new()
	defer C.ECDSA_SIG_free(sm2Sig)

	rBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&r.Bytes()[0])), C.int(len(r.Bytes())), nil)
	sBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&s.Bytes()[0])), C.int(len(s.Bytes())), nil)

	ret := C.ECDSA_SIG_set0(sm2Sig, rBig, sBig)
	if ret != 1 {
		return false
	}

	len := C.i2d_ECDSA_SIG(sm2Sig, nil)

	buf := (*C.uchar)(C.malloc(C.size_t(len)))
	defer C.free(unsafe.Pointer(buf))

	tmp := buf
	len2 := C.i2d_ECDSA_SIG(sm2Sig, &tmp)

	return k.VerifyASN1(data, C.GoBytes(unsafe.Pointer(buf), C.int(len2)))
}

func (k *PrivateKey) Sign(data []byte) (r, s *big.Int, err error) {
	sig, err := k.SignPKCS1v15(crypto.SM3_Method, data)
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

func GenerateKey() (*PrivateKey, error) {
	priv, err := crypto.GenerateECKey(crypto.Sm2Curve)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{priv}, nil
}

func LoadPrivateKeyFromPEM(pem_block []byte) (*PrivateKey, error) {
	priv, err := crypto.LoadPrivateKeyFromPEM(pem_block)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{priv}, nil
}

func LoadPublicKeyFromPEM(pem_block []byte) (*PublicKey, error) {
	pub, err := crypto.LoadPublicKeyFromPEM(pem_block)
	if err != nil {
		return nil, err
	}

	return &PublicKey{pub}, nil
}
