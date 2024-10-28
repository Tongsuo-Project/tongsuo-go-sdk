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
	"io"
	"runtime"
	"unsafe"
)

type Method *C.EVP_MD

func SHA1Method() Method {
	return C.X_EVP_sha1()
}

func SHA256Method() Method {
	return C.X_EVP_sha256()
}

func SHA512Method() Method {
	return C.X_EVP_sha512()
}

func SM3Method() Method {
	return C.X_EVP_sm3()
}

// Constants for the various key types.
// Mapping of name -> NID taken from openssl/evp.h
const (
	KeyTypeNone    = NidUndef
	KeyTypeRSA     = NidRsaEncryption
	KeyTypeRSA2    = NidRsa
	KeyTypeDSA     = NidDsa
	KeyTypeDSA1    = NidDsa2
	KeyTypeDSA2    = NidDsaWithSHA
	KeyTypeDSA3    = NidDsaWithSHA1
	KeyTypeDSA4    = NidDsaWithSHA12
	KeyTypeDH      = NidDhKeyAgreement
	KeyTypeDHX     = NidDhpublicnumber
	KeyTypeEC      = NidX962IdEcPublicKey
	KeyTypeHMAC    = NidHmac
	KeyTypeCMAC    = NidCmac
	KeyTypeTLS1PRF = NidTLS1Prf
	KeyTypeHKDF    = NidHkdf
	KeyTypeX25519  = NidX25519
	KeyTypeX448    = NidX448
	KeyTypeED25519 = NidEd25519
	KeyTypeED448   = NidEd448
	KeyTypeSM2     = NidSM2
)

type PublicKey interface {
	// VerifyPKCS1v15 verifies the data signature using PKCS1.15
	VerifyPKCS1v15(method Method, data, sig []byte) error

	// Encrypt encrypts the data using SM2
	Encrypt(data []byte) ([]byte, error)

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX
	// format
	MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX
	// format
	MarshalPKIXPublicKeyDER() (derBlock []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this
	// object.
	KeyType() NID

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	EvpPKey() *C.EVP_PKEY
}

type PrivateKey interface {
	PublicKey

	// Public return public key
	Public() PublicKey

	// SignPKCS1v15 signs the data using PKCS1.15
	SignPKCS1v15(method Method, data []byte) ([]byte, error)

	// Decrypt decrypts the data using SM2
	Decrypt(data []byte) ([]byte, error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error)

	// MarshalPKCS8PrivateKeyPEM converts the private key to PEM-encoded PKCS8
	// format
	MarshalPKCS8PrivateKeyPEM() (pemBlock []byte, err error)
}

func SupportEd25519() bool {
	return C.X_ED25519_SUPPORT != 0
}

type pKey struct {
	key *C.EVP_PKEY
}

func (key *pKey) EvpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(key.key))
}

func (key *pKey) BaseType() NID {
	return NID(C.EVP_PKEY_base_id(key.key))
}

func (key *pKey) Public() PublicKey {
	der, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil
	}

	pub, err := LoadPublicKeyFromDER(der)
	if err != nil {
		return nil
	}

	return pub
}

func (key *pKey) SignPKCS1v15(method Method, data []byte) ([]byte, error) {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign
		if method != nil || len(data) == 0 {
			return nil, ErrNilParameter
		}

		if C.X_EVP_DigestSignInit(ctx, nil, nil, nil, key.key) != 1 {
			return nil, PopError()
		}

		var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
		sig := make([]byte, sigblen)

		if C.X_EVP_DigestSign(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen, (*C.uchar)(unsafe.Pointer(&data[0])),
			C.size_t(len(data))) != 1 {
			return nil, PopError()
		}

		return sig[:sigblen], nil
	}

	if C.X_EVP_DigestSignInit(ctx, nil, method, nil, key.key) != 1 {
		return nil, PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestSignUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return nil, PopError()
		}
	}

	var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
	sig := make([]byte, sigblen)

	if C.X_EVP_DigestSignFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen) != 1 {
		return nil, PopError()
	}

	return sig[:sigblen], nil
}

func (key *pKey) VerifyPKCS1v15(method Method, data, sig []byte) error {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign

		if method != nil || len(data) == 0 || len(sig) == 0 {
			return ErrNilParameter
		}

		if C.X_EVP_DigestVerifyInit(ctx, nil, nil, nil, key.key) != 1 {
			return PopError()
		}

		if C.X_EVP_DigestVerify(ctx, ((*C.uchar)(unsafe.Pointer(&sig[0]))), C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return PopError()
		}

		return nil
	}

	if C.X_EVP_DigestVerifyInit(ctx, nil, method, nil, key.key) != 1 {
		return PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestVerifyUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return PopError()
		}
	}

	if C.X_EVP_DigestVerifyFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) != 1 {
		return PopError()
	}

	return nil
}

func (key *pKey) MarshalPKCS8PrivateKeyPEM() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if C.PEM_write_bio_PKCS8PrivateKey(bio, key.key, nil, nil, 0, nil, nil) != 1 {
		return nil, PopError()
	}

	var ptr *C.char
	length := C.X_BIO_get_mem_data(bio, &ptr)
	if length <= 0 {
		return nil, ErrNoData
	}

	result := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return result, nil
}

func (key *pKey) Encrypt(data []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_encrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var enclen C.size_t
	if C.EVP_PKEY_encrypt(ctx, nil, &enclen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	enc := make([]byte, enclen)

	if C.EVP_PKEY_encrypt(ctx, (*C.uchar)(unsafe.Pointer(&enc[0])), &enclen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	return enc[:enclen], nil
}

func (key *pKey) Decrypt(data []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, ErrMallocFailure
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_decrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var declen C.size_t
	if C.EVP_PKEY_decrypt(ctx, nil, &declen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	dec := make([]byte, declen)

	if C.EVP_PKEY_decrypt(ctx, (*C.uchar)(unsafe.Pointer(&dec[0])), &declen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	return dec[:declen], nil
}

func (key *pKey) MarshalPKCS1PrivateKeyPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.X_PEM_write_bio_PrivateKey_traditional(bio, key.key, nil, nil,
		C.int(0), nil, nil)) != 1 {
		return nil, PopError()
	}

	pem, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return pem, nil
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PrivateKey_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.PEM_write_bio_PUBKEY(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyDER() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PUBKEY_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pemBlock []byte) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCert
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	priKey := &pKey{key: key}
	runtime.SetFinalizer(priKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if C.X_EVP_PKEY_is_sm2(priKey.key) == 1 {
		if C.EVP_PKEY_set_alias_type(priKey.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return priKey, nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEMWithPassword(pemBlock []byte, password string) (
	PrivateKey, error,
) {
	if len(pemBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)
	cs := C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, unsafe.Pointer(cs))
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(derBlock []byte) (PrivateKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PrivateKey_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// LoadPrivateKeyFromPEMWidthPassword loads a private key from a PEM-encoded block.
// Backwards-compatible with typo
func LoadPrivateKeyFromPEMWidthPassword(pemBlock []byte, password string) (
	PrivateKey, error,
) {
	return LoadPrivateKeyFromPEMWithPassword(pemBlock, password)
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pemBlock []byte) (PublicKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoPubKey
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return p, nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(derBlock []byte) (PublicKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoPubKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PUBKEY_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 65537.
func GenerateRSAKey(bits int) (PrivateKey, error) {
	defaultPubExp := 0x10001

	return GenerateRSAKeyWithExponent(bits, defaultPubExp)
}

// GenerateRSAKeyWithExponent generates a new RSA private key.
func GenerateRSAKeyWithExponent(bits int, exponent int) (PrivateKey, error) {
	rsa := C.RSA_generate_key(C.int(bits), C.ulong(exponent), nil, nil)
	if rsa == nil {
		return nil, ErrMallocFailure
	}
	key := C.X_EVP_PKEY_new()
	if key == nil {
		return nil, ErrMallocFailure
	}
	if C.X_EVP_PKEY_assign_charp(key, C.EVP_PKEY_RSA, (*C.char)(unsafe.Pointer(rsa))) != 1 {
		C.X_EVP_PKEY_free(key)
		return nil, PopError()
	}
	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
// see https://www.openssl.org/docs/apps/ecparam.html for a list of implemented curves.
type EllipticCurve int

const (
	// P-256: X9.62/SECG curve over a 256 bit prime field
	Prime256v1 EllipticCurve = C.NID_X9_62_prime256v1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
	// P-521: NIST/SECG curve over a 521 bit prime field
	Secp521r1 EllipticCurve = C.NID_secp521r1
	// SM2:	GB/T 32918-2017
	SM2Curve EllipticCurve = C.NID_sm2
)

// GenerateECKey generates a new elliptic curve private key on the speicified
// curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {
	// Create context for parameter generation
	paramCtx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if paramCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	if curve == SM2Curve {
		if C.EVP_PKEY_keygen_init(paramCtx) != 1 {
			return nil, PopError()
		}
	} else {
		if int(C.EVP_PKEY_paramgen_init(paramCtx)) != 1 {
			return nil, PopError()
		}
	}

	// Set curve in EC parameter generation context
	if int(C.X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, C.int(curve))) != 1 {
		return nil, PopError()
	}

	var key *C.EVP_PKEY

	if curve == SM2Curve {
		if int(C.EVP_PKEY_keygen(paramCtx, &key)) != 1 {
			return nil, PopError()
		}
	} else {
		// Create parameter object
		var params *C.EVP_PKEY
		if int(C.EVP_PKEY_paramgen(paramCtx, &params)) != 1 {
			return nil, PopError()
		}
		defer C.EVP_PKEY_free(params)

		// Create context for the key generation
		keyCtx := C.EVP_PKEY_CTX_new(params, nil)
		if keyCtx == nil {
			return nil, PopError()
		}
		defer C.EVP_PKEY_CTX_free(keyCtx)

		if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
			return nil, PopError()
		}

		if int(C.EVP_PKEY_keygen(keyCtx, &key)) != 1 {
			return nil, PopError()
		}
	}

	privKey := &pKey{key: key}
	runtime.SetFinalizer(privKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if curve == SM2Curve {
		if C.EVP_PKEY_set_alias_type(privKey.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return privKey, nil
}

// GenerateED25519Key generates a Ed25519 key
func GenerateED25519Key() (PrivateKey, error) {
	// Key context
	keyCtx := C.EVP_PKEY_CTX_new_id(C.X_EVP_PKEY_ED25519, nil)
	if keyCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	// Generate the key
	var privKey *C.EVP_PKEY
	if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, PopError()
	}
	if int(C.EVP_PKEY_keygen(keyCtx, &privKey)) != 1 {
		return nil, PopError()
	}

	p := &pKey{key: privKey}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}
