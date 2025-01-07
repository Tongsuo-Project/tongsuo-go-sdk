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
	"math/big"
	"os"
	"runtime"
	"time"
	"unsafe"
)

type DigestAlgo int

const (
	DigestNull      DigestAlgo = iota
	DigestMD5       DigestAlgo = iota
	DigestMD4       DigestAlgo = iota
	DigestSHA       DigestAlgo = iota
	DigestSHA1      DigestAlgo = iota
	DigestDSS       DigestAlgo = iota
	DigestDSS1      DigestAlgo = iota
	DigestMDC2      DigestAlgo = iota
	DigestRipemd160 DigestAlgo = iota
	DigestSHA224    DigestAlgo = iota
	DigestSHA256    DigestAlgo = iota
	DigestSHA384    DigestAlgo = iota
	DigestSHA512    DigestAlgo = iota
	DigestSM3       DigestAlgo = iota
)

type GMDoubleCertKey struct {
	SignCertFile string
	SignKeyFile  string
	EncCertFile  string
	EncKeyFile   string
}

// X509Version represents a version on a x509 certificate.
type X509Version int

// Specify constants for x509 versions because the standard states that they
// are represented internally as one lower than the common version name.
const (
	X509V1 X509Version = 0
	X509V3 X509Version = 2
)

type Certificate struct {
	x      *C.X509
	Issuer *Certificate
	ref    interface{}
	pubKey PublicKey
}

type CertificateInfo struct {
	Serial       *big.Int
	Issued       time.Duration
	Expires      time.Duration
	Country      string
	Organization string
	CommonName   string
}

type Name struct {
	name *C.X509_NAME
}

func NewCertWrapper(x unsafe.Pointer, ref ...interface{}) *Certificate {
	if len(ref) > 0 {
		return &Certificate{x: (*C.X509)(x), ref: ref[0]}
	}

	return &Certificate{x: (*C.X509)(x)}
}

// NewName allocate and return a new Name object.
func NewName() (*Name, error) {
	n := C.X509_NAME_new()
	if n == nil {
		return nil, fmt.Errorf("could not create x509 name: %w", ErrMallocFailure)
	}
	name := &Name{name: n}
	runtime.SetFinalizer(name, func(n *Name) {
		C.X509_NAME_free(n.name)
	})

	return name, nil
}

// AddTextEntry appends a text entry to an X509 NAME.
func (n *Name) AddTextEntry(field, value string) error {
	cfield := C.CString(field)

	defer C.free(unsafe.Pointer(cfield))

	cvalue := (*C.uchar)(unsafe.Pointer(C.CString(value)))

	defer C.free(unsafe.Pointer(cvalue))

	ret := C.X509_NAME_add_entry_by_txt(n.name, cfield, C.MBSTRING_ASC, cvalue, -1, -1, 0)
	if ret != 1 {
		return fmt.Errorf("failed to add x509 name text entry: %w", PopError())
	}

	return nil
}

// AddTextEntries allows adding multiple entries to a name in one call.
func (n *Name) AddTextEntries(entries map[string]string) error {
	for f, v := range entries {
		if err := n.AddTextEntry(f, v); err != nil {
			return err
		}
	}
	return nil
}

// GetEntry returns a name entry based on NID.  If no entry, then ("", false) is
// returned.
func (n *Name) GetEntry(nid NID) (string, bool) {
	entrylen := C.X509_NAME_get_text_by_NID(n.name, C.int(nid), nil, 0)
	if entrylen == -1 {
		return "", false
	}
	buf := (*C.char)(C.malloc(C.size_t(entrylen + 1)))
	defer C.free(unsafe.Pointer(buf))
	C.X509_NAME_get_text_by_NID(n.name, C.int(nid), buf, entrylen+1)
	return C.GoStringN(buf, entrylen), true
}

// NewCertificate generates a basic certificate based
// on the provided CertificateInfo struct
func NewCertificate(info *CertificateInfo, key PublicKey) (*Certificate, error) {
	cert := &Certificate{x: C.X509_new()}
	runtime.SetFinalizer(cert, func(c *Certificate) {
		C.X509_free(c.x)
	})
	if err := cert.SetVersion(X509V3); err != nil {
		return nil, err
	}
	name, err := cert.GetSubjectName()
	if err != nil {
		return nil, err
	}
	err = name.AddTextEntries(map[string]string{
		"C":  info.Country,
		"O":  info.Organization,
		"CN": info.CommonName,
	})
	if err != nil {
		return nil, err
	}
	// self-issue for now
	if err := cert.SetIssuerName(name); err != nil {
		return nil, err
	}
	if err := cert.SetSerial(info.Serial); err != nil {
		return nil, err
	}
	if err := cert.SetIssueDate(info.Issued); err != nil {
		return nil, err
	}
	if err := cert.SetExpireDate(info.Expires); err != nil {
		return nil, err
	}
	if err := cert.SetPubKey(key); err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *Certificate) GetCert() *C.X509 {
	return c.x
}

func (c *Certificate) GetSubjectName() (*Name, error) {
	n := C.X509_get_subject_name(c.x)
	if n == nil {
		return nil, fmt.Errorf("failed to get subject name: %w", ErrNilParameter)
	}
	return &Name{name: n}, nil
}

func (c *Certificate) GetIssuerName() (*Name, error) {
	n := C.X509_get_issuer_name(c.x)
	if n == nil {
		return nil, fmt.Errorf("failed to get issuer name: %w", ErrNilParameter)
	}
	return &Name{name: n}, nil
}

func (c *Certificate) SetSubjectName(name *Name) error {
	if C.X509_set_subject_name(c.x, name.name) != 1 {
		return fmt.Errorf("failed to set subject name: %w", PopError())
	}
	return nil
}

// SetIssuer updates the stored Issuer cert
// and the internal x509 Issuer Name of a certificate.
// The stored Issuer reference is used when adding extensions.
func (c *Certificate) SetIssuer(issuer *Certificate) error {
	name, err := issuer.GetSubjectName()
	if err != nil {
		return err
	}
	if err = c.SetIssuerName(name); err != nil {
		return err
	}
	c.Issuer = issuer
	return nil
}

// SetIssuerName populates the issuer name of a certificate.
// Use SetIssuer instead, if possible.
func (c *Certificate) SetIssuerName(name *Name) error {
	if C.X509_set_issuer_name(c.x, name.name) != 1 {
		return fmt.Errorf("failed to set subject name: %w", PopError())
	}
	return nil
}

// SetSerial sets the serial of a certificate.
func (c *Certificate) SetSerial(serial *big.Int) error {
	sno := C.ASN1_INTEGER_new()
	defer C.ASN1_INTEGER_free(sno)
	bn := C.BN_new()
	defer C.BN_free(bn)

	serialBytes := serial.Bytes()
	if bn = C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&serialBytes[0])), C.int(len(serialBytes)), bn); bn == nil {
		return fmt.Errorf("failed to set serial: %w", PopError())
	}
	if sno = C.BN_to_ASN1_INTEGER(bn, sno); sno == nil {
		return fmt.Errorf("failed to set serial: %w", PopError())
	}
	if C.X509_set_serialNumber(c.x, sno) != 1 {
		return fmt.Errorf("failed to set serial: %w", PopError())
	}
	return nil
}

// SetIssueDate sets the certificate issue date relative to the current time.
func (c *Certificate) SetIssueDate(when time.Duration) error {
	offset := C.long(when / time.Second)
	result := C.X509_gmtime_adj(C.X_X509_get0_notBefore(c.x), offset)
	if result == nil {
		return fmt.Errorf("failed to set issue date: %w", PopError())
	}
	return nil
}

// SetExpireDate sets the certificate issue date relative to the current time.
func (c *Certificate) SetExpireDate(when time.Duration) error {
	offset := C.long(when / time.Second)
	result := C.X509_gmtime_adj(C.X_X509_get0_notAfter(c.x), offset)
	if result == nil {
		return fmt.Errorf("failed to set expire date: %w", PopError())
	}
	return nil
}

// SetPubKey assigns a new public key to a certificate.
func (c *Certificate) SetPubKey(pubKey PublicKey) error {
	c.pubKey = pubKey
	if C.X509_set_pubkey(c.x, pubKey.EvpPKey()) != 1 {
		return fmt.Errorf("failed to set public key: %w", PopError())
	}
	return nil
}

// Sign a certificate using a private key and a digest name.
// Accepted digest names are 'sm3', 'sha256', 'sha384', and 'sha512'.
func (c *Certificate) Sign(privKey PrivateKey, digest DigestAlgo) error {
	switch digest {
	case DigestSM3:
	case DigestSHA256:
	case DigestSHA384:
	case DigestSHA512:
	default:
		return ErrUnsupportedDigest
	}
	return c.insecureSign(privKey, digest)
}

func (c *Certificate) insecureSign(privKey PrivateKey, digest DigestAlgo) error {
	var md *C.EVP_MD = getDigestFunction(digest)
	if C.X509_sign(c.x, privKey.EvpPKey(), md) <= 0 {
		return fmt.Errorf("failed to sign certificate: %w", PopError())
	}
	return nil
}

// AddExtension Add an extension to a certificate.
// Extension constants are NID_* as found in openssl.
func (c *Certificate) AddExtension(nid NID, value string) error {
	if c.x == nil {
		return fmt.Errorf("certificate is nil: %w", ErrNilParameter)
	}

	issuer := c
	if c.Issuer != nil {
		if c.Issuer.x == nil {
			return fmt.Errorf("issuer certificate is nil: %w", ErrNilParameter)
		}
		issuer = c.Issuer
	}

	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))

	var ctx C.X509V3_CTX
	C.X509V3_set_ctx(&ctx, c.x, issuer.x, nil, nil, 0)

	ext := C.X509V3_EXT_conf_nid(nil, &ctx, C.int(nid), cValue)
	if ext == nil {
		return fmt.Errorf("failed to create x509v3 extension: %w", PopError())
	}
	defer C.X509_EXTENSION_free(ext)

	if C.X509_add_ext(c.x, ext, -1) <= 0 {
		return fmt.Errorf("failed to add x509v3 extension: %w", PopError())
	}

	return nil
}

// helper function to validate extension input
func validateExtensionInput(nid NID, value string) error {
	if nid <= 0 {
		return ErrInvalidNid
	}
	if value == "" {
		return ErrEmptyExtensionValue
	}
	return nil
}

// AddExtensions Wraps AddExtension using a map of NID to text extension.
// Will return without finishing if it encounters an error.
func (c *Certificate) AddExtensions(extensions map[NID]string) error {
	targetNid := NidAuthorityKeyIdentifier
	found := false
	for nid, value := range extensions {
		if nid == NidAuthorityKeyIdentifier {
			found = true

			continue
		}
		if err := c.AddExtension(nid, value); err != nil {
			return err
		}
	}

	// NID_authority_key_identifier depends on subject key ID, needs to be added last
	if found {
		if err := c.AddExtension(targetNid, extensions[targetNid]); err != nil {
			return err
		}
	}
	return nil
}

// LoadCertificateFromPEM loads an X509 certificate from a PEM-encoded block.
func LoadCertificateFromPEM(pemBlock []byte) (*Certificate, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCert
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	cert := C.PEM_read_bio_X509(bio, nil, nil, nil)
	C.BIO_free(bio)
	if cert == nil {
		return nil, PopError()
	}
	x := &Certificate{x: cert}
	runtime.SetFinalizer(x, func(x *Certificate) {
		C.X509_free(x.x)
	})
	return x, nil
}

// MarshalPEM converts the X509 certificate to PEM-encoded format
func (c *Certificate) MarshalPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}

	defer C.BIO_free(bio)
	if int(C.PEM_write_bio_X509(bio, c.x)) != 1 {
		return nil, fmt.Errorf("failed to write certificate: %w", PopError())
	}

	data, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	return data, nil
}

// PublicKey returns the public key embedded in the X509 certificate.
func (c *Certificate) PublicKey() (PublicKey, error) {
	pkey := C.X509_get_pubkey(c.x)
	if pkey == nil {
		return nil, ErrNoPubKey
	}
	key := &pKey{key: pkey}
	runtime.SetFinalizer(key, func(key *pKey) {
		C.EVP_PKEY_free(key.key)
	})
	return key, nil
}

// GetSerialNumberHex returns the certificate's serial number in hex format
func (c *Certificate) GetSerialNumberHex() string {
	asn1Num := C.X509_get_serialNumber(c.x)
	bignum := C.ASN1_INTEGER_to_BN(asn1Num, nil)
	defer C.BN_free(bignum)

	hex := C.BN_bn2hex(bignum)
	defer C.X_OPENSSL_free(unsafe.Pointer(hex))

	serial := C.GoString(hex)

	return serial
}

// GetVersion returns the X509 version of the certificate.
func (c *Certificate) GetVersion() X509Version {
	return X509Version(C.X_X509_get_version(c.x))
}

// SetVersion sets the X509 version of the certificate.
func (c *Certificate) SetVersion(version X509Version) error {
	cvers := C.long(version)
	if C.X_X509_set_version(c.x, cvers) != 1 {
		return fmt.Errorf("failed to set certificate version: %w", PopError())
	}
	return nil
}

func getDigestFunction(digest DigestAlgo) *C.EVP_MD {
	var md *C.EVP_MD
	switch digest {
	case DigestNull:
		md = C.X_EVP_md_null()
	case DigestMD5:
		md = C.X_EVP_md5()
	case DigestSHA:
		md = C.X_EVP_sha()
	case DigestSHA1:
		md = C.X_EVP_sha1()
	case DigestDSS:
		md = C.X_EVP_dss()
	case DigestDSS1:
		md = C.X_EVP_dss1()
	case DigestSHA224:
		md = C.X_EVP_sha224()
	case DigestSHA256:
		md = C.X_EVP_sha256()
	case DigestSHA384:
		md = C.X_EVP_sha384()
	case DigestSHA512:
		md = C.X_EVP_sha512()
	case DigestSM3:
		md = C.X_EVP_sm3()
	}
	return md
}

// LoadPEMFromFile loads a PEM file and returns the []byte format.
func LoadPEMFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	pemBlock, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return pemBlock, nil
}

// SavePEMToFile saves a PEM block to a file.
func SavePEMToFile(pemBlock []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(pemBlock)
	if err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}

	return nil
}
