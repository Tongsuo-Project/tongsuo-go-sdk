package main

import (
	"encoding/hex"
	"fmt"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

var sm2_key1 = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe
-----END PRIVATE KEY-----
`)

func main() {
	data := []byte("hello world")

	priv, err := crypto.LoadPrivateKeyFromPEM(sm2_key1)
	if err != nil {
		panic(err)
	}

	pub := priv.Public()

	// Encrypt data
	ciphertext, err := sm2.Encrypt(pub, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("SM2(%s)=%s\n", data, hex.EncodeToString(ciphertext))

	// Decrypt ciphertext
	plaintext, err := sm2.Decrypt(priv, ciphertext)
	if err != nil {
		panic(err)
	}

	if string(plaintext) != string(data) {
		panic("Decryption failure")
	}

	fmt.Printf("Decryption OK: %s\n", plaintext)
}
