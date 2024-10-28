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

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

func TestECDH(t *testing.T) {
	t.Parallel()

	myKey, err := crypto.GenerateECKey(crypto.Prime256v1)
	if err != nil {
		t.Fatal(err)
	}

	peerKey, err := crypto.GenerateECKey(crypto.Prime256v1)
	if err != nil {
		t.Fatal(err)
	}

	mySecret, err := crypto.DeriveSharedSecret(myKey, peerKey)
	if err != nil {
		t.Fatal(err)
	}

	theirSecret, err := crypto.DeriveSharedSecret(peerKey, myKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mySecret, theirSecret) {
		t.Fatal("shared secrets are different")
	}
}
