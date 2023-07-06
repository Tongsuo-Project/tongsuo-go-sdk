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

package sha256

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

func Test(t *testing.T) {
	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		expected := sha256.Sum256(buf)
		got, err := Sum(buf)
		if err != nil {
			t.Fatal(err)
		}

		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	}
}

func TestWriter(t *testing.T) {
	ohash, err := New()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()

	for i := 0; i < 100; i++ {
		if err := ohash.Reset(); err != nil {
			t.Fatal(err)
		}
		hash.Reset()
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		if _, err := ohash.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := hash.Write(buf); err != nil {
			t.Fatal(err)
		}

		var got, exp [32]byte

		hash.Sum(exp[:0])
		got, err := ohash.Sum()
		if err != nil {
			t.Fatal(err)
		}

		if got != exp {
			t.Fatalf("exp:%x got:%x", exp, got)
		}
	}
}

func benchmark(b *testing.B, length int64, fn func([]byte)) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(length)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(buf)
	}
}

func BenchmarkLarge_openssl(b *testing.B) {
	benchmark(b, 1024*1024, func(buf []byte) { Sum(buf) })
}

func BenchmarkLarge_stdlib(b *testing.B) {
	benchmark(b, 1024*1024, func(buf []byte) { sha256.Sum256(buf) })
}

func BenchmarkSmall_openssl(b *testing.B) {
	benchmark(b, 1, func(buf []byte) { Sum(buf) })
}

func BenchmarkSmall_stdlib(b *testing.B) {
	benchmark(b, 1, func(buf []byte) { sha256.Sum256(buf) })
}
