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

package sm3

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/tjfoc/gmsm/sm3"
)

func TestSM3(t *testing.T) {
	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		var got, expected [SM3_DIGEST_LENGTH]byte

		s := sm3.Sm3Sum(buf)
		got = SM3Sum(buf)
		copy(expected[:], s[:SM3_DIGEST_LENGTH])

		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	}
}

func TestSM3Writer(t *testing.T) {
	ohash, err := New()
	if err != nil {
		t.Fatal(err)
	}
	hash := sm3.New()

	for i := 0; i < 100; i++ {
		ohash.Reset()
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

		var got, exp [SM3_DIGEST_LENGTH]byte

		hash.Sum(exp[:0])
		ohash.Sum(got[:0])

		if got != exp {
			t.Fatalf("exp:%x got:%x", exp, got)
		}
	}
}

type sm3func func([]byte)

func benchmarkSM3(b *testing.B, length int64, fn sm3func) {
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

func BenchmarkSM3Large_openssl(b *testing.B) {
	benchmarkSM3(b, 1024*1024, func(buf []byte) { SM3Sum(buf) })
}

func BenchmarkSM3Large_stdlib(b *testing.B) {
	benchmarkSM3(b, 1024*1024, func(buf []byte) { sm3.Sm3Sum(buf) })
}

func BenchmarkSM3Normal_openssl(b *testing.B) {
	benchmarkSM3(b, 1024, func(buf []byte) { SM3Sum(buf) })
}

func BenchmarkSM3Normal_stdlib(b *testing.B) {
	benchmarkSM3(b, 1024, func(buf []byte) { sm3.Sm3Sum(buf) })
}

func BenchmarkSM3Small_openssl(b *testing.B) {
	benchmarkSM3(b, 1, func(buf []byte) { SM3Sum(buf) })
}

func BenchmarkSM3Small_stdlib(b *testing.B) {
	benchmarkSM3(b, 1, func(buf []byte) { sm3.Sm3Sum(buf) })
}
