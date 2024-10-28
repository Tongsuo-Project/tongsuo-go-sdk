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

package md5_test

import (
	"crypto/md5"
	"crypto/rand"
	"io"
	"testing"

	tsMD5 "github.com/tongsuo-project/tongsuo-go-sdk/crypto/md5"
)

func TestMD5(t *testing.T) {
	t.Parallel()

	for i := 0; i < 100; i++ {
		buf := make([]byte, 10*1024-i)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			t.Fatal(err)
		}

		var got, expected [tsMD5.MDSize]byte

		s := md5.Sum(buf)
		got = tsMD5.Sum(buf)

		copy(expected[:], s[:tsMD5.MDSize])

		if expected != got {
			t.Fatalf("exp:%x got:%x", expected, got)
		}
	}
}

func TestMD5Writer(t *testing.T) {
	t.Parallel()

	ohash, err := tsMD5.New()
	if err != nil {
		t.Fatal(err)
	}

	hash := md5.New()

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

		var got, exp [tsMD5.MDSize]byte

		hash.Sum(exp[:0])
		ohash.Sum(got[:0])

		if got != exp {
			t.Fatalf("exp:%x got:%x", exp, got)
		}
	}
}

type md5func func([]byte)

func benchmarkMD5(b *testing.B, length int64, fn md5func) {
	b.Helper()

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

func BenchmarkMD5Large_openssl(b *testing.B) {
	benchmarkMD5(b, 1024*1024, func(buf []byte) { tsMD5.Sum(buf) })
}

func BenchmarkMD5Large_stdlib(b *testing.B) {
	benchmarkMD5(b, 1024*1024, func(buf []byte) { md5.Sum(buf) })
}

func BenchmarkMD5Normal_openssl(b *testing.B) {
	benchmarkMD5(b, 1024, func(buf []byte) { tsMD5.Sum(buf) })
}

func BenchmarkMD5Normal_stdlib(b *testing.B) {
	benchmarkMD5(b, 1024, func(buf []byte) { md5.Sum(buf) })
}

func BenchmarkMD5Small_openssl(b *testing.B) {
	benchmarkMD5(b, 1, func(buf []byte) { tsMD5.Sum(buf) })
}

func BenchmarkMD5Small_stdlib(b *testing.B) {
	benchmarkMD5(b, 1, func(buf []byte) { md5.Sum(buf) })
}
