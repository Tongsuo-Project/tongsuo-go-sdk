// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"sync"
	"unsafe"
)

const (
	SSLRecordSize = 16 * 1024
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

var writeBioMapping = newMapping()

type WriteBio struct {
	dataMtx        sync.Mutex
	opMtx          sync.Mutex
	buf            []byte
	releaseBuffers bool
}

func loadWritePtr(b *C.BIO) *WriteBio {
	t := token(C.X_BIO_get_data(b))

	return (*WriteBio)(writeBioMapping.Get(t))
}

func bioClearRetryFlags(b *C.BIO) {
	C.X_BIO_clear_flags(b, C.BIO_FLAGS_RWS|C.BIO_FLAGS_SHOULD_RETRY)
}

func bioSetRetryRead(b *C.BIO) {
	C.X_BIO_set_flags(b, C.BIO_FLAGS_READ|C.BIO_FLAGS_SHOULD_RETRY)
}

//export go_write_bio_write
func go_write_bio_write(bio *C.BIO, data *C.char, size C.int) C.int {
	var rc C.int

	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: writeBioWrite panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadWritePtr(bio)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()
	bioClearRetryFlags(bio)
	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
	rc = size

	return rc
}

//export go_write_bio_ctrl
func go_write_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
	_, _ = arg1, arg2 // unused

	var rc C.long

	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_WPENDING:
		rc = writeBioPending(bio)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		rc = 1
	default:
		rc = 0
	}

	return rc
}

func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()

	return C.long(len(ptr.buf))
}

func (bio *WriteBio) WriteTo(writer io.Writer) (int64, error) {
	bio.opMtx.Lock()
	defer bio.opMtx.Unlock()

	// write whatever data we currently have
	bio.dataMtx.Lock()
	data := bio.buf
	bio.dataMtx.Unlock()

	if len(data) == 0 {
		return 0, nil
	}
	n, err := writer.Write(data)

	// subtract however much data we wrote from the buffer
	bio.dataMtx.Lock()
	bio.buf = bio.buf[:copy(bio.buf, bio.buf[n:])]
	if bio.releaseBuffers && len(bio.buf) == 0 {
		bio.buf = nil
	}
	bio.dataMtx.Unlock()

	return int64(n), err
}

func (bio *WriteBio) SetRelease(flag bool) {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.releaseBuffers = flag
}

func (bio *WriteBio) Disconnect(b *C.BIO) {
	if loadWritePtr(b) == bio {
		writeBioMapping.Del(token(C.X_BIO_get_data(b)))
		C.X_BIO_set_data(b, nil)
	}
}

func (bio *WriteBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_write_bio()
	token := writeBioMapping.Add(unsafe.Pointer(bio))
	C.X_BIO_set_data(rv, unsafe.Pointer(token))

	return rv
}

var readBioMapping = newMapping()

type ReadBio struct {
	dataMtx        sync.Mutex
	opMtx          sync.Mutex
	buf            []byte
	eof            bool
	releaseBuffers bool
}

func loadReadPtr(b *C.BIO) *ReadBio {
	return (*ReadBio)(readBioMapping.Get(token(C.X_BIO_get_data(b))))
}

//export go_read_bio_read
func go_read_bio_read(bio *C.BIO, data *C.char, size C.int) C.int {
	rc := 0

	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: go_read_bio_read panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadReadPtr(bio)
	if ptr == nil || size < 0 {
		return -1
	}
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()
	bioClearRetryFlags(bio)
	if len(ptr.buf) == 0 {
		if ptr.eof {
			return 0
		}
		bioSetRetryRead(bio)
		return -1
	}
	if size == 0 || data == nil {
		return C.int(len(ptr.buf))
	}
	rc = copy(nonCopyCString(data, size), ptr.buf)
	ptr.buf = ptr.buf[:copy(ptr.buf, ptr.buf[rc:])]
	if ptr.releaseBuffers && len(ptr.buf) == 0 {
		ptr.buf = nil
	}
	return C.int(rc)
}

//export go_read_bio_ctrl
func go_read_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
	_, _ = arg1, arg2 // unused

	var rc C.long
	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: readBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_PENDING:
		rc = readBioPending(bio)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		rc = 1
	default:
		rc = 0
	}

	return rc
}

func readBioPending(b *C.BIO) C.long {
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()
	return C.long(len(ptr.buf))
}

func (bio *ReadBio) SetRelease(flag bool) {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.releaseBuffers = flag
}

func (bio *ReadBio) ReadFromOnce(r io.Reader) (int, error) {
	bio.opMtx.Lock()
	defer bio.opMtx.Unlock()

	// make sure we have a destination that fits at least one SSL record
	bio.dataMtx.Lock()
	if cap(bio.buf) < len(bio.buf)+SSLRecordSize {
		newBuf := make([]byte, len(bio.buf), len(bio.buf)+SSLRecordSize)
		copy(newBuf, bio.buf)
		bio.buf = newBuf
	}

	dst := bio.buf[len(bio.buf):cap(bio.buf)]
	dstSlice := bio.buf
	bio.dataMtx.Unlock()

	n, err := r.Read(dst)
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	if n > 0 {
		if len(dstSlice) != len(bio.buf) {
			// someone shrunk the buffer, so we read in too far ahead and we
			// need to slide backwards
			copy(bio.buf[len(bio.buf):len(bio.buf)+n], dst)
		}
		bio.buf = bio.buf[:len(bio.buf)+n]
	}

	if err != nil {
		return n, fmt.Errorf("read from once error: %w", err)
	}

	return n, nil
}

func (bio *ReadBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_read_bio()
	token := readBioMapping.Add(unsafe.Pointer(bio))
	C.X_BIO_set_data(rv, unsafe.Pointer(token))
	return rv
}

func (bio *ReadBio) Disconnect(b *C.BIO) {
	if loadReadPtr(b) == bio {
		readBioMapping.Del(token(C.X_BIO_get_data(b)))
		C.X_BIO_set_data(b, nil)
	}
}

func (bio *ReadBio) MarkEOF() {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.eof = true
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (bio *anyBio) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_read((*C.BIO)(bio), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (bio *anyBio) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	ret := int(C.X_BIO_write((*C.BIO)(bio), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if ret < 0 {
		return 0, fmt.Errorf("BIO write failed: %w", PopError())
	}
	if ret < len(buf) {
		return ret, fmt.Errorf("BIO write trucated: %w", ErrPartialWrite)
	}
	return ret, nil
}
