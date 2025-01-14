# Tongsuo-Go-SDK

Tongsuo-Go-SDK uses Tongsuo to provide cryptographic primitives and secure transport protocols for
golang applications.

## Features

- Hash algorithms: SM3, MD5, SHA1, SHA256
- Symmetric algorithms: SM4
- SM2 keygen, encryption and decryption
- Digital signature algorithm: SM2withSM3
- Message Authentication Code: HMAC
- Support issuing SM2 certificate
- Secure transport protocols: TLCP, TLSv1.0/1.1/1.2/1.3

## Installation

tongsuo-go-sdk is based on Tongsuo, so we must install Tongsuo firstly.
Build and install Tongsuo from source code is as follows:

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo

git checkout 8.3-stable

./config --prefix=/opt/tongsuo --libdir=/opt/tongsuo/lib enable-ntls enable-export-sm4
make -j
make install
```

Then install tongsuo-go-sdk:

```bash
go get github.com/tongsuo-project/tongsuo-go-sdk
```

### Run examples

On Linux:

```bash
TONGSUO_HOME=/opt/tongsuo
LD_LIBRARY_PATH=${TONGSUO_HOME}/lib CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" go run examples/sm4/main.go
```

On MacOS:

```bash
TONGSUO_HOME=/opt/tongsuo
DYLD_LIBRARY_PATH=${TONGSUO_HOME}/lib CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" go run examples/sm4/main.go
```

### Run tests

On Linux:

```bash
TONGSUO_HOME=/opt/tongsuo
LD_LIBRARY_PATH=${TONGSUO_HOME}/lib CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" go test ./...
```

On MacOS:

```bash
TONGSUO_HOME=/opt/tongsuo
DYLD_LIBRARY_PATH=${TONGSUO_HOME}/lib CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib" go test ./...
```
