# tongsuo-go-sdk

Tongsuo bindings for Go.

## Feature

- Symmetric algorithms: SM4
- Digital signature algorithms: SM2withSM3
- Hash algorithms: SM3, MD5, SHA1, SHA256
- Secure transport protocol: TLCP, TLSv1.0/1.1/1.2/1.3

## quick start

### Install Tongsuo

tongsuo-go-sdk is based on Tongsuo, so we must install Tongsuo firstly.
Build and install Tongsuo from source code is as follows:

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo

git checkout 8.3-stable

./config --prefix=/opt/tongsuo --libdir=/opt/tongsuo/lib enable-ntls
make -j
make install
```

### Test tongsuo-go-sdk

On Linux:

```bash
LD_LIBRARY_PATH=/opt/tongsuo/lib CGO_CFLAGS="-I/opt/tongsuo/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L/opt/tongsuo/lib" go test ./...
```

On MacOS:

```bash
DYLD_LIBRARY_PATH=/opt/tongsuo/lib CGO_CFLAGS="-I/opt/tongsuo/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L/opt/tongsuo/lib" go test ./...
```

### Run example

On Linux:

```bash
LD_LIBRARY_PATH=/opt/tongsuo/lib CGO_CFLAGS="-I/opt/tongsuo/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L/opt/tongsuo/lib" go run examples/sm4/sm4
```

On MacOS:

```bash
DYLD_LIBRARY_PATH=/opt/tongsuo/lib CGO_CFLAGS="-I/opt/tongsuo/include -Wno-deprecated-declarations" CGO_LDFLAGS="-L/opt/tongsuo/lib" go run examples/sm4/sm4.go
```
