# tongsuo-go-sdk

Tongsuo bindings for Go.

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
LD_LIBRARY_PATH=/opt/tongsuo/lib go test ./...
```

On MacOS:

```bash
DYLD_LIBRARY_PATH=/opt/tongsuo/lib go test ./...
```

### Run example

On Linux:

```bash
cd examples/sm4
go build
LD_LIBRARY_PATH=/opt/tongsuo/lib ./sm4
```

On MacOS:

```bash
cd examples/sm4
go build
DYLD_LIBRARY_PATH=/opt/tongsuo/lib ./sm4
```
