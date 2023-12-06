# tongsuo-go-sdk
tongsuo bindings for Go

# quick start

## Install Tongsuo

tongsuo-go-sdk is based on Tongsuo, so we must install Tongsuo firstly.
Build and install Tongsuo based on source code is as follows:

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo

git checkout 8.3-stable

./config --prefix=/opt/tongsuo --libdir=/opt/tongsuo/lib -Wl,-rpath,/opt/tongsuo/lib enable-ssl-trace enable-ntls
make -j
make install
```

## Test tongsuo-go-sdk

```bash
export CGO_CFLAGS='-O2 -g -I/opt/tongsuo/include'
export CGO_LDFLAGS='-O2 -g -L/opt/tongsuo/lib -lssl -lcrypto'

cd tongsuo-go-sdk
go test -exec "env LD_LIBRARY_PATH=/opt/tongsuo/lib" ./...
```
