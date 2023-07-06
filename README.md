# tongsuo-go-sdk
tongsuo bindings for Go

# quick start

```
git clone https://github.com/Tongsuo-Project/Tongsuo.git  tongsuo
```

```
cd tongsuo &&  ./config --prefix=/opt/tongsuo -Wl,-rpath,/opt/tongsuo/lib  enable-ssl-trace enable-ec_elgamal enable-ntls && make -j && make install
```

```
go test -exec "env LD_LIBRARY_PATH=/opt/tongsuo/lib" ./...
```
