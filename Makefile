all:
	go build -tags tongsuo
test:
	go test -v -tags tongsuo
bench:
	go test -v -run notexist -bench SM3 -tags tongsuo
