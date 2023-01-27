.PHONY: build-wasm

all: build-wasm

build-wasm:
	cd wasm && GOOS=js GOARCH=wasm go build -o  ../build/pgp.wasm

