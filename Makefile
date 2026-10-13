.PHONY: build test vet release demo clean

build:
	CGO_ENABLED=0 go build -trimpath -o infralens .

test:
	go vet ./...
	go test ./...

release:
	scripts/release.sh

demo: build
	./infralens demo --out demo

clean:
	rm -rf dist demo infralens
