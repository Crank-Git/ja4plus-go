.PHONY: build test lint bench clean

build:
	go build -o bin/ja4plus ./cmd/ja4plus

test:
	go test -v -race ./...

lint:
	golangci-lint run

bench:
	go test -bench=. -benchmem ./...

clean:
	rm -rf bin/
