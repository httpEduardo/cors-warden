BINARY  := cors-warden
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test -race -cover ./...

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...

run:
	go run ./cmd/$(BINARY) -input examples/responses.txt -trusted example.com

clean:
	rm -rf bin/
