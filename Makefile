VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test cover lint clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o mailguard ./cmd/mailguard

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	gofmt -l . | (! grep .)
	go vet ./...

clean:
	rm -f mailguard coverage.out
