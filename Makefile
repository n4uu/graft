VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet lint fixtures clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/graft ./cmd/graft

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run || \
		echo "golangci-lint not installed, ran go vet only"

clean:
	rm -rf bin graft-report.*

install: build
	install -Dm755 bin/graft /usr/local/bin/graft
