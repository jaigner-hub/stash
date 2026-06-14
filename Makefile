BINARY := stash
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build release test vet fmt tidy run-demo clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/stash

# Portable static binary for rolling out to the cluster (runs on NixOS too).
# See docs/DEPLOY.md.
release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/stash

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

# Generate a key and run a throwaway single-node cluster (Ctrl-C to stop).
run-demo: build
	./$(BINARY) init -unseal-key-out ./unseal-key
	./$(BINARY) server -data ./data -unseal-key ./unseal-key -bootstrap

clean:
	rm -f $(BINARY) unseal-key
	rm -rf data
