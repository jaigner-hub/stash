BINARY := stash

.PHONY: build test vet fmt tidy run-demo clean

build:
	go build -o $(BINARY) ./cmd/stash

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
