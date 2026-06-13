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

# Init a throwaway store and run the node against it (Ctrl-C to stop).
run-demo: build
	./$(BINARY) init -data ./data -unseal-key-out ./unseal-key
	./$(BINARY) server -data ./data -unseal-key ./unseal-key

clean:
	rm -f $(BINARY) unseal-key
	rm -rf data
