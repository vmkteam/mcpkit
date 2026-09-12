LINT_VERSION := v2.13.2

PKG := `go list -f {{.Dir}} ./...`

ifeq ($(RACE),1)
	GOFLAGS+=-race
endif

.PHONY: *

tools:
	@curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/${LINT_VERSION}/install.sh | sh -s -- -b $(go env GOPATH)/bin ${LINT_VERSION}

fmt:
	@golangci-lint fmt

lint:
	@golangci-lint version
	@golangci-lint config verify
	@golangci-lint run

test:
	@echo "Running tests"
	@go test -count=1 $(GOFLAGS) -coverprofile=coverage.txt -covermode count $(PKG)

test-race:
	@CGO_ENABLED=1 go test -count=1 -race $(PKG)

# run: the example server from example/main.go. It speaks the same /mcp the
# README curl talks to, so the recipe there can be checked without a service.
run:
	@go run ./example -api-key demo-token

mod:
	@go mod tidy
