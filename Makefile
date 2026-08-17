# ServerGuard Makefile
# Build, test, and package the complete ServerGuard suite

VERSION ?= 0.1.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

LDFLAGS := -X 'github.com/suoten/serverguard/internal/version.Version=$(VERSION)' \
           -X 'github.com/suoten/serverguard/internal/version.BuildTime=$(BUILD_TIME)' \
           -X 'github.com/suoten/serverguard/internal/version.GitCommit=$(GIT_COMMIT)' \
           -X 'github.com/suoten/serverguard/internal/version.GoVersion=$(GO_VERSION)' \
           -X 'github.com/suoten/serverguard/internal/version.OS=$(GOOS)' \
           -X 'github.com/suoten/serverguard/internal/version.Arch=$(GOARCH)'

CGO_ENABLED ?= 1

.PHONY: all agent hub sgctl clean test vet fmt build-web install-deps

all: agent hub sgctl build-web

# Build the agent binary
agent:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o bin/serverguard-agent ./cmd/serverguard-agent

# Build the hub binary
hub:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o bin/serverguard-hub ./cmd/serverguard-hub

# Build the sgctl CLI
sgctl:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o bin/sgctl ./cmd/sgctl

# Build all binaries for current platform
build: agent hub sgctl

# Cross-compile for Linux amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(MAKE) build

# Cross-compile for Linux arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 $(MAKE) build

# Build web frontend
build-web:
	cd web && npm install && npm run build

# Dev mode for web frontend
dev-web:
	cd web && npm install && npm run dev

# Run tests
test:
	go test -v ./...

# Run vet
vet:
	go vet ./...

# Format code
fmt:
	go fmt ./...

# Clean build artifacts
clean:
	rm -rf bin/ web/node_modules/ web/dist/

# Install Go dependencies
install-deps:
	go mod tidy
	go mod download

# Package for release
package: build-linux-amd64
	mkdir -p release
	cp bin/serverguard-agent release/
	cp bin/sgctl release/
	cp scripts/install.sh release/
	cp scripts/serverguard.service release/
	tar -czf release/serverguard-$(VERSION)-linux-amd64.tar.gz -C release serverguard-agent sgctl install.sh serverguard.service

# Run agent locally
run: agent
	./bin/serverguard-agent

# Run hub locally
run-hub: hub
	./bin/serverguard-hub

# Show help
help:
	@echo "ServerGuard Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build agent, hub, sgctl, and web panel"
	@echo "  agent         - Build the agent binary"
	@echo "  hub           - Build the hub binary"
	@echo "  sgctl         - Build the sgctl CLI"
	@echo "  build         - Build all binaries"
	@echo "  build-web     - Build the Vue3 web panel"
	@echo "  dev-web       - Run web panel in dev mode"
	@echo "  test          - Run tests"
	@echo "  vet           - Run go vet"
	@echo "  fmt           - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  package       - Create release package"
	@echo "  run           - Run agent locally"
	@echo "  run-hub       - Run hub locally"
