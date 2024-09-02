.PHONY: install
install:
	@echo "Installing..."
	go install github.com/bombsimon/wsl/v4/cmd...@v4.4.1
	go install mvdan.cc/gofumpt@v0.6.0
	go install github.com/daixiang0/gci@v0.13.4
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/ogen-go/ogen/cmd/ogen@latest
	npm install -g @stoplight/spectral-cli@6.11.1

.PHONY: generate
generate:
	@echo "Generating..."
	go run ./scripts/lucide.go
	ogen --target api --clean openapi.yaml

.PHONY: fmt
fmt:
	@echo "Formatting..."
	go mod tidy
	go fmt ./...
	gci write -s standard -s default -s "prefix(github.com/SecurityBrewery/catalyst-analysis)" .
	gofumpt -l -w .
	wsl -fix ./... || true

.PHONY: lint_spectral
lint_spectral:
	spectral lint openapi.yaml

.PHONY: lint
lint: lint_spectral
	golangci-lint version
	golangci-lint run -v ./...

.PHONY: test
test:
	@echo "Testing..."
	go test -v ./...

@PHONY: test_short
test_short:
	@echo "Running short tests"
	@go test -v -short ./...

.PHONY: test-coverage
test-coverage:
	@echo "Testing with coverage..."
	go test -coverpkg=./... -coverprofile=coverage.out -count 1 ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out
