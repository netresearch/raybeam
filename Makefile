.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS=":.*##"; printf "\nUsage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the raybeam binary
	go build -o raybeam .

.PHONY: install
install: ## Install raybeam to GOPATH/bin
	go install .

.PHONY: run
run: ## Run raybeam (requires LDAP env vars)
	go run . serve

.PHONY: fmt
fmt: ## Format Go code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: vet ## Alias for vet (no separate linter configured)

.PHONY: test
test: ## Run all tests
	go test ./... -v

.PHONY: test-race
test-race: ## Run tests with race detector
	go test ./... -race

.PHONY: test-cover
test-cover: ## Run tests with coverage
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: test-short
test-short: ## Run only unit tests (skip integration)
	go test ./... -short

.PHONY: typecheck
typecheck: ## Run type checking (go build with no output)
	go build -o /dev/null ./...

.PHONY: check
check: fmt vet test ## Run all checks (format, vet, test)

.PHONY: clean
clean: ## Remove built binaries and test artifacts
	rm -f raybeam
	rm -f coverage.out coverage.html
	go clean

.PHONY: mod-tidy
mod-tidy: ## Tidy go.mod and go.sum
	go mod tidy
	go mod verify

.PHONY: mod-update
mod-update: ## Update all dependencies
	go get -u ./...
	go mod tidy

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t raybeam:latest .

.PHONY: docker-run
docker-run: ## Run Docker container (requires LDAP)
	docker run -it --rm -p 8080:8080 raybeam:latest

.DEFAULT_GOAL := help