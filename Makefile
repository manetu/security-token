# Copyright Manetu Inc. All Rights Reserved.

PROJECT_NAME := manetu-security-token
GOPROJECT := github.com/manetu/security-token

VERSIONARGS := -X $(GOPROJECT)/version.GitCommit=$(shell git log -n1 --format=format:"%H")\
			   -X $(GOPROJECT)/version.GoVersion=$(shell go version | cut -d' ' -f3) \
			   -X $(GOPROJECT)/version.BuildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

.PHONY: all clean lint test goimports staticcheck tests sec-scan bin

all: lint test race staticcheck goimports sec-scan bin

lint: ## Run unittests
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go vet

test: ## Run unittests
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go test -cover -coverprofile=coverage.out -coverpkg=./... ./...

race: ## Run data race detector
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go test ./... -race -short .

staticcheck: ## Run data race detector
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@staticcheck -f stylish  ./...

goimports: ## Run goimports
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	$(eval goimportsdiffs = $(shell goimports -l .))
	@if [ -n "$(goimportsdiffs)" ]; then\
		echo "goimports shows diffs for these files:";\
		echo "$(goimportsdiffs)";\
		exit 1;\
	fi

clean: ## Remove previous build
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@-rm manetu-security-token

bin: ## Build the exe
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	go build -ldflags "$(VERSIONARGS)" -o manetu-security-token

sec-scan: ## Run gosec; see https://github.com/securego/gosec
	@gosec ./...

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
