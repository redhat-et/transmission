
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin

.PHONY: help
help:
	@echo "Targets:"
	@echo "    tidy:        tidy go mod"
	@echo "    lint:        run golangci-lint"
	@echo "    build:       run all builds"
	@echo "    test:        run all tests"

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: lint
lint: tools
	git ls-files go.mod '**/*go.mod' -z | xargs -0 -I{} bash -xc 'cd $$(dirname {}) && $(GOBIN)/golangci-lint run ./...'

.PHONY: build
build:
	go build -o $(GOBIN) ./cmd/...

.PHONY: test
test:
	git ls-files go.mod '**/*go.mod' -z | xargs -0 -I{} bash -xc 'cd $$(dirname {}) && go test -cover ./...'

.PHONY: tools
tools: $(GOBIN)/golangci-lint

$(GOBIN)/golangci-lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.54.0
