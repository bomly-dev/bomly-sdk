# Keep GOLANGCI_LINT_VERSION in sync with the golangci-lint-action `version`
# input in .github/workflows/ci.yml.
GOLANGCI_LINT_VERSION=v2.12.0
GOPATH_BIN=$(shell go env GOPATH)/bin
EXE_SUFFIX=$(if $(filter Windows_NT,$(OS)),.exe,)
GOLANGCI_LINT=$(GOPATH_BIN)/golangci-lint$(EXE_SUFFIX)
FUZZTIME?=60s

.PHONY: test vet fmt fmt-check lint tidy-check fuzz install-hooks

test:
	go test ./...

vet:
	go vet ./...

fmt:
	git ls-files -z '*.go' | xargs -0 gofmt -w

# Fails, listing the offenders, when any tracked Go file is not gofmt-clean.
# `gofmt -l` exits 0 even when it lists files, so the check is on its output.
fmt-check:
	@unformatted="$$(git ls-files -z '*.go' | xargs -0 gofmt -l)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

$(GOLANGCI_LINT): Makefile
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

tidy-check:
	go mod tidy -diff

fuzz:
	FUZZTIME="$(FUZZTIME)" scripts/run-fuzz.sh

install-hooks:
	git config core.hooksPath .githooks
