BINDIR ?= $(HOME)/bin
OPA_BASE_CAPS_VERSION ?= v1.13.1

# DocC documentation settings. SwiftOPASDK is the landing module, Runtime and
# Config have the actual public symbols (SwiftOPASDK only re-exports them).
# `DOCS_HOSTING_BASE_PATH` is the sub-path the static site is served under.
DOCS_OUTPUT_DIR ?= .build/docs
DOCS_TARGETS ?= --target SwiftOPASDK --target Runtime --target Config
DOCS_HOSTING_BASE_PATH ?= swift-opa-sdk

.PHONY: all
all: fmt lint test build

.PHONY: fmt
fmt:
	swift format format --parallel --recursive -i .

.PHONY: lint
lint:
	swift format lint --strict --parallel --recursive .

.PHONY: test
test:
	mkdir -p .build/test-results
	@if command -v openssl >/dev/null 2>&1; then \
		echo "openssl detected on PATH; enabling OpenSSL-dependent tests"; \
		SWIFT_OPA_OPENSSL_TESTS=1 swift test --xunit-output .build/test-results/junit.xml; \
	else \
		echo "openssl NOT found on PATH; OpenSSL-dependent tests will be skipped"; \
		swift test --xunit-output .build/test-results/junit.xml; \
	fi

.PHONY: test-compliance
test-compliance:
	$(MAKE) -C ComplianceSuite test-compliance

.PHONY: perf
perf:
	cd Benchmarks && swift package benchmark

.PHONY: build
build:
	swift build
	
.PHONY: build-release
build-release:
	swift build -c release

# CI-specific targets. `build-ci` builds the code and tests in one pass, and
# `test-ci` (which depends on it) runs with `--skip-build`. Test artifacts are
# written outside `.build` so they don't pollute the cached build directory.
.PHONY: build-ci
build-ci:
	swift build --build-tests

.PHONY: test-ci
test-ci: build-ci
	mkdir -p test-results
	@if command -v openssl >/dev/null 2>&1; then \
		echo "openssl detected on PATH; enabling OpenSSL-dependent tests"; \
		SWIFT_OPA_OPENSSL_TESTS=1 swift test --skip-build --xunit-output test-results/junit.xml; \
	else \
		echo "openssl NOT found on PATH; OpenSSL-dependent tests will be skipped"; \
		swift test --skip-build --xunit-output test-results/junit.xml; \
	fi

.PHONY: ensure-bindir
ensure-bindir:
ifeq ($(shell test -d "$(BINDIR)"; echo $$?),1)
	$(error BINDIR "$(BINDIR)" does not exist.)
endif

.PHONY: install-release
install-release: build-release ensure-bindir
	install $(shell swift build --show-bin-path -c release)/swift-opa-cli $(BINDIR)/

.PHONY: generate
generate:
	curl -o opa-capabilities.json https://raw.githubusercontent.com/open-policy-agent/opa/refs/tags/$(OPA_BASE_CAPS_VERSION)/capabilities.json
	swift run swift-opa-cli capabilities opa-capabilities.json > capabilities.json

.PHONY: clean
clean:
	rm -rf .build

# Generate a static-hosting DocC site combining the public SDK targets into
# `$(DOCS_OUTPUT_DIR)`. Requires SWIFT_PREVIEW_DOCS so Package.swift pulls in
# swift-docc-plugin. Override DOCS_HOSTING_BASE_PATH to match the serving path.
.PHONY: docs
docs:
	SWIFT_PREVIEW_DOCS=1 swift package \
		--allow-writing-to-directory "$(DOCS_OUTPUT_DIR)" \
		generate-documentation \
		--enable-experimental-combined-documentation \
		$(DOCS_TARGETS) \
		--transform-for-static-hosting \
		--hosting-base-path "$(DOCS_HOSTING_BASE_PATH)" \
		--output-path "$(DOCS_OUTPUT_DIR)"

# Serve the Runtime docs locally with live reload. Combined docs aren't
# supported in preview mode, so this previews a single target.
.PHONY: docs-preview
docs-preview:
	SWIFT_PREVIEW_DOCS=1 swift package --disable-sandbox \
		preview-documentation --target Runtime

.PHONY: clean-docs
clean-docs:
	rm -rf "$(DOCS_OUTPUT_DIR)"

.PHONY: generate-compliance-tests
generate-compliance-tests:
	cd tools/generate-compliance-tests && go run main.go ../../ComplianceSuite/Tests/RegoComplianceTests/TestData/v1