BINDIR ?= $(HOME)/bin
OPA_BASE_CAPS_VERSION ?= v1.13.1

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

.PHONY: generate-compliance-tests
generate-compliance-tests:
	cd tools/generate-compliance-tests && go run main.go ../../ComplianceSuite/Tests/RegoComplianceTests/TestData/v1