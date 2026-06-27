.PHONY: help build test benchmark format format-check clean \
        deps compile jar install  ci-test ci-format ci-qodana ci-semgrep \
        qodana semgrep test-unit test-integration \
        install-pipx install-semgrep

UNAME_S := $(shell uname -s 2>/dev/null)
DETECTED_OS := Linux
GRADLE := ./gradlew
PWD := $(shell pwd)
.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

deps: ## Download and cache dependencies
	$(GRADLE) dependencies --no-daemon

compile: ## Compile the application
	$(GRADLE) compileJava --no-daemon

jar: ## Build JAR file
	$(GRADLE) bootJar --no-daemon

build: format-check compile jar ## Full build with format check

##@ Testing

test: ## Run all tests
	$(GRADLE) clean test --info --no-daemon

test-unit: ## Run unit tests only
	$(GRADLE) test --tests '*Test' --no-daemon

test-integration: ## Run integration tests only
	$(GRADLE) test --tests '*IT' --no-daemon

##@ Bench mark
benchmark: ## Run JMH benchmarks
	$(GRADLE) jmh --no-daemon

##@ Code Quality

format: ## Format code (Java and YAML)
	@if [ -f "format.sh" ]; then \
		chmod +x format.sh && ./format.sh; \
	else \
		echo "Error: No format script found (format.sh or format.bat)"; \
		exit 1; \
	fi

format-check: ## Verify code formatting
	@if [ -f "format.sh" ]; then \
		chmod +x format.sh && ./format.sh; \
	else \
		echo "Error: No format script found (format.sh or format.bat)"; \
		exit 1; \
	fi
	@git diff --exit-code || (echo "Formatting issues detected. Run 'make format' to fix." && exit 1)

lint: ## Run linting checks
	$(GRADLE) check --no-daemon

qodana: ## Run Qodana code analysis
	@mkdir -p $(PWD)/qodana-results
	@docker run --rm \
		-v $(PWD):/data/project \
		-v $(PWD)/qodana-results:/data/results \
		jetbrains/qodana-jvm-community:latest \
		--save-report --results-dir=/data/results

install-pipx: ## Install pipx based on OS
	@if ! command -v pipx >/dev/null 2>&1; then \
		echo "Installing pipx on Linux..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y pipx; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y pipx; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install -y pipx; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm python-pipx; \
		else \
			python3 -m pip install --user pipx; \
			python3 -m pipx ensurepath; \
		fi; \
	else \
		echo "pipx is already installed"; \
	fi

install-semgrep: install-pipx ## Install Semgrep using pipx
	@if ! command -v semgrep >/dev/null 2>&1; then \
		echo "Installing Semgrep via pipx..."; \
		pipx install semgrep || (echo "Failed to install Semgrep" && exit 1); \
	else \
		echo "Semgrep is already installed"; \
	fi

semgrep: install-semgrep ## Run Semgrep security scanning
	@semgrep ci --config=auto --sarif --output=semgrep.sarif --verbose

ci-test: test ## Run CI test pipeline locally

ci-format: format-check ## Run CI format check locally

ci-qodana: qodana ## Run CI Qodana pipeline locally

ci-semgrep: semgrep ## Run CI Semgrep pipeline locally

##@ Cleanup

clean: ## Clean build artifacts
	@rm -rf build/

clean-all: clean ## Complete cleanup

##@ Setup

install: ## Install and verify development tools
	@test -f google-java-format-1.28.0-all-deps.jar || \
		curl -L -o google-java-format-1.28.0-all-deps.jar \
		https://github.com/google/google-java-format/releases/download/v1.28.0/google-java-format-1.28.0-all-deps.jar
	@if [ -f "format.sh" ]; then chmod +x format.sh; fi
	@if [ -d "yamlfmt" ]; then chmod +x yamlfmt/* 2>/dev/null || true; fi

verify: ## Verify development environment
	@echo "Detected OS: $(DETECTED_OS)"
	@echo "Gradle command: $(GRADLE)"
	@java -version
	@$(GRADLE) --version