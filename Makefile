.PHONY: help install install-dev test test-unit test-integration test-benchmark lint format format-check type-check security clean pre-commit

# Default target
help:
	@echo "Cerberus Development Commands"
	@echo "=============================="
	@echo "install           - Install package in editable mode"
	@echo "install-dev       - Install package with dev dependencies"
	@echo "test              - Run all tests with coverage"
	@echo "test-unit         - Run only unit tests"
	@echo "test-integration  - Run only integration tests"
	@echo "test-benchmark    - Run performance benchmarks"
	@echo "lint              - Run all linters (ruff + pylint)"
	@echo "format            - Auto-format code with black and isort"
	@echo "format-check      - Check code formatting without modifying"
	@echo "type-check        - Run mypy type checker"
	@echo "security          - Run security scans (bandit + pip-audit)"
	@echo "clean             - Remove cache and generated files"
	@echo "pre-commit        - Run all pre-commit checks (format, test-unit, lint, type-check)"

# Installation
install:
	pip install -e .

install-dev:
	pip install -r requirements-dev.txt
	pip install -e .

# Testing
test:
	pytest tests/unit/ tests/integration/ -v --cov=cerberus --cov-report=term-missing --cov-report=html

test-unit:
	pytest tests/unit/ -v --cov=cerberus

test-integration:
	pytest tests/integration/ -v

test-benchmark:
	pytest tests/benchmarks/ --benchmark-only --benchmark-verbose

# Linting
lint:
	ruff check src/ tests/
	@echo "Ruff checks passed ✓"

# Formatting
format:
	black src/ tests/
	isort src/ tests/
	@echo "Code formatted ✓"

format-check:
	black --check src/ tests/
	isort --check-only src/ tests/

# Type checking
type-check:
	mypy src/cerberus/

# Security
security:
	bandit -r src/ -ll
	pip-audit
	@echo "Security checks passed ✓"

# Cleanup
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov/ dist/ build/
	@echo "Cleaned up cache and generated files ✓"

# CI targets (for local CI simulation)
ci-quality: format-check lint type-check
ci-security: security
ci-test: test

# Pre-commit target (matches what pre-commit hooks will check)
pre-commit: format test-unit lint type-check
	@echo "✅ Pre-commit checks passed! Safe to commit."
