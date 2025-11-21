# Cerberus - Python CLI Security Analysis Tool

## Project Overview
Cerberus is a command-line security tool for recursively analyzing files and folders to detect malware, suspicious files, and security risks. Built with Python, it emphasizes clean architecture, testability, and professional development practices.

### Core Purpose
- **Malware Detection**: Identify potentially malicious files through pattern matching, heuristics, and hash lookups
- **Risk Assessment**: Flag suspicious file types, permissions, hidden files, and anomalies
- **Recursive Scanning**: Deep directory traversal with configurable depth and exclusions
- **Threat Intelligence**: Optional integration with hash databases (VirusTotal, malware repositories)

## Architecture & Design Principles

### SOLID Principles Application
- **Single Responsibility**: Separate analyzers for different detection methods (hash matching, signature scanning, heuristic analysis, permission checks)
- **Open/Closed**: Use abstract base classes for analyzers; add new detection rules without modifying core engine
- **Liskov Substitution**: All analyzer implementations must be interchangeable and return standardized risk scores
- **Interface Segregation**: Small, focused interfaces (e.g., `MalwareScanner`, `RiskAssessor`, `ThreatReporter`)
- **Dependency Inversion**: Depend on abstractions, inject signature databases and hash providers via constructors

### Project Structure
```
cerberus/
├── src/
│   ├── cerberus/
│   │   ├── __init__.py
│   │   ├── cli.py              # Click CLI entry point
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py      # Abstract base scanner
│   │   │   ├── models.py       # Risk assessment data models
│   │   │   └── risk_scorer.py  # Risk calculation logic
│   │   ├── scanners/
│   │   │   ├── __init__.py
│   │   │   ├── hash_scanner.py      # MD5/SHA256 hash matching
│   │   │   ├── signature_scanner.py # Pattern/signature detection
│   │   │   ├── heuristic_scanner.py # Behavioral analysis
│   │   │   ├── permission_scanner.py # Dangerous permissions (SUID, etc.)
│   │   │   ├── filetype_scanner.py   # Suspicious extensions/types
│   │   │   └── chunk_processor.py    # Streaming analysis for large files
│   │   ├── signatures/
│   │   │   ├── __init__.py
│   │   │   ├── yara_rules/     # YARA rules (if used)
│   │   │   └── patterns.json   # Known malicious patterns
│   │   ├── integrations/
│   │   │   ├── __init__.py
│   │   │   ├── virustotal.py   # VirusTotal API (optional)
│   │   │   └── hash_database.py # Local hash DB lookup
│   │   ├── reporters/
│   │   │   ├── __init__.py
│   │   │   ├── console.py
│   │   │   ├── json.py
│   │   │   └── csv.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── file_walker.py  # Recursive directory traversal
│   │       ├── hash_utils.py   # File hashing utilities
│   │       └── chunked_reader.py # Memory-efficient file reading
├── tests/
│   ├── unit/
│   │   ├── scanners/
│   │   └── utils/
│   ├── integration/
│   └── fixtures/
│       ├── malicious_samples/  # Test files (EICAR, etc.)
│       └── benign_samples/
├── data/
│   ├── known_malware_hashes.txt  # SHA256 hashes
│   └── suspicious_patterns.json   # Regex patterns
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
├── README.md
└── Makefile
```

## Development Workflow

### Environment Setup (CRITICAL)
**ALWAYS use a virtual environment** - never install packages globally:
```bash
# Create venv
python3 -m venv venv

# Activate (do this in every new session)
source venv/bin/activate

# Verify you're in venv (should show venv path)
which python

# Install dependencies
pip install -r requirements-dev.txt
pip install -e .  # Install in editable mode
```

### Code Quality Standards
- **Formatting**: Use `black` with default settings (88 char line length)
- **Linting**: Use `ruff` or `flake8` + `pylint`
- **Type Checking**: Use `mypy` with strict mode enabled
- **Testing**: Use `pytest` with >80% coverage target

### Testing Requirements
- **Unit tests**: Test each scanner in isolation with mocks
- **Integration tests**: Test scanner combinations and risk scoring
- **Test fixtures**: Use `tests/fixtures/` for sample files
  - **EICAR test file**: Standard antivirus test file (safe to use)
  - **Benign samples**: Known-safe files for false positive testing
  - **Mock malicious patterns**: Synthetic risky files
- **Coverage**: Run `pytest --cov=cerberus --cov-report=html`
- **Test naming**: `test_<scanner>_<scenario>_<expected_result>`
- **Safety**: Never use real malware samples in tests; use EICAR or synthetic patterns

Example test structure:
```python
# tests/unit/scanners/test_hash_scanner.py
import pytest
from cerberus.scanners.hash_scanner import HashScanner
from cerberus.core.models import RiskLevel

class TestHashScanner:
    @pytest.fixture
    def scanner(self):
        malware_hashes = {"44d88612fea8a8f36de82e1278abb02f"}  # Known bad hash
        return HashScanner(malware_hashes)

    def test_scan_detects_malicious_hash(self, scanner, tmp_path):
        # Arrange
        malicious_file = tmp_path / "bad.exe"
        malicious_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")

        # Act
        result = scanner.scan(malicious_file)

        # Assert
        assert result.risk_level == RiskLevel.HIGH
        assert "hash match" in result.reason.lower()
```

### Performance Benchmarking
**Critical**: Track performance metrics to make informed decisions about optimizations and library changes.

#### Benchmark Structure
```
tests/
├── benchmarks/
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures for benchmark files
│   ├── benchmark_hash_scanner.py
│   ├── benchmark_signature_scanner.py
│   ├── benchmark_chunked_reader.py
│   └── benchmark_full_scan.py   # End-to-end scanning
```

#### Using pytest-benchmark
```python
# Install: pip install pytest-benchmark
# tests/benchmarks/benchmark_hash_scanner.py
import pytest
from pathlib import Path
from cerberus.scanners.hash_scanner import HashScanner
from cerberus.utils.hash_utils import calculate_hash_streaming

class TestHashScannerPerformance:
    @pytest.fixture
    def test_files(self, tmp_path):
        """Generate test files of various sizes."""
        files = {}
        sizes = {
            'small': 1024,           # 1KB
            'medium': 1024 * 1024,   # 1MB
            'large': 10 * 1024 * 1024,  # 10MB
            'xlarge': 100 * 1024 * 1024  # 100MB
        }
        for name, size in sizes.items():
            file_path = tmp_path / f"test_{name}.bin"
            file_path.write_bytes(b'A' * size)
            files[name] = file_path
        return files

    def test_hash_small_file(self, benchmark, test_files):
        """Benchmark hash calculation for 1KB file."""
        result = benchmark(calculate_hash_streaming, test_files['small'])
        assert len(result) == 64  # SHA256 hex length

    def test_hash_large_file(self, benchmark, test_files):
        """Benchmark hash calculation for 100MB file."""
        result = benchmark(calculate_hash_streaming, test_files['xlarge'])
        assert len(result) == 64

    def test_scanner_throughput(self, benchmark, test_files, tmp_path):
        """Measure files scanned per second."""
        scanner = HashScanner(set())

        # Create 100 small files
        files = [tmp_path / f"file_{i}.txt" for i in range(100)]
        for f in files:
            f.write_bytes(b'test content')

        def scan_batch():
            return [scanner.scan(f) for f in files]

        results = benchmark(scan_batch)
        assert len(results) == 100
```

#### Running Benchmarks
```bash
# Run all benchmarks
pytest tests/benchmarks/ -v

# Run with statistics
pytest tests/benchmarks/ --benchmark-only --benchmark-verbose

# Save baseline for comparison
pytest tests/benchmarks/ --benchmark-save=baseline

# Compare against baseline after changes
pytest tests/benchmarks/ --benchmark-compare=baseline

# Generate histogram
pytest tests/benchmarks/ --benchmark-histogram
```

#### Benchmark Targets & Metrics
Track these key performance indicators:

**Hash Scanner**:
- Target: >100 MB/s for streaming hash calculation
- Metric: `time_per_mb = execution_time / file_size_mb`

**Signature Scanner**:
- Target: >50 MB/s for pattern matching with 100 patterns
- Metric: `patterns_per_second = num_patterns / execution_time`

**Chunked Reader**:
- Target: Memory usage stays constant regardless of file size
- Metric: `memory_delta = max_memory - baseline_memory`

**Full Scan**:
- Target: >1000 files/minute for small files (<1MB)
- Target: >10 files/minute for large files (>100MB)
- Metric: `throughput = files_scanned / total_time`

#### Continuous Performance Monitoring
```python
# tests/benchmarks/conftest.py
import pytest
import psutil
import os

@pytest.fixture
def memory_monitor():
    """Monitor memory usage during test."""
    process = psutil.Process(os.getpid())
    baseline = process.memory_info().rss / (1024 * 1024)  # MB

    yield baseline

    final = process.memory_info().rss / (1024 * 1024)
    delta = final - baseline
    if delta > 100:  # Alert if memory increased by >100MB
        pytest.fail(f"Memory leak detected: {delta:.2f}MB increase")
```

#### Integration with Makefile
```makefile
.PHONY: benchmark benchmark-compare

benchmark:
	pytest tests/benchmarks/ --benchmark-only --benchmark-autosave

benchmark-compare:
	pytest tests/benchmarks/ --benchmark-compare --benchmark-compare-fail=mean:10%

benchmark-report:
	pytest tests/benchmarks/ --benchmark-histogram=benchmark_results
```

#### Performance Regression Prevention
- Run benchmarks in CI/CD pipeline
- Fail builds if performance degrades >10% from baseline
- Document performance changes in commit messages
- Review benchmark reports before merging performance-sensitive PRs

## Chunked File Processing (CRITICAL)

### Design Principle
**Never skip files due to size** - use streaming/chunked analysis to handle files of any size without loading them entirely into memory.

### Implementation Strategy
```python
# utils/chunked_reader.py
from pathlib import Path
from typing import Iterator

def read_chunks(file_path: Path, chunk_size: int = 8192) -> Iterator[bytes]:
    """
    Yield file chunks without loading entire file into memory.
    Default chunk size: 8KB (adjustable based on scanner needs)
    """
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            yield chunk

# Example: Hash calculation for large files
import hashlib

def calculate_hash_streaming(file_path: Path) -> str:
    """Calculate SHA256 hash using streaming for memory efficiency."""
    sha256 = hashlib.sha256()
    for chunk in read_chunks(file_path, chunk_size=65536):  # 64KB chunks
        sha256.update(chunk)
    return sha256.hexdigest()
```

### Scanner-Specific Chunking
Different scanners need different approaches:

**Hash Scanner**: Stream entire file through hash function
```python
# Efficient for any file size, constant memory usage
hash_value = calculate_hash_streaming(large_file)
```

**Signature Scanner**: Search patterns in chunks with overlap
```python
# Handle patterns that might span chunk boundaries
OVERLAP_SIZE = 1024  # Pattern overlap between chunks

def scan_patterns_chunked(file_path: Path, patterns: List[bytes]) -> bool:
    previous_tail = b""
    for chunk in read_chunks(file_path):
        # Combine overlap from previous chunk
        searchable = previous_tail + chunk

        for pattern in patterns:
            if pattern in searchable:
                return True

        # Keep tail for next iteration
        previous_tail = chunk[-OVERLAP_SIZE:] if len(chunk) >= OVERLAP_SIZE else chunk
    return False
```

**Heuristic Scanner**: Analyze first/last N bytes + sample middle
```python
def analyze_file_structure(file_path: Path) -> dict:
    """
    Analyze file without reading it all:
    - First 1MB (headers, magic bytes)
    - Last 1MB (footers, signatures)
    - Random samples from middle (for large files)
    """
    file_size = file_path.stat().st_size
    with open(file_path, 'rb') as f:
        header = f.read(1024 * 1024)  # First 1MB

        if file_size > 2 * 1024 * 1024:
            f.seek(-1024 * 1024, 2)  # Seek to last 1MB
            footer = f.read()
        else:
            footer = b""

    return analyze_bytes(header, footer)
```

### Chunk Size Guidelines
- **Hash calculation**: 64KB chunks (balances I/O and memory)
- **Pattern matching**: 8KB-16KB with overlap
- **String extraction**: 4KB chunks
- **Binary analysis**: Read only needed sections (PE headers, ELF sections)

### Progress Reporting for Large Files
```python
def scan_with_progress(file_path: Path) -> ScanResult:
    """Show progress for files larger than threshold."""
    file_size = file_path.stat().st_size
    LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100MB

    if file_size > LARGE_FILE_THRESHOLD:
        logger.info(f"Scanning large file: {file_path.name} ({file_size / (1024**3):.2f} GB)")
        # Implement progress callback

    return perform_scan(file_path)
```

### Memory Safety
- Set maximum chunk size limits (prevent malicious huge "chunks")
- Implement timeout for individual file scans
- Track memory usage during scans
- Fail gracefully if file becomes inaccessible mid-scan

## CLI Design Patterns

### Command Structure
Use **Click** library for robust CLI (preferred over argparse):
```python
import click

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--recursive', '-r', is_flag=True, help='Scan recursively')
@click.option('--max-depth', type=int, default=None, help='Maximum recursion depth')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'csv']), default='text')
@click.option('--scanner', '-s', multiple=True, help='Specific scanners to run')
@click.option('--exclude', multiple=True, help='Patterns to exclude (e.g., "*.log")')
@click.option('--min-risk', type=click.Choice(['low', 'medium', 'high']), help='Minimum risk to report')
def scan(path, recursive, max_depth, format, scanner, exclude, min_risk):
    """Scan files or folders at PATH for malware and security risks."""
    pass
```

### Error Handling
- Use custom exceptions in `cerberus/exceptions.py`
- Catch filesystem errors (permissions, not found, etc.)
- Provide actionable error messages
- Exit with appropriate codes (0=success, 1=general error, 2=invalid usage)

## CI/CD Pipeline (GitHub Actions)

### Quality Gates for Pull Requests
Run these checks on every PR to maintain code quality:

#### 1. **Tests** (Functionality)
```yaml
- pytest tests/unit/ -v --cov=cerberus --cov-report=xml --cov-report=term
- pytest tests/integration/ -v
- Coverage threshold: 100% (exclude specific files in pyproject.toml if needed)
```

#### 2. **Linting** (Static Code Analysis)
```yaml
- ruff check src/ tests/          # Fast Python linter
- pylint src/cerberus/            # Deep code analysis
- Exit on any errors, warnings are reported
```

#### 3. **Type Checking** (Type Safety)
```yaml
- mypy src/cerberus/ --strict
- Catch type errors before runtime
```

#### 4. **Code Formatting** (Style Consistency)
```yaml
- black --check src/ tests/       # Check formatting
- isort --check-only src/ tests/  # Check import order
- Fail PR if code isn't formatted
```

#### 5. **Security Scanning** (Vulnerability Detection)
```yaml
- bandit -r src/                  # Security issues in code
- pip-audit                       # Known vulnerabilities in dependencies (recommended over safety)
```

#### 6. **Performance Benchmarks** (Regression Prevention)
```yaml
- pytest tests/benchmarks/ --benchmark-only --benchmark-compare=main
- Fail if performance degrades >10% from main branch
- Comment benchmark comparison on PR
```

#### 7. **Dependency Analysis** (Supply Chain Security)
```yaml
- pip-audit                       # Audit dependencies
- Check for outdated critical packages
```

### GitHub Actions Workflow Structure
```yaml
# .github/workflows/ci.yml
name: CI

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

jobs:
  # Job 1: Code Quality (fast checks)
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      - run: pip install -r requirements-dev.txt
      - name: Format check
        run: |
          black --check src/ tests/
          isort --check-only src/ tests/
      - name: Lint
        run: |
          ruff check src/ tests/
          pylint src/cerberus/
      - name: Type check
        run: mypy src/cerberus/ --strict

  # Job 2: Security (parallel with quality)
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - name: Security scan
        run: |
          bandit -r src/ -ll
          pip-audit

  # Job 3: Tests (multiple Python versions)
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.13']  # Single version for now, matrix ready for expansion
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: 'pip'
      - run: pip install -e . -r requirements-dev.txt
      - name: Run tests
        run: |
          pytest tests/unit/ tests/integration/ -v \
            --cov=cerberus \
            --cov-report=xml \
            --cov-report=term \
            --cov-fail-under=100
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        if: matrix.python-version == '3.13'
        with:
          file: ./coverage.xml

  # Job 4: Benchmarks (only on PR, compare to main)
  benchmark:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need history for comparison
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      - run: pip install -e . -r requirements-dev.txt

      # Benchmark current PR
      - name: Run benchmarks (PR)
        run: |
          pytest tests/benchmarks/ \
            --benchmark-only \
            --benchmark-json=pr-bench.json

      # Checkout main and benchmark
      - name: Checkout main
        run: git checkout main
      - name: Run benchmarks (main)
        run: |
          pip install -e . -r requirements-dev.txt
          pytest tests/benchmarks/ \
            --benchmark-only \
            --benchmark-json=main-bench.json

      # Compare and fail if >10% regression
      - name: Compare benchmarks
        run: |
          pytest-benchmark compare main-bench.json pr-bench.json \
            --group-by=name \
            --fail-on-regression=10%
```

### Pre-commit Hooks (Local Development)
Install pre-commit hooks to catch issues before pushing:
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ['--maxkb=500']

  - repo: local
    hooks:
      - id: pytest-fast
        name: pytest-fast
        entry: pytest tests/unit/ -x
        language: system
        pass_filenames: false
        always_run: true

# Install: pip install pre-commit && pre-commit install
```

### Recommended Tools & Their Purposes

| Tool | Purpose | Fail PR? | Speed |
|------|---------|----------|-------|
| **pytest** | Unit & integration tests | Yes | Medium |
| **pytest-cov** | Code coverage measurement | Yes (if <80%) | Medium |
| **black** | Code formatting | Yes | Fast |
| **isort** | Import sorting | Yes | Fast |
| **ruff** | Fast linting (replaces flake8, pylint partially) | Yes | Very Fast |
| **pylint** | Deep code analysis | Yes (errors only) | Slow |
| **mypy** | Type checking | Yes | Medium |
| **bandit** | Security vulnerability scanner | Yes (high severity) | Fast |
| **pip-audit** | Dependency vulnerability check | Yes (critical) | Fast |
| **pytest-benchmark** | Performance regression detection | Yes (if >10% slower) | Slow |

### CI Optimization Tips
1. **Cache dependencies**: Use `actions/setup-python` with `cache: 'pip'`
2. **Parallel jobs**: Run quality, security, and tests in parallel
3. **Fail fast**: Put fastest checks first (format → lint → type → test)
4. **Matrix testing**: Test multiple Python versions (3.10, 3.11, 3.12)
5. **Conditional benchmarks**: Only run on PRs, not every push
6. **Artifacts**: Save coverage reports and benchmark results

### Makefile Integration
```makefile
.PHONY: ci-local ci-quality ci-security ci-test

# Run all CI checks locally before pushing
ci-local: ci-quality ci-security ci-test

ci-quality:
	black --check src/ tests/
	isort --check-only src/ tests/
	ruff check src/ tests/
	pylint src/cerberus/
	mypy src/cerberus/ --strict

ci-security:
	bandit -r src/ -ll
	pip-audit

ci-test:
	pytest tests/ -v --cov=cerberus --cov-fail-under=100

# Fix formatting issues
format-fix:
	black src/ tests/
	isort src/ tests/
	ruff check src/ tests/ --fix
```

### Branch Protection Rules
Configure in GitHub repository settings:
- ✅ Require status checks to pass before merging
- ✅ Require branches to be up to date before merging
- ✅ Required checks: `quality`, `security`, `test`, `benchmark`
- ✅ Require pull request reviews (1+ approvers)
- ✅ Dismiss stale reviews when new commits pushed
- ❌ Do not allow bypassing required checks

**Note**: As solo developer, you can disable PR review requirement initially and enable it if collaborators join.

## Git Workflow

### Commit Conventions
Follow conventional commits:
- `feat:` New features
- `fix:` Bug fixes
- `refactor:` Code restructuring
- `test:` Adding/updating tests
- `docs:` Documentation changes
- `chore:` Maintenance tasks

### Branch Strategy
- `main`: Stable, production-ready code
- `develop`: Integration branch
- `feature/*`: New features
- `fix/*`: Bug fixes

### Pre-commit Checklist
```bash
# Before committing
make test          # Run all tests
make lint          # Check code quality
make format        # Auto-format code
git add .
git commit -m "feat: add file size analyzer"
```

## Key Conventions

### Imports
Order imports by: standard library → third-party → local
```python
import os
from pathlib import Path
from typing import List, Optional

import click
from dataclasses import dataclass

from cerberus.core.scanner import Scanner
from cerberus.core.models import ScanResult
```

### Type Hints
Always use type hints for function signatures:
```python
def scan_file(path: Path, scanners: List[Scanner]) -> ScanResult:
    pass
```

### Configuration
- Use `pyproject.toml` for tool configuration (pytest, black, mypy, etc.)
- Store user config in `~/.config/cerberus/config.toml` or via environment variables
- Use `python-dotenv` for local development overrides

### Logging
Use Python's logging module:
```python
import logging

logger = logging.getLogger(__name__)
logger.debug("Scanning file: %s", path)
logger.warning("Suspicious file detected: %s", path)
```

## Common Tasks (Makefile)
```makefile
.PHONY: test lint format install clean

install:
	pip install -e .
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v --cov=cerberus

lint:
	ruff check src/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .coverage htmlcov/
```

## Dependencies Management

### Core Dependencies (requirements.txt)
- `click>=8.0` - CLI framework
- `rich>=10.0` - Beautiful terminal output (optional, for enhanced formatting)
- `pydantic>=2.0` - Data validation (if using instead of dataclasses)

### Development Dependencies (requirements-dev.txt)
- `pytest>=7.0`
- `pytest-cov>=4.0`
- `pytest-benchmark>=4.0` - Performance benchmarking
- `psutil>=5.9` - Memory monitoring in benchmarks
- `black>=23.0`
- `ruff>=0.1.0`
- `mypy>=1.0`
- `isort>=5.0`
- `bandit>=1.7` - Security linting
- `pip-audit>=2.6` - Dependency vulnerability scanning
- `pre-commit>=3.5` - Git hooks for local checks

## AI Agent Guidelines

### When Adding Features
1. Start with defining the interface/abstract class
2. Write tests first (TDD approach)
3. Implement the minimal solution
4. Refactor while keeping tests green
5. Update documentation

### When Debugging
1. Check if running in virtual environment (`which python`)
2. Verify all tests pass in isolation
3. Use `pytest -vv` for detailed test output
4. Check type hints with `mypy`

### When Refactoring
1. Ensure test coverage exists first
2. Refactor in small, atomic commits
3. Run full test suite after each change
4. Update docstrings and type hints

## Documentation Standards

### Required Documentation Files
Maintain these files throughout development:

#### 1. **README.md** (User-Facing)
Primary entry point for users and evaluators. Must include:
```markdown
# Cerberus - Security File Scanner

## Overview
Brief description of what Cerberus does and why it exists

## Features
- List of key capabilities
- What makes it different/useful

## Installation
```bash
# From source
git clone https://github.com/home-kops/cerberus
cd cerberus
python -m venv venv
source venv/bin/activate
pip install -e .
```

## Quick Start
```bash
# Basic scan
cerberus /path/to/scan

# Recursive scan with options
cerberus /path/to/scan --recursive --format json
```

## Usage Examples
Common use cases with actual commands

## Configuration
Available options and how to configure

## Development
How to contribute (link to CONTRIBUTING.md if needed)

## License
```

**Update README.md when:**
- Adding new features or scanners
- Changing CLI interface
- Modifying configuration options
- Adding new dependencies

#### 2. **CHANGELOG.md** (Release History)
Track user-facing changes using [Keep a Changelog](https://keepachangelog.com/) format:
```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- New feature descriptions

### Changed
- Modified behavior descriptions

### Fixed
- Bug fix descriptions

## [0.1.0] - 2025-11-21
### Added
- Initial release
- Hash-based malware detection
- File type risk assessment
```

**Update CHANGELOG.md when:**
- Merging features to main
- Fixing bugs
- Changing behavior
- Deprecating functionality

#### 3. **Code Documentation** (Developer-Facing)
Use docstrings for all public functions/classes (Google style):
```python
def scan_file(path: Path, scanners: List[Scanner]) -> ScanResult:
    """Scan a file using provided scanners and aggregate results.

    Args:
        path: Absolute path to the file to scan.
        scanners: List of scanner instances to use for analysis.

    Returns:
        ScanResult containing aggregated risk assessment and findings.

    Raises:
        FileNotFoundError: If the specified file doesn't exist.
        PermissionError: If the file cannot be read.

    Example:
        >>> result = scan_file(Path("/tmp/test.exe"), [hash_scanner])
        >>> print(result.risk_level)
        RiskLevel.HIGH
    """
    pass
```

**Update docstrings when:**
- Creating new functions/classes
- Changing function signatures
- Modifying behavior or return values
- Adding new exceptions

#### 4. **Architecture Documentation** (Complex Decisions)
For non-obvious architectural decisions, add comments or docs/ADR.md:
```python
# Why we use chunked reading:
# Large files (GB+) must not be loaded into memory entirely.
# Streaming approach keeps memory constant regardless of file size.
# See: utils/chunked_reader.py for implementation details
```

### Documentation Review Checklist
Before merging any PR, verify:
- [ ] README.md reflects new features/changes
- [ ] CHANGELOG.md entry added for user-facing changes
- [ ] All new public functions have docstrings
- [ ] Complex logic has explanatory comments
- [ ] CLI help text updated (`--help` output)

### Automated Documentation Checks
```makefile
.PHONY: docs-check

docs-check:
	# Check for missing docstrings
	interrogate src/cerberus/ --fail-under=100 -vv

	# Validate README has required sections
	grep -q "## Installation" README.md
	grep -q "## Quick Start" README.md
	grep -q "## Usage" README.md
```

**Note**: Keep documentation concise but complete. README is your project's resume - make it count.

## Future Considerations
**Note**: These will be addressed in later phases, after MVP is complete:
- **Distribution**: PyPI package for `pip install cerberus-scanner`
- **Containerization**: Docker image for isolated scanning environments
- **Release automation**: GitHub Actions workflow for versioned releases

Focus on building a solid, tested, performant tool first. Distribution infrastructure comes after the core is stable.
