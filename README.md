# Cerberus - Security File Scanner

**A Python CLI tool for detecting malware and assessing security risks in files and directories.**

Cerberus recursively analyzes files using multiple detection methods including hash matching, signature scanning, heuristic analysis, and permission checks. Built with professional development practices and designed for both homelab security and production use.

## Features

- 🔍 **Recursive Directory Scanning** - Deep analysis with configurable depth
- 🎯 **Multiple Detection Methods** - Hash matching, signatures, heuristics, permissions
- 📊 **Risk Assessment** - Clear risk levels (Safe, Low, Medium, High, Critical)
- ⚡ **Chunked File Processing** - Handle files of any size without memory issues
- 🎨 **Multiple Output Formats** - Text, JSON, CSV reporting
- 🧪 **Fully Tested** - 100% test coverage with performance benchmarks
- 🔒 **Security-First** - Built following SOLID principles and best practices

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/home-kops/cerberus.git
cd cerberus

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
make install-dev

# Or install just the package
make install
```

## Quick Start

```bash
# Scan a single file
cerberus /path/to/file

# Recursive scan of a directory
cerberus /path/to/directory --recursive

# Scan with specific output format
cerberus /path/to/scan --format json

# Limit recursion depth
cerberus /path/to/scan --recursive --max-depth 3

# Filter by minimum risk level
cerberus /path/to/scan --min-risk high
```

## Development

### Prerequisites

- Python 3.13+
- pip
- make (optional, for convenient commands)

### Setup Development Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
make install-dev

# Run tests
make test

# Run linters
make lint

# Format code
make format

# Type check
make type-check

# Run security scans
make security
```

### Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes following our conventions (see `.github/copilot-instructions.md`)
3. Run tests and linters: `make test lint type-check`
4. Commit using conventional commits: `git commit -m "feat: add new scanner"`
5. Push and create a pull request

### Project Structure

```
cerberus/
├── src/cerberus/           # Main package
│   ├── core/               # Core models and base classes
│   ├── scanners/           # Detection implementations
│   ├── utils/              # Utility functions
│   └── reporters/          # Output formatting
├── tests/                  # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   ├── benchmarks/         # Performance tests
│   └── fixtures/           # Test data
├── pyproject.toml          # Project configuration
└── Makefile                # Development commands
```

## Contributing

Contributions are welcome! Please read our development guidelines in `.github/copilot-instructions.md` and ensure all tests pass before submitting a PR.

## License

MIT License - See LICENSE file for details

## Author

**home-kops** - [GitHub](https://github.com/home-kops)

---

**Note**: This project is in active development. Features and APIs may change.
