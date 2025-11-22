"""Scanner Architecture Documentation

This document describes the architecture, design principles, and integration patterns
for Cerberus scanners - the modular detection engines that analyze files for security risks.
"""

# Scanner Architecture

## Overview

Cerberus uses a modular scanner architecture where each scanner implements a specific
detection method. Scanners can be composed together, allowing flexible configuration
for different security analysis scenarios.

All scanners inherit from the `Scanner` abstract base class and follow a standardized
interface for scanning files and reporting results.

## Core Concepts

### Scanner Interface

The `Scanner` abstract base class defines the contract all scanners must implement:

```python
from abc import ABC, abstractmethod
from pathlib import Path
from cerberus.core import ScanResult

class Scanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner identifier."""
        pass

    @abstractmethod
    def scan(self, file_path: Path) -> ScanResult:
        """Scan a file and return risk assessment."""
        pass
```

### ScanResult

Each scanner returns a standardized `ScanResult` containing:

- **file_path** (`Path`): Path to the scanned file
- **risk_level** (`RiskLevel`): Assessment of risk (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
- **reason** (`str`): Human-readable explanation of the risk
- **scanner_name** (`str`): Identifier of the scanner that produced this result
- **details** (`dict[str, str] | None`): Additional diagnostic information

### Risk Level Hierarchy

Risk levels are ordered and comparable:

```
SAFE < LOW < MEDIUM < HIGH < CRITICAL
```

Scanner implementations should assign risk levels based on their detection confidence:

- **SAFE**: No risk detected
- **LOW**: Minor concerns or low-confidence detections
- **MEDIUM**: Notable anomalies or moderate risk indicators
- **HIGH**: Significant risk indicators or high-confidence detections
- **CRITICAL**: Definitive threat (e.g., hash match with known malware)

## Scanner Types

### 1. HashScanner

**Purpose**: Detect known malware through hash-based database lookup

**Detection Method**:
- Calculates file hash (SHA256/MD5)
- Compares against database of known malicious file hashes
- Zero false positives (only flags known malicious files)

**Risk Assignment**:
- Hash matches database → CRITICAL
- Hash not in database → SAFE

**Characteristics**:
- Very fast (single pass through file)
- Memory-efficient (streaming hash calculation)
- Deterministic (same file always produces same result)
- No false positives (depends on hash database quality)

### 2. SignatureScanner

**Purpose**: Detect malware through pattern/signature matching

**Detection Method**:
- Searches file content for known malicious patterns
- Uses regex patterns or binary sequences
- Handles patterns that span chunk boundaries with overlap

**Risk Assignment**:
- Pattern found → HIGH
- No patterns found → SAFE

**Characteristics**:
- Medium speed (full file scan with pattern matching)
- Streaming approach (chunks with overlap)
- Can produce false positives/negatives depending on signature quality
- Flexible (patterns can be updated without code changes)

### 3. HeuristicScanner

**Purpose**: Detect malware through behavioral and structural analysis

**Detection Method**:
- Analyzes file headers, magic bytes, and structure
- Detects entropy patterns (compressed/encrypted content)
- Identifies suspicious characteristics without signatures
- Samples files for efficiency (doesn't require full file read)

**Risk Assignment**:
- Multiple suspicious indicators → MEDIUM/HIGH
- One suspicious indicator → LOW/MEDIUM
- No indicators → SAFE

**Characteristics**:
- Medium speed (targeted file sampling)
- Memory-efficient (reads samples, not entire file)
- Heuristic approach (may have false positives)
- Context-aware (same characteristic means different risk in different contexts)

### 4. PermissionScanner

**Purpose**: Detect dangerous file permissions

**Detection Method**:
- Checks for SUID/SGID privilege escalation bits
- Identifies world-writable files
- Detects world-readable sensitive files
- Analyzes unusual permission configurations

**Risk Assignment**:
- SUID on user scripts → HIGH
- SUID on system binaries → MEDIUM
- World-writable on system files → HIGH
- World-writable on temp files → LOW

**Characteristics**:
- Very fast (single stat call)
- Unix/Linux specific (behavior differs on Windows)
- Context-dependent (same permission means different risk based on file purpose)
- No false positives (permissions are objectively present or absent)

### 5. FileTypeScanner

**Purpose**: Detect risky files based on extension and content

**Detection Method**:
- Checks file extensions against dangerous type list
- Detects double extensions (e.g., .pdf.exe)
- Verifies extension matches actual file type (magic bytes)
- Identifies extension/content mismatches

**Risk Assignment**:
- Dangerous extension (.exe) → HIGH
- Double extension (.pdf.exe) → CRITICAL
- Extension/content mismatch → MEDIUM/HIGH
- Safe extension → SAFE

**Characteristics**:
- Very fast (reads only first KB for MIME detection)
- Effective against deceptive file types
- Can detect simple file type spoofing
- May have false positives if MIME detection is ambiguous

## Design Principles

### 1. Single Responsibility

Each scanner focuses on one detection method. This allows:
- Independent testing and validation
- Clear reasoning about what each scanner does
- Easy replacement or swapping of implementations

### 2. Pluggable Architecture

Scanners implement a common interface, enabling:
- Composition of multiple scanners
- Dynamic scanner selection
- Aggregation of results from different methods

### 3. Memory Efficiency

All scanners use streaming/chunked file processing:
- No file size limitations (supports GB+ files)
- Constant memory usage regardless of file size
- Efficient I/O with configurable chunk sizes

**Chunked Reading Pattern**:
```python
from cerberus.utils import read_chunks

for chunk in read_chunks(file_path, chunk_size=65536):
    # Process chunk without loading entire file
    process(chunk)
```

**Hash Calculation Pattern**:
```python
from cerberus.utils import calculate_hash_streaming

file_hash = calculate_hash_streaming(file_path)  # Efficient for any file size
```

### 4. Standardized Error Handling

All scanners handle the same error cases:
- `FileNotFoundError`: File does not exist
- `PermissionError`: File cannot be read
- `IsADirectoryError`: Path is a directory, not a file

This consistency enables reliable error handling at higher levels.

### 5. Immutable Results

`ScanResult` objects are immutable after creation, ensuring:
- Results can be safely passed between components
- No accidental modification of historical scan data
- Thread-safe result passing

## Scanner Composition

Scanners can be combined to perform comprehensive analysis:

```python
from cerberus.scanners import HashScanner, SignatureScanner, FileTypeScanner

hash_scanner = HashScanner(known_malware_hashes)
signature_scanner = SignatureScanner(malicious_patterns)
file_type_scanner = FileTypeScanner()

scanners = [hash_scanner, signature_scanner, file_type_scanner]

for scanner in scanners:
    result = scanner.scan(file_path)
    # Aggregate results
```

### Result Aggregation

When combining multiple scanners, results are typically aggregated by taking the
highest risk level:

```python
results = [scanner.scan(file_path) for scanner in scanners]
overall_risk = max(result.risk_level for result in results)
```

## Extensibility

New scanners can be added by:

1. Inheriting from `Scanner`
2. Implementing `name` property and `scan()` method
3. Following the chunked reading pattern for large files
4. Returning standardized `ScanResult` objects

Example:

```python
from cerberus.core import Scanner, ScanResult, RiskLevel
from pathlib import Path

class CustomScanner(Scanner):
    @property
    def name(self) -> str:
        return "CustomScanner"

    def scan(self, file_path: Path) -> ScanResult:
        # Implementation
        return ScanResult(
            file_path=file_path,
            risk_level=RiskLevel.LOW,
            reason="Custom detection logic",
            scanner_name=self.name,
            details={"custom_info": "value"}
        )
```

## Performance Characteristics

| Scanner | Speed | Memory | False Positives | Coverage |
|---------|-------|--------|-----------------|----------|
| Hash | Very Fast | Constant | None | Known hashes only |
| Signature | Medium | Constant | Possible | Pattern-based |
| Heuristic | Medium | Constant | Likely | Behavioral analysis |
| Permission | Very Fast | Constant | None | Permission-based |
| FileType | Very Fast | Constant | Possible | Extension/type-based |

## Integration Points

### Scanner Registry

A registry pattern enables dynamic scanner configuration:

```python
class ScannerRegistry:
    def __init__(self):
        self.scanners = {}

    def register(self, name: str, scanner: Scanner):
        self.scanners[name] = scanner

    def get(self, name: str) -> Scanner:
        return self.scanners[name]
```

### Scanner Factory

A factory can instantiate scanners with appropriate configuration:

```python
class ScannerFactory:
    @staticmethod
    def create_hash_scanner(hash_database_path: Path) -> HashScanner:
        hashes = load_hash_database(hash_database_path)
        return HashScanner(hashes)
```

### Result Reporter

A reporter can format and display results:

```python
class ResultReporter:
    def report(self, results: list[ScanResult]):
        for result in results:
            print(f"{result.scanner_name}: {result.risk_level.value}")
```

## Testing Patterns

Each scanner should be tested for:

1. **Initialization**: Proper setup with valid and invalid inputs
2. **Positive Cases**: Correctly identifying risky files
3. **Negative Cases**: Correctly identifying safe files
4. **Error Handling**: Proper exception handling for edge cases
5. **Large Files**: Efficient handling of multi-GB files
6. **Edge Cases**: Special characters, empty files, unusual permissions

## Best Practices

1. **Use Dependency Injection**: Pass signatures, hashes, and rules via constructor
2. **Fail Safely**: Handle missing files and permission errors gracefully
3. **Provide Details**: Include actionable information in `ScanResult.details`
4. **Be Deterministic**: Same input should always produce same output
5. **Stream Large Files**: Use chunked reading to handle files of any size
6. **Log Comprehensively**: Use logging for debugging and audit trails
7. **Validate Input**: Check file exists and is readable before processing

## Future Enhancements

Potential areas for scanner expansion:

- **YARA Scanner**: Integration with YARA rule engine for advanced pattern matching
- **Sandboxing**: Behavioral analysis through controlled execution
- **Machine Learning**: Trained models for anomaly detection
- **API Scanners**: Integration with VirusTotal, other hash databases
- **Archive Scanners**: Recursive scanning of ZIP, TAR, and other archive formats
- **Performance Tuning**: Caching hashes/signatures for repeated scans
- **Parallel Scanning**: Multiple scanners running concurrently on large batches
