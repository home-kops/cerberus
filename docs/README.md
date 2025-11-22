# Cerberus Documentation

This directory contains comprehensive documentation for the Cerberus security analysis tool.

## Contents

### [SCANNER_ARCHITECTURE.md](./SCANNER_ARCHITECTURE.md)

Comprehensive documentation of Cerberus's modular scanner architecture:

- **Core Concepts**: Overview of the Scanner interface and ScanResult model
- **Scanner Types**: Detailed description of each scanner (Hash, Signature, Heuristic, Permission, FileType)
- **Design Principles**: Architectural decisions and patterns
- **Scanner Composition**: How to combine multiple scanners
- **Extensibility**: How to add new scanners
- **Performance Characteristics**: Comparison of scanner speeds and characteristics
- **Integration Points**: Registry, factory, and reporter patterns
- **Testing Patterns**: How to test scanners
- **Best Practices**: Development guidelines

## Quick Links

- **Project README**: [`../README.md`](../README.md)
- **Contributing**: See project root for contribution guidelines
- **Source Code**: [`../src/cerberus/`](../src/cerberus/)

## Key Concepts

### Scanners

Each scanner implements a specific security detection method:

1. **HashScanner** - Hash-based malware detection (known malicious hashes)
2. **SignatureScanner** - Pattern-based malware detection (malicious signatures)
3. **HeuristicScanner** - Behavioral analysis and structural anomalies
4. **PermissionScanner** - Dangerous file permission detection
5. **FileTypeScanner** - Risky file type and extension detection

All scanners follow the same interface and can be composed together for comprehensive analysis.

### Risk Levels

Files are assessed on a 5-level risk scale:

- **SAFE**: No risk detected
- **LOW**: Minor concerns or low-confidence detections
- **MEDIUM**: Notable anomalies or moderate risk indicators
- **HIGH**: Significant risk indicators
- **CRITICAL**: Definitive threat (e.g., hash match with known malware)

### Memory Efficiency

All scanners use streaming/chunked file processing to efficiently handle files of any size,
from bytes to multiple gigabytes, without excessive memory consumption.
