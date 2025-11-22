"""Abstract base class for all security scanners."""

from abc import ABC, abstractmethod
from pathlib import Path

from cerberus.core.scan_result import ScanResult


class Scanner(ABC):
    """Base class for all file security scanners.

    All scanners must implement the scan() method and provide a name property.
    Results are standardized ScanResult objects with consistent risk assessment.

    Scanners should handle:
    - Large files efficiently (chunked/streaming reading)
    - Permission errors gracefully
    - Missing files gracefully
    - Type validation

    Example:
        >>> class MyScanner(Scanner):
        ...     @property
        ...     def name(self) -> str:
        ...         return "MyScanner"
        ...
        ...     def scan(self, file_path: Path) -> ScanResult:
        ...         # Implementation here
        ...         pass
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier.

        Returns:
            Human-readable scanner name (e.g., 'HashScanner', 'SignatureScanner').
        """
        pass

    @abstractmethod
    def scan(self, file_path: Path) -> ScanResult:
        """Scan a file and return risk assessment.

        Args:
            file_path: Path to the file to scan.

        Returns:
            ScanResult containing risk_level, reason, and optional details.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read due to permissions.
            IsADirectoryError: If the provided path is a directory.

        Note:
            Implementations should handle large files efficiently using
            chunked/streaming reads to avoid memory issues.
        """
        pass
