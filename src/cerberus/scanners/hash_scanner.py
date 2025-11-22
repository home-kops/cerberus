"""Hash-based malware detection scanner.

Detects malware by comparing file hashes (MD5, SHA256) against
a database of known malicious file hashes.
"""

import hashlib
import os
from pathlib import Path

from cerberus.core import RiskLevel, Scanner, ScanResult
from cerberus.utils import read_chunks


class HashScanner(Scanner):
    """Scanner that detects malware through hash matching.

    Compares SHA256/MD5 hashes of scanned files against a database
    of known malicious file hashes. Provides fast, reliable detection
    with zero false positives (only flags known malicious files).

    Attributes:
        malware_hashes: Set of hexadecimal hash strings of known malicious files.
        hash_algorithm: Algorithm to use for file hashing (default: sha256).

    Example:
        >>> malware_hashes = {"e3b0c...2b855"}
        >>> scanner = HashScanner(malware_hashes)
        >>> result = scanner.scan(Path("/tmp/suspicious.exe"))
        >>> print(result.risk_level)
        high
    """

    def __init__(self, malware_hashes: set[str], hash_algorithm: str = "sha256"):
        """Initialize HashScanner with known malware hashes.

        Args:
            malware_hashes: Set of hexadecimal hash strings (lowercase).
            hash_algorithm: Hash algorithm to use (default: sha256).

        Raises:
            ValueError: If hash_algorithm is not supported.
            TypeError: If malware_hashes is not a set.
        """
        if not isinstance(malware_hashes, set):
            raise TypeError("malware_hashes is not a set")

        if hash_algorithm not in (hashlib.algorithms_available):
            raise ValueError(
                f"Unsupported hash algorithm: {hash_algorithm}. "
                f"Supported: {', '.join(hashlib.algorithms_available)}"
            )

        self.malware_hashes = malware_hashes
        self.hash_algorithm = hash_algorithm

    @property
    def name(self) -> str:
        return __class__.__name__

    def scan(self, file_path: Path) -> ScanResult:
        """Scan file by comparing hash against known malware database.

        Args:
            file_path: Path to the file to scan.

        Returns:
            ScanResult with CRITICAL risk if hash matches, SAFE if not.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            IsADirectoryError: If the provided path is a directory.

        Algorithm:
            1. Validate file exists and is readable
            2. Calculate file hash using streaming (efficient for large files)
            3. Compare against known malware hashes
            4. Return appropriate risk level and details
        """
        if file_path.is_dir():
            raise IsADirectoryError

        if not file_path.is_file():
            raise FileNotFoundError

        if not os.access(file_path, os.R_OK):
            raise PermissionError

        file_hash = self._calculate_hash(file_path, self.hash_algorithm)

        if file_hash in self.malware_hashes:
            return ScanResult(
                file_path,
                RiskLevel.CRITICAL,
                "File hash matches malware",
                self.name,
                {"hash": file_hash},
            )

        return ScanResult(
            file_path, RiskLevel.SAFE, "Safe", self.name, {"hash": file_hash}
        )

    def _calculate_hash(self, file_path: Path, hash_algorithm: str) -> str:
        """Calculate file hash using streaming for memory efficiency.

        Args:
            file_path: Path to the file to hash.

        Returns:
            Hexadecimal string representation of the hash.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read due to permissions.
            IsADirectoryError: If the provided path is a directory.
            ValueError: If an unsupported hash algorithm is specified.

        Note:
            Uses 64KB chunks to balance I/O efficiency with memory usage.
            Suitable for files of any size from bytes to multiple GB.
        """
        try:
            hasher = hashlib.new(hash_algorithm)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported hash algorithm: {hash_algorithm}. "
                f"Supported: {', '.join(hashlib.algorithms_available)}"
            ) from exc

        for chunk in read_chunks(file_path):
            hasher.update(chunk)

        return hasher.hexdigest()
