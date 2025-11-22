"""Unit tests for HashScanner."""

from pathlib import Path

import pytest

from cerberus.core import RiskLevel, ScanResult
from cerberus.scanners import HashScanner


class TestHashScannerInitialization:
    """Test HashScanner initialization."""

    def test_init_with_valid_hashes(self):
        """Test initialization with valid hash set."""
        malware_hashes = {
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        }
        scanner = HashScanner(malware_hashes)
        assert scanner is not None

    def test_init_with_empty_hashes(self):
        """Test initialization with empty hash set."""
        scanner = HashScanner(set())
        assert scanner is not None

    def test_init_with_invalid_type_raises_error(self):
        """Test initialization with non-set type raises TypeError."""
        with pytest.raises(TypeError):
            HashScanner(["hash1", "hash2"])  # List instead of set

    def test_init_with_invalid_hash_algorithm(self):
        """Test initialization with non-set type raises TypeError."""
        with pytest.raises(ValueError):
            HashScanner({"hash1"}, "not_a_hash_algorithm")

    def test_name_property(self):
        """Test scanner name property."""
        scanner = HashScanner(set())
        assert scanner.name == "HashScanner"
        assert isinstance(scanner.name, str)


class TestHashScannerScan:
    """Test HashScanner.scan() method."""

    @pytest.fixture
    def test_file(self, tmp_path):
        """Create a temporary test file."""
        test_file = tmp_path / "test.bin"
        test_file.write_text("test content")
        return test_file

    @pytest.fixture
    def malicious_file(self, tmp_path):
        """Create a temporary file with known malicious content."""
        # EICAR test file (safe malware test pattern)
        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        malicious_file = tmp_path / "eicar.txt"
        malicious_file.write_text(eicar)
        return malicious_file

    def test_scan_safe_file_returns_safe_risk(self, test_file):
        """Test scanning a safe file returns SAFE risk level."""
        scanner = HashScanner(set())
        result = scanner.scan(test_file)

        assert isinstance(result, ScanResult)
        assert result.risk_level == RiskLevel.SAFE
        assert result.file_path == test_file
        assert result.scanner_name == "HashScanner"

    def test_scan_malicious_file_returns_critical_risk(self, malicious_file):
        """Test scanning a malicious file returns CRITICAL risk level."""
        malware_hashes = {
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        }
        scanner = HashScanner(malware_hashes)

        result = scanner.scan(malicious_file)

        assert result.risk_level == RiskLevel.CRITICAL

    def test_scan_nonexistent_file_raises_error(self):
        """Test scanning nonexistent file raises FileNotFoundError."""
        scanner = HashScanner(set())
        with pytest.raises(FileNotFoundError):
            scanner.scan(Path("/nonexistent/file.txt"))

    def test_scan_directory_raises_error(self, tmp_path):
        """Test scanning directory raises IsADirectoryError."""
        scanner = HashScanner(set())
        with pytest.raises(IsADirectoryError):
            scanner.scan(tmp_path)

    def test_scan_file_with_no_read_permission_raises_error(self, test_file):
        """Test scanning a non readable file raises permissions error."""
        test_file.chmod(0o333)
        scanner = HashScanner(set())

        with pytest.raises(PermissionError):
            scanner.scan(test_file)

    def test_scan_result_contains_hash_details(self, test_file):
        """Test scan result includes hash in details."""
        scanner = HashScanner(set())
        result = scanner.scan(test_file)

        assert result.details is not None
        assert "hash" in result.details
        assert len(result.details["hash"]) == 64  # SHA256 hex length

    def test_scan_multiple_files_independently(self, malicious_file, test_file):
        """Test scanning multiple files produces correct independent results."""
        malware_hashes = {
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        }
        scanner = HashScanner(malware_hashes)

        result1 = scanner.scan(malicious_file)
        result2 = scanner.scan(test_file)

        assert result1.risk_level == RiskLevel.CRITICAL
        assert result2.risk_level == RiskLevel.SAFE


class TestHashScannerLargeFiles:
    """Test HashScanner with large files."""

    def test_scan_large_file_efficiently(self, tmp_path):
        """Test scanning a large file without loading entire file in memory."""
        # Create a 10MB file
        large_file = tmp_path / "large.bin"
        with open(large_file, "wb") as f:
            f.write(b"A" * (10 * 1024 * 1024))

        scanner = HashScanner(set())
        result = scanner.scan(large_file)

        assert result.risk_level == RiskLevel.SAFE
        assert result.details is not None
        assert len(result.details["hash"]) == 64


class TestHashScannerEdgeCases:
    """Test HashScanner edge cases."""

    def test_scan_empty_file(self, tmp_path):
        """Test scanning an empty file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")

        # SHA256 of empty string
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        scanner = HashScanner({empty_hash})
        result = scanner.scan(empty_file)

        assert result.risk_level == RiskLevel.CRITICAL

    def test_scan_file_with_special_characters_in_name(self, tmp_path):
        """Test scanning files with special characters in name."""
        special_file = tmp_path / "file-with_special.chars@2024.txt"
        special_file.write_text("content")

        scanner = HashScanner(set())
        result = scanner.scan(special_file)

        assert result.risk_level == RiskLevel.SAFE
