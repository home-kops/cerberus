"""Unit tests for ScanResult dataclass."""

from pathlib import Path

import pytest

from cerberus.core.risk_level import RiskLevel
from cerberus.core.scan_result import ScanResult


class TestScanResult:
    """Test suite for ScanResult dataclass."""

    def test_scan_result_creation(self) -> None:
        """Test creating a basic ScanResult."""
        result = ScanResult(
            file_path=Path("/tmp/test.txt"),
            risk_level=RiskLevel.LOW,
            reason="Test reason",
            scanner_name="TestScanner",
        )

        assert result.file_path == Path("/tmp/test.txt")
        assert result.risk_level == RiskLevel.LOW
        assert result.reason == "Test reason"
        assert result.scanner_name == "TestScanner"
        assert result.details is None

    def test_scan_result_with_details(self) -> None:
        """Test creating a ScanResult with optional details."""
        details = {"hash": "abc123", "signature": "malware_x"}
        result = ScanResult(
            file_path=Path("/tmp/malware.exe"),
            risk_level=RiskLevel.CRITICAL,
            reason="Known malware detected",
            scanner_name="HashScanner",
            details=details,
        )

        assert result.details == details
        assert result.details["hash"] == "abc123"

    def test_scan_result_converts_string_path(self) -> None:
        """Test that string file paths are converted to Path objects."""
        result = ScanResult(
            file_path="/tmp/test.txt",  # type: ignore
            risk_level=RiskLevel.SAFE,
            reason="Clean file",
            scanner_name="TestScanner",
        )

        assert isinstance(result.file_path, Path)
        assert result.file_path == Path("/tmp/test.txt")

    def test_scan_result_invalid_risk_level(self) -> None:
        """Test that invalid risk_level raises TypeError."""
        with pytest.raises(TypeError, match="risk_level must be RiskLevel"):
            ScanResult(
                file_path=Path("/tmp/test.txt"),
                risk_level="invalid",  # type: ignore
                reason="Test",
                scanner_name="TestScanner",
            )

    def test_scan_result_all_risk_levels(self) -> None:
        """Test creating ScanResults with all risk levels."""
        for risk_level in RiskLevel:
            result = ScanResult(
                file_path=Path("/tmp/test.txt"),
                risk_level=risk_level,
                reason=f"Test {risk_level.value}",
                scanner_name="TestScanner",
            )
            assert result.risk_level == risk_level
