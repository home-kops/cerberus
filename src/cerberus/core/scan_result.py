"""Scan result data model for security analysis output."""

from dataclasses import dataclass
from pathlib import Path

from cerberus.core.risk_level import RiskLevel


@dataclass
class ScanResult:
    """Result of scanning a file for security risks.

    Attributes:
        file_path: Path to the scanned file.
        risk_level: Overall risk assessment.
        reason: Human-readable explanation of the risk.
        scanner_name: Name of the scanner that produced this result.
        details: Optional additional information about findings.

    Example:
        >>> result = ScanResult(
        ...     file_path=Path("/tmp/test.exe"),
        ...     risk_level=RiskLevel.HIGH,
        ...     reason="Hash matches known malware",
        ...     scanner_name="HashScanner"
        ... )
        >>> print(result.risk_level.value)
        high
    """

    file_path: Path
    risk_level: RiskLevel
    reason: str
    scanner_name: str
    details: dict[str, str] | None = None

    def __post_init__(self) -> None:
        """Validate scan result after initialization."""
        if not isinstance(self.file_path, Path):
            self.file_path = Path(self.file_path)
        if not isinstance(self.risk_level, RiskLevel):
            raise TypeError(
                f"risk_level must be RiskLevel, got {type(self.risk_level)}"
            )
