"""Risk level enumeration for file security assessment."""

from enum import Enum


class RiskLevel(Enum):
    """Risk levels for scanned files."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "RiskLevel") -> bool:
        """Allow risk level comparison."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        risk_order = [
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        return risk_order.index(self) < risk_order.index(other)

    def __le__(self, other: "RiskLevel") -> bool:
        """Allow risk level comparison."""
        return self == other or self < other

    def __gt__(self, other: "RiskLevel") -> bool:
        """Allow risk level comparison."""
        return not self <= other

    def __ge__(self, other: "RiskLevel") -> bool:
        """Allow risk level comparison."""
        return not self < other
