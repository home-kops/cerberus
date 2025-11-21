"""Unit tests for RiskLevel enum."""

import pytest

from cerberus.core.risk_level import RiskLevel


class TestRiskLevel:
    """Test suite for RiskLevel enum."""

    def test_risk_levels_exist(self) -> None:
        """Test that all expected risk levels are defined."""
        assert RiskLevel.SAFE
        assert RiskLevel.LOW
        assert RiskLevel.MEDIUM
        assert RiskLevel.HIGH
        assert RiskLevel.CRITICAL

    def test_risk_level_values(self) -> None:
        """Test that risk levels have correct string values."""
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_risk_level_comparison_less_than(self) -> None:
        """Test that risk levels can be compared using < operator."""
        assert RiskLevel.SAFE < RiskLevel.LOW
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_risk_level_comparison_less_equal(self) -> None:
        """Test that risk levels can be compared using <= operator."""
        assert RiskLevel.SAFE <= RiskLevel.SAFE
        assert RiskLevel.SAFE <= RiskLevel.LOW
        assert RiskLevel.HIGH <= RiskLevel.CRITICAL

    def test_risk_level_comparison_greater_than(self) -> None:
        """Test that risk levels can be compared using > operator."""
        assert RiskLevel.CRITICAL > RiskLevel.HIGH
        assert RiskLevel.HIGH > RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM > RiskLevel.LOW
        assert RiskLevel.LOW > RiskLevel.SAFE

    def test_risk_level_comparison_greater_equal(self) -> None:
        """Test that risk levels can be compared using >= operator."""
        assert RiskLevel.CRITICAL >= RiskLevel.CRITICAL
        assert RiskLevel.CRITICAL >= RiskLevel.HIGH
        assert RiskLevel.LOW >= RiskLevel.SAFE

    def test_risk_level_comparison_with_invalid_type(self) -> None:
        """Test that comparing with non-RiskLevel raises TypeError."""
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH < "invalid"  # type: ignore
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH <= 5  # type: ignore
