from __future__ import annotations

from .schemas import RiskFactors, RiskLevel, RiskResult


class RiskEngine:
    """COMPASS-aligned 5x5 base risk with AI-specific contextual modifiers."""

    MAX_CONTEXTUAL_MULTIPLIER = 5.0**5

    @staticmethod
    def _level(score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def score(self, factors: RiskFactors) -> RiskResult:
        base = float(factors.impact * factors.likelihood)
        contextual = base * (
            factors.data_sensitivity
            * factors.privilege
            * factors.autonomy
            * factors.exposure
            * factors.reachability
        )
        residual = contextual * factors.control_effectiveness

        # Normalize against a 25-point base and bounded contextual multiplier.
        maximum = 25.0 * self.MAX_CONTEXTUAL_MULTIPLIER
        normalized = min(100.0, max(0.0, (residual / maximum) * 100.0))

        return RiskResult(
            base_risk=round(base, 2),
            contextual_risk=round(contextual, 2),
            residual_risk=round(residual, 2),
            normalized_score=round(normalized, 2),
            level=self._level(normalized),
        )
