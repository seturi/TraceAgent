from __future__ import annotations

from dataclasses import dataclass

from core.models import AgentAttribution


@dataclass(frozen=True, slots=True)
class AttributionResult:
    level: AgentAttribution
    score: float
    reasons: tuple[str, ...]


def score_attribution(score: float, reasons: tuple[str, ...] = ()) -> AttributionResult:
    if not 0.0 <= score <= 1.0:
        raise ValueError("score must be between 0.0 and 1.0")
    if score >= 0.95:
        level = AgentAttribution.CONFIRMED
    elif score >= 0.75:
        level = AgentAttribution.HIGH
    elif score >= 0.50:
        level = AgentAttribution.MEDIUM
    elif score > 0.0:
        level = AgentAttribution.LOW
    else:
        level = AgentAttribution.NONE
    return AttributionResult(level, score, reasons)
