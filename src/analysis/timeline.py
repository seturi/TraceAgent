from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from core.models import AgentAttribution


@dataclass(frozen=True, slots=True)
class TimelineQuery:
    text: str = ""
    service: str | None = None
    event_type: str | None = None
    attribution: AgentAttribution | None = None
    start: datetime | None = None
    end: datetime | None = None
