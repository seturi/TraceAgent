from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


class SourceKind(StrEnum):
    LIVE_SYSTEM = "live_system"
    DISK_IMAGE = "disk_image"
    ARTIFACT_DIRECTORY = "artifact_directory"


class AgentAttribution(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class EvidenceSource:
    kind: SourceKind
    location: Path
    label: str = ""
    read_only: bool = True
    sha256: str | None = None
    source_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    source_id: str
    producer_id: str
    path: str
    artifact_type: str
    service: str | None = None
    sha256: str | None = None
    size: int | None = None
    original_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    source_id: str
    parser_id: str
    timestamp: datetime
    event_type: str
    path: str | None = None
    service: str | None = None
    session_id: str | None = None
    actor: str | None = None
    tool_name: str | None = None
    command: str | None = None
    result: str | None = None
    attribution: AgentAttribution = AgentAttribution.NONE
    attribution_score: float = 0.0
    attribution_reasons: tuple[str, ...] = ()
    raw_reference: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if not 0.0 <= self.attribution_score <= 1.0:
            raise ValueError("attribution_score must be between 0.0 and 1.0")
        if self.timestamp.tzinfo is None:
            object.__setattr__(self, "timestamp", self.timestamp.replace(tzinfo=timezone.utc))
