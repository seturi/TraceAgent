from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from core.models import ArtifactRecord, EvidenceSource, SourceKind


@dataclass(frozen=True, slots=True)
class CollectorMetadata:
    collector_id: str
    name: str
    source_kinds: tuple[SourceKind, ...]
    description: str = ""


@dataclass(slots=True)
class CollectionContext:
    workspace: Path
    calculate_sha256: bool = True
    cancelled: Callable[[], bool] = lambda: False
    progress: Callable[[int, str], None] = lambda _percent, _message: None
    options: dict[str, object] = field(default_factory=dict)


class Collector(ABC):
    @property
    @abstractmethod
    def metadata(self) -> CollectorMetadata:
        raise NotImplementedError

    @abstractmethod
    def collect(self, source: EvidenceSource, context: CollectionContext) -> Iterable[ArtifactRecord]:
        raise NotImplementedError
