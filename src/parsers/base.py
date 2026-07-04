from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Literal

from core.models import ArtifactRecord, EvidenceSource, NormalizedEvent

ParserCategory = Literal["service", "ntfs"]
EventSink = Callable[[NormalizedEvent], None]


@dataclass(frozen=True, slots=True)
class ParserMetadata:
    parser_id: str
    name: str
    category: ParserCategory
    version: str
    services: tuple[str, ...] = ()
    description: str = ""
    implementation_status: Literal["ready", "placeholder"] = "ready"


@dataclass(slots=True)
class ParseContext:
    workspace: Path
    cancelled: Callable[[], bool] = lambda: False
    progress: Callable[[int, str], None] = lambda _percent, _message: None
    options: dict[str, object] = field(default_factory=dict)


class ArtifactParser(ABC):
    @property
    @abstractmethod
    def metadata(self) -> ParserMetadata:
        raise NotImplementedError

    @abstractmethod
    def probe(self, source: EvidenceSource) -> float:
        raise NotImplementedError

    @abstractmethod
    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        raise NotImplementedError

    @abstractmethod
    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        raise NotImplementedError
