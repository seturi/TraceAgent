from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from analysis.timeline import TimelineQuery


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


@dataclass(frozen=True, slots=True)
class ExportRequest:
    destination: Path
    format: ExportFormat
    query: TimelineQuery = TimelineQuery()
