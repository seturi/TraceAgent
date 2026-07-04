from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.models import EvidenceSource, NormalizedEvent


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS evidence_sources (
    source_id TEXT PRIMARY KEY, kind TEXT NOT NULL, location TEXT NOT NULL,
    label TEXT NOT NULL, read_only INTEGER NOT NULL, sha256 TEXT
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
    parser_id TEXT NOT NULL, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
    path TEXT, service TEXT, session_id TEXT, actor TEXT, tool_name TEXT,
    command TEXT, result TEXT, attribution TEXT NOT NULL,
    attribution_score REAL NOT NULL, attribution_reasons TEXT NOT NULL,
    raw_reference TEXT, metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
CREATE INDEX IF NOT EXISTS idx_events_attribution ON events(attribution, attribution_score);
"""


class ProjectDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.executescript(SCHEMA)

    def add_source(self, source: EvidenceSource) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO evidence_sources
                (source_id, kind, location, label, read_only, sha256)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (source.source_id, source.kind.value, str(source.location), source.label, int(source.read_only), source.sha256),
            )

    def add_event(self, event: NormalizedEvent) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO events VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.source_id, event.parser_id, event.timestamp.isoformat(),
                    event.event_type, event.path, event.service, event.session_id, event.actor,
                    event.tool_name, event.command, event.result, event.attribution.value,
                    event.attribution_score, json.dumps(event.attribution_reasons, ensure_ascii=False),
                    event.raw_reference, json.dumps(event.metadata, ensure_ascii=False),
                ),
            )
