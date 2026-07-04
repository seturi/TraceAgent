from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.chromium_indexeddb import (
    ChromiumIndexedDbArtifact,
    ChromiumIndexedDbParser,
    ChromiumIndexedDbRecord,
)
from version import __version__

CLAUDE_LEVELDB_NAME = "https_claude.ai_0.indexeddb.leveldb"
CHAT_DRAFT_PREFIXES = ("store:chat-draft:", "chat-draft:")


class ClaudeCoworkParser(ArtifactParser):
    """Claude Cowork service parser composed from reusable artifact parsers."""

    def __init__(self, indexeddb_parser: ChromiumIndexedDbParser | None = None) -> None:
        self._indexeddb = indexeddb_parser or ChromiumIndexedDbParser()

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="claude.cowork",
            name="Claude Cowork",
            category="service",
            version=__version__,
            services=("Claude Cowork",),
            description="Claude Cowork artifacts interpreted through reusable format parsers.",
        )

    def probe(self, source: EvidenceSource) -> float:
        root = source.location
        if self._indexeddb.is_leveldb_directory(root):
            return 1.0 if root.name == CLAUDE_LEVELDB_NAME else 0.0
        expected = root / "IndexedDB" / CLAUDE_LEVELDB_NAME
        return 0.95 if self._indexeddb.is_leveldb_directory(expected) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        artifacts = tuple(
            artifact
            for artifact in self._indexeddb.discover(source.location)
            if artifact.leveldb_path.name == CLAUDE_LEVELDB_NAME
        )
        for index, artifact in enumerate(artifacts, start=1):
            if context.cancelled():
                break
            yield ArtifactRecord(
                source_id=source.source_id,
                producer_id=self.metadata.parser_id,
                path=str(artifact.leveldb_path),
                artifact_type="chromium_indexeddb_leveldb",
                service="Claude Cowork",
                size=artifact.size,
            )
            context.progress(
                round(index / max(len(artifacts), 1) * 100),
                f"Discovered {artifact.leveldb_path.name}",
            )
        if not artifacts:
            context.progress(100, "No Claude IndexedDB LevelDB directory found.")

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = list(artifacts)
        for index, artifact_record in enumerate(artifact_list, start=1):
            if context.cancelled():
                return
            leveldb_path = Path(artifact_record.path)
            result = self._indexeddb.parse(leveldb_path)
            events = [self._to_event(source, result.artifact, record) for record in result.records]
            _mark_final_prompt_candidates(events)
            for event in events:
                emit(event)
            if result.issues:
                context.options.setdefault("indexeddb_issues", []).extend(result.issues)
            context.progress(
                round(index / max(len(artifact_list), 1) * 100),
                f"Parsed {leveldb_path.name}",
            )

    def _to_event(
        self,
        source: EvidenceSource,
        artifact: ChromiumIndexedDbArtifact,
        record: ChromiumIndexedDbRecord,
    ) -> NormalizedEvent:
        session_id = _draft_session_id(record.key)
        is_draft = session_id is not None
        timestamp, timestamp_source = _artifact_timestamp(record, record.value, artifact.leveldb_path)

        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=timestamp,
            event_type="prompt_draft" if is_draft else "indexeddb_record",
            service="Claude Cowork",
            session_id=session_id,
            actor="user" if is_draft else None,
            result=_draft_text(record.value) if is_draft else None,
            raw_reference=record.raw_reference,
            metadata={
                "database_id": record.database_id,
                "database_name": record.database_name,
                "database_origin": record.database_origin,
                "object_store_id": record.object_store_id,
                "object_store": record.object_store_name,
                "key": record.key,
                "value": record.value,
                "is_live": record.is_live,
                "leveldb_sequence_number": record.sequence_number,
                "leveldb_origin_file": str(record.origin_file),
                "external_value_path": (
                    str(record.external_value_path) if record.external_value_path else None
                ),
                "timestamp_source": timestamp_source,
                "draft_state": "cleared" if is_draft and record.value is None else "active" if is_draft else None,
                "is_final_prompt_candidate": False if is_draft else None,
            },
        )


def _draft_session_id(key: Any) -> str | None:
    if not isinstance(key, str):
        return None
    for prefix in CHAT_DRAFT_PREFIXES:
        if key.startswith(prefix):
            return key[len(prefix):]
    return None


def _draft_text(value: Any) -> str | None:
    if isinstance(value, Mapping):
        state = value.get("state")
        if isinstance(state, Mapping):
            editor_text = _tip_tap_text(state.get("tipTapEditorState"))
            if editor_text is not None:
                return editor_text

        for key in ("text", "content", "draft", "prompt", "value"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
        for child in value.values():
            result = _draft_text(child)
            if result is not None:
                return result
    elif isinstance(value, list):
        for child in value:
            result = _draft_text(child)
            if result is not None:
                return result
    elif isinstance(value, str):
        return value
    return None


def _tip_tap_text(node: Any) -> str | None:
    if not isinstance(node, Mapping):
        return None
    if node.get("type") == "text" and isinstance(node.get("text"), str):
        return node["text"]
    content = node.get("content")
    if not isinstance(content, list):
        return None
    parts = [text for child in content if (text := _tip_tap_text(child)) is not None]
    if not parts:
        return "" if node.get("type") in {"doc", "paragraph"} else None
    return ("\n" if node.get("type") == "doc" else "").join(parts)


def _artifact_timestamp(
    record: ChromiumIndexedDbRecord,
    value: Any,
    leveldb_path: Path,
) -> tuple[datetime, str]:
    timestamp = _find_timestamp(value)
    if timestamp is not None:
        return timestamp, "record_value"
    try:
        return datetime.fromtimestamp(record.origin_file.stat().st_mtime, timezone.utc), "leveldb_file_mtime"
    except OSError:
        return datetime.fromtimestamp(leveldb_path.stat().st_mtime, timezone.utc), "leveldb_directory_mtime"


def _find_timestamp(value: Any) -> datetime | None:
    timestamp_keys = {
        "timestamp",
        "updatedat",
        "updatedtimestamp",
        "createdat",
        "createdtimestamp",
        "lastmodified",
        "lastmodifiedat",
    }

    def walk(item: Any) -> Iterator[Any]:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if re.sub(r"[^a-z]", "", str(key).lower()) in timestamp_keys:
                    yield child
            for child in item.values():
                yield from walk(child)
        elif isinstance(item, list):
            for child in item:
                yield from walk(child)

    for candidate in walk(value):
        parsed = _coerce_timestamp(candidate)
        if parsed is not None:
            return parsed
    return None


def _coerce_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value) / 1000 if abs(float(value)) >= 10_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return _coerce_timestamp(int(text))
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _mark_final_prompt_candidates(events: Iterable[NormalizedEvent]) -> None:
    last_active: dict[str, NormalizedEvent] = {}
    for event in events:
        if event.event_type != "prompt_draft" or event.session_id is None:
            continue
        if event.metadata.get("draft_state") == "cleared":
            candidate = last_active.pop(event.session_id, None)
            if candidate is not None:
                candidate.metadata["is_final_prompt_candidate"] = True
                event.metadata["final_prompt_sequence_number"] = candidate.metadata.get(
                    "leveldb_sequence_number"
                )
        else:
            last_active[event.session_id] = event
