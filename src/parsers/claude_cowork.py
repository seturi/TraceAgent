from __future__ import annotations

import re
import json
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from parsers.claude_common import claude_record_events
from utils.chromium_indexeddb import (
    ChromiumIndexedDbArtifact,
    ChromiumIndexedDbParser,
    ChromiumIndexedDbRecord,
)
from utils.structured_data import (
    StructuredDataIssue,
    file_timestamp,
    iter_json_lines,
    iter_timestamped_log,
    json_safe,
    load_collection_manifest,
    parse_timestamp,
    read_json_object,
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
            return 1.0 if _is_claude_leveldb_name(root.name) else 0.0
        expected = root / "IndexedDB" / CLAUDE_LEVELDB_NAME
        return 0.95 if self._indexeddb.is_leveldb_directory(expected) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        search_roots = _service_roots(source.location, "Claude_Cowork")
        manifest: dict[str, dict[str, Any]] = {}
        for search_root in search_roots:
            manifest.update(load_collection_manifest(search_root))
        indexeddb_artifacts = tuple(
            artifact
            for search_root in search_roots
            for artifact in self._indexeddb.discover(search_root)
            if _is_claude_leveldb_name(artifact.leveldb_path.name)
        )
        candidates: list[tuple[Path, str, int | None]] = [
            (artifact.leveldb_path, "chromium_indexeddb_leveldb", artifact.size)
            for artifact in indexeddb_artifacts
        ]
        patterns = (
            ("**/local-agent-mode-sessions/**/audit.jsonl", "cowork_audit_jsonl"),
            ("**/local-agent-mode-sessions/**/local_*.json", "cowork_session_metadata"),
            ("**/local-agent-mode-sessions/**/.claude/projects/**/*.jsonl", "cowork_claude_jsonl"),
            ("**/mcp-logs-*/*.jsonl", "cowork_mcp_log"),
            ("**/local-agent-mode-sessions/**/outputs/**/*", "cowork_output_file"),
            ("**/Roaming/Claude/logs/*.log", "cowork_application_log"),
        )
        for search_root in search_roots:
            for pattern, artifact_type in patterns:
                for path in search_root.glob(pattern):
                    if path.is_file():
                        candidates.append((path, artifact_type, path.stat().st_size))
            for path in search_root.glob("agent_sessions__*"):
                if not path.is_file():
                    continue
                original_name = path.name.split("__", 1)[-1].lower()
                if path.suffix.lower() == ".jsonl":
                    artifact_type = (
                        "cowork_audit_jsonl"
                        if original_name.startswith("audit")
                        else "cowork_claude_jsonl"
                    )
                elif path.suffix.lower() == ".json" and original_name.startswith("local_"):
                    artifact_type = "cowork_session_metadata"
                else:
                    artifact_type = "cowork_output_file"
                candidates.append((path, artifact_type, path.stat().st_size))
            candidates.extend(
                (path, "cowork_mcp_log", path.stat().st_size)
                for path in search_root.glob("mcp_logs__*.jsonl")
                if path.is_file()
            )
            candidates.extend(
                (path, "cowork_application_log", path.stat().st_size)
                for path in search_root.glob("application_logs__*.log")
                if path.is_file()
            )

        seen: set[Path] = set()
        for index, (path, artifact_type, size) in enumerate(sorted(candidates), start=1):
            if context.cancelled():
                break
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            manifest_entry = manifest.get(str(resolved).lower(), {})
            yield ArtifactRecord(
                source_id=source.source_id,
                producer_id=self.metadata.parser_id,
                path=str(path),
                artifact_type=artifact_type,
                service="Claude Cowork",
                size=size,
                original_path=(
                    str(manifest_entry.get("original_path"))
                    if manifest_entry.get("original_path")
                    else None
                ),
                metadata=manifest_entry,
            )
            context.progress(
                round(index / max(len(candidates), 1) * 100),
                f"Discovered {path.name}",
            )
        if not candidates:
            context.progress(100, "No Claude Cowork artifacts found.")

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = list(artifacts)
        issues: list[StructuredDataIssue] = []
        for index, artifact_record in enumerate(artifact_list, start=1):
            if context.cancelled():
                return
            path = Path(artifact_record.path)
            try:
                if artifact_record.artifact_type == "chromium_indexeddb_leveldb":
                    result = self._indexeddb.parse(path)
                    events = [
                        self._to_event(source, result.artifact, record)
                        for record in result.records
                    ]
                    _mark_final_prompt_candidates(events)
                    for event in events:
                        emit(event)
                    if result.issues:
                        context.options.setdefault("indexeddb_issues", []).extend(result.issues)
                elif artifact_record.artifact_type in {"cowork_audit_jsonl", "cowork_claude_jsonl"}:
                    for record in iter_json_lines(path, issues):
                        for event in claude_record_events(
                            source,
                            parser_id=self.metadata.parser_id,
                            service="Claude Cowork",
                            artifact=artifact_record,
                            payload=record.value,
                            line_number=record.line_number,
                        ):
                            emit(event)
                elif artifact_record.artifact_type == "cowork_session_metadata":
                    emit(self._session_metadata_event(source, artifact_record, read_json_object(path)))
                elif artifact_record.artifact_type == "cowork_mcp_log":
                    self._parse_mcp_log(source, artifact_record, emit, issues)
                elif artifact_record.artifact_type == "cowork_application_log":
                    self._parse_application_log(source, artifact_record, emit)
                elif artifact_record.artifact_type == "cowork_output_file":
                    emit(self._file_event(source, artifact_record))
            except (OSError, ValueError) as exc:
                issues.append(StructuredDataIssue(str(path), "file", str(exc)))
            context.progress(
                round(index / max(len(artifact_list), 1) * 100),
                f"Parsed {path.name}",
            )
        if issues:
            context.options.setdefault("cowork_errors", []).extend(issues)

    def _session_metadata_event(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        payload: dict[str, Any],
    ) -> NormalizedEvent:
        path = Path(artifact.path)
        timestamp = (
            parse_timestamp(payload.get("lastActivityAt"))
            or parse_timestamp(payload.get("createdAt"))
            or file_timestamp(path)
        )
        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=timestamp,
            event_type="cowork_session_metadata",
            path=str(payload.get("cwd")) if payload.get("cwd") else None,
            service="Claude Cowork",
            session_id=str(payload.get("sessionId")) if payload.get("sessionId") else None,
            result=str(payload.get("title")) if payload.get("title") else None,
            raw_reference=artifact.record_id,
            metadata=json_safe(payload),
        )

    def _parse_mcp_log(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        emit: EventSink,
        issues: list[StructuredDataIssue],
    ) -> None:
        for record in iter_json_lines(Path(artifact.path), issues):
            debug = record.value.get("debug")
            message = debug if isinstance(debug, str) else json.dumps(json_safe(debug), ensure_ascii=False)
            tool_match = re.search(r"(?:Calling MCP tool:|Tool ['\"])([\w.-]+)", message)
            tool_name = tool_match.group(1) if tool_match else None
            failed = " failed " in f" {message.lower()} " or "access denied" in message.lower()
            event_type = "cowork_mcp_tool_result" if failed else "cowork_mcp_tool_call" if tool_name else "cowork_mcp_log"
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=parse_timestamp(record.value.get("timestamp")) or file_timestamp(Path(artifact.path)),
                    event_type=event_type,
                    path=_text_path(message),
                    service="Claude Cowork",
                    session_id=(
                        str(record.value.get("sessionId")) if record.value.get("sessionId") else None
                    ),
                    actor="assistant" if tool_name else None,
                    tool_name=tool_name,
                    command=message if tool_name and not failed else None,
                    result=message if failed or not tool_name else None,
                    attribution=AgentAttribution.CONFIRMED if tool_name else AgentAttribution.HIGH,
                    attribution_score=1.0 if tool_name else 0.8,
                    attribution_reasons=("cowork_mcp_log",),
                    raw_reference=f"{artifact.record_id}:line={record.line_number}",
                    metadata=json_safe(record.value),
                )
            )

    def _file_event(self, source: EvidenceSource, artifact: ArtifactRecord) -> NormalizedEvent:
        path = Path(artifact.path)
        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=file_timestamp(path),
            event_type=artifact.artifact_type,
            path=str(path),
            service="Claude Cowork",
            raw_reference=artifact.record_id,
            metadata={"size": path.stat().st_size, "suffix": path.suffix.lower()},
        )

    def _parse_application_log(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        emit: EventSink,
    ) -> None:
        path = Path(artifact.path)
        for record in iter_timestamped_log(path):
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=record.timestamp or file_timestamp(path),
                    event_type="cowork_application_log",
                    path=_text_path(record.message),
                    service="Claude Cowork",
                    result=record.message,
                    raw_reference=f"{artifact.record_id}:line={record.line_number}",
                    metadata={"level": record.level, "line_number": record.line_number},
                )
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


def _is_claude_leveldb_name(name: str) -> bool:
    lowered = name.lower()
    return lowered == CLAUDE_LEVELDB_NAME or (
        lowered.endswith(".indexeddb.leveldb") and "https_claude.ai_0" in lowered
    )


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


def _text_path(text: str) -> str | None:
    match = re.search(r"(?:[A-Za-z]:\\|/)[^\s'\"]+", text)
    return match.group(0) if match else None


def _service_roots(location: Path, service_directory: str) -> tuple[Path, ...]:
    compact = location / service_directory
    return (compact,) if compact.is_dir() else (location,)
