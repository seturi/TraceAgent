from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import (
    StructuredDataIssue,
    file_timestamp,
    iter_json_lines,
    iter_sqlite_rows,
    json_safe,
    load_collection_manifest,
    parse_timestamp,
    read_json_object,
)
from version import __version__

_SERVICE = "Antigravity"
_ACTION_TYPES = {
    "CODE_ACTION",
    "LIST_DIRECTORY",
    "READ_FILE",
    "WRITE_FILE",
    "RUN_COMMAND",
    "SEARCH",
    "BROWSER_ACTION",
}


class AntigravityParser(ArtifactParser):
    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="antigravity.local",
            name="Antigravity",
            category="service",
            version=__version__,
            services=(_SERVICE,),
            description="Parses Antigravity transcripts, messages, conversation DBs, state, annotations, and scratch files.",
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        compact = source.location / "Antigravity"
        if compact.is_dir() and any(compact.iterdir()):
            return 0.95
        return 0.95 if any(source.location.glob("**/antigravity/brain")) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        patterns = (
            ("**/antigravity/brain/**/.system_generated/logs/transcript*.jsonl", "antigravity_transcript"),
            ("**/antigravity/brain/**/.system_generated/messages/*.json", "antigravity_message"),
            ("**/antigravity/conversations/*.db", "antigravity_conversation_db"),
            ("**/antigravity/annotations/*.pbtxt", "antigravity_annotation"),
            ("**/antigravity/antigravity_state.pbtxt", "antigravity_state"),
            ("**/antigravity/scratch/**/*", "antigravity_scratch_file"),
        )
        candidates: list[tuple[Path, str]] = []
        manifest: dict[str, dict[str, Any]] = {}
        for search_root in _service_roots(source.location, "Antigravity"):
            manifest.update(load_collection_manifest(search_root))
            for pattern, artifact_type in patterns:
                candidates.extend(
                    (path, artifact_type)
                    for path in search_root.glob(pattern)
                    if path.is_file()
                )
            compact_patterns = (
                ("brain_transcripts__transcript*.jsonl", "antigravity_transcript"),
                ("brain_transcripts__*.json", "antigravity_message"),
                ("conversation_databases__*.db", "antigravity_conversation_db"),
                ("scratch_artifacts__*", "antigravity_scratch_file"),
                ("annotations__*.pbtxt", "antigravity_annotation"),
                ("application_state__*.pbtxt", "antigravity_state"),
            )
            for pattern, artifact_type in compact_patterns:
                candidates.extend(
                    (path, artifact_type)
                    for path in search_root.glob(pattern)
                    if path.is_file()
                )
        seen: set[Path] = set()
        for index, (path, artifact_type) in enumerate(sorted(candidates), start=1):
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
                service=_SERVICE,
                size=path.stat().st_size,
                original_path=(
                    str(manifest_entry.get("original_path"))
                    if manifest_entry.get("original_path")
                    else None
                ),
                metadata=manifest_entry,
            )
            context.progress(round(index / max(len(candidates), 1) * 100), f"Discovered {path.name}")

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = tuple(artifacts)
        issues: list[StructuredDataIssue] = []
        for index, artifact in enumerate(artifact_list, start=1):
            if context.cancelled():
                break
            path = Path(artifact.path)
            try:
                if artifact.artifact_type == "antigravity_transcript":
                    self._parse_transcript(source, artifact, emit, issues, context)
                elif artifact.artifact_type == "antigravity_message":
                    emit(self._message_event(source, artifact, read_json_object(path)))
                elif artifact.artifact_type == "antigravity_conversation_db":
                    self._parse_database(source, artifact, emit, context)
                elif artifact.artifact_type in {"antigravity_annotation", "antigravity_state"}:
                    emit(self._textproto_event(source, artifact))
                elif artifact.artifact_type == "antigravity_scratch_file":
                    emit(self._scratch_event(source, artifact))
            except (OSError, ValueError, sqlite3.Error) as exc:
                issues.append(StructuredDataIssue(str(path), "file", str(exc)))
            context.progress(round(index / max(len(artifact_list), 1) * 100), f"Parsed {path.name}")
        if issues:
            context.options.setdefault("antigravity_errors", []).extend(issues)

    def _parse_transcript(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        emit: EventSink,
        issues: list[StructuredDataIssue],
        context: ParseContext,
    ) -> None:
        path = Path(artifact.path)
        session_id = _session_id(Path(artifact.original_path or artifact.path), "brain")
        for record in iter_json_lines(path, issues):
            if context.cancelled():
                return
            payload = record.value
            source_name = str(payload.get("source") or "")
            actor = {
                "USER_EXPLICIT": "user",
                "MODEL": "assistant",
                "SYSTEM": "system",
            }.get(source_name)
            step_type = str(payload.get("type") or "record")
            content = payload.get("content")
            text = content if isinstance(content, str) else None
            is_action = step_type in _ACTION_TYPES
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=parse_timestamp(payload.get("created_at")) or file_timestamp(path),
                    event_type=f"antigravity_{step_type.lower()}",
                    path=_text_path(text),
                    service=_SERVICE,
                    session_id=session_id,
                    actor=actor,
                    tool_name=step_type if is_action else None,
                    command=text if is_action else None,
                    result=text if not is_action else None,
                    attribution=(
                        AgentAttribution.CONFIRMED
                        if is_action and actor == "assistant"
                        else AgentAttribution.HIGH
                        if actor == "assistant"
                        else AgentAttribution.NONE
                    ),
                    attribution_score=1.0 if is_action and actor == "assistant" else 0.85 if actor == "assistant" else 0.0,
                    attribution_reasons=("antigravity_model_action",) if actor == "assistant" else (),
                    raw_reference=f"{artifact.record_id}:line={record.line_number}",
                    metadata=json_safe(payload),
                )
            )

    def _message_event(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        payload: dict[str, Any],
    ) -> NormalizedEvent:
        path = Path(artifact.path)
        sender = str(payload.get("sender")) if payload.get("sender") else None
        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=parse_timestamp(payload.get("timestamp")) or file_timestamp(path),
            event_type="antigravity_interagent_message",
            service=_SERVICE,
            session_id=_session_id(Path(artifact.original_path or artifact.path), "brain"),
            actor=sender,
            result=str(payload.get("content")) if payload.get("content") is not None else None,
            attribution=AgentAttribution.HIGH,
            attribution_score=0.85,
            attribution_reasons=("antigravity_internal_message",),
            raw_reference=artifact.record_id,
            metadata=json_safe(payload),
        )

    def _parse_database(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        path = Path(artifact.path)
        fallback = file_timestamp(path)
        session_id = path.stem
        for row in iter_sqlite_rows(path):
            if context.cancelled():
                return
            values = row.values
            if row.table == "trajectory_meta" and values.get("trajectory_id"):
                session_id = str(values["trajectory_id"])
            timestamp = _timestamp_from_mapping(values) or fallback
            step_type = values.get("step_type") if row.table == "steps" else None
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=timestamp,
                    event_type=f"antigravity_db_{row.table}",
                    service=_SERVICE,
                    session_id=session_id,
                    actor="assistant" if row.table == "steps" else None,
                    tool_name=f"step_type:{step_type}" if step_type is not None else None,
                    attribution=AgentAttribution.HIGH if row.table == "steps" else AgentAttribution.NONE,
                    attribution_score=0.8 if row.table == "steps" else 0.0,
                    attribution_reasons=("antigravity_conversation_step",) if row.table == "steps" else (),
                    raw_reference=f"{artifact.record_id}:table={row.table}:row={row.row_number}",
                    metadata=values,
                )
            )

    def _textproto_event(self, source: EvidenceSource, artifact: ArtifactRecord) -> NormalizedEvent:
        path = Path(artifact.path)
        fields = _parse_textproto_fields(path)
        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=_timestamp_from_mapping(fields) or file_timestamp(path),
            event_type=artifact.artifact_type,
            service=_SERVICE,
            session_id=path.stem if artifact.artifact_type == "antigravity_annotation" else None,
            raw_reference=artifact.record_id,
            metadata={"fields": fields, "source_file": str(path)},
        )

    def _scratch_event(self, source: EvidenceSource, artifact: ArtifactRecord) -> NormalizedEvent:
        path = Path(artifact.path)
        return NormalizedEvent(
            source_id=source.source_id,
            parser_id=self.metadata.parser_id,
            timestamp=file_timestamp(path),
            event_type="antigravity_scratch_file",
            path=str(path),
            service=_SERVICE,
            actor="assistant",
            attribution=AgentAttribution.HIGH,
            attribution_score=0.8,
            attribution_reasons=("antigravity_scratch_artifact",),
            raw_reference=artifact.record_id,
            metadata={"size": path.stat().st_size, "suffix": path.suffix.lower()},
        )


def _session_id(path: Path, marker: str) -> str | None:
    lowered = [part.lower() for part in path.parts]
    try:
        index = lowered.index(marker.lower())
    except ValueError:
        return None
    return path.parts[index + 1] if index + 1 < len(path.parts) else None


def _text_path(text: str | None) -> str | None:
    if not text:
        return None
    match = re.search(r"(?:[A-Za-z]:\\|/)[^\s'\"]+", text)
    return match.group(0) if match else None


def _parse_textproto_fields(path: Path) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            match = pattern.match(line)
            if not match:
                continue
            key, raw_value = match.groups()
            value = raw_value.strip().strip('"')
            existing = fields.get(key)
            if existing is None:
                fields[key] = value
            elif isinstance(existing, list):
                existing.append(value)
            else:
                fields[key] = [existing, value]
    return fields


def _timestamp_from_mapping(values: dict[str, Any]) -> Any:
    for key, value in values.items():
        if "time" in key.lower() or key.lower().endswith("_at"):
            if (timestamp := parse_timestamp(value)) is not None:
                return timestamp
    return None


def _service_roots(location: Path, service_directory: str) -> tuple[Path, ...]:
    compact = location / service_directory
    return (compact,) if compact.is_dir() else (location,)
