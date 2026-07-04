from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from core.models import ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from parsers.claude_common import claude_record_events
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

_SERVICE = "Claude Code"
_SESSION_GLOB = "**/.claude/projects/**/*.jsonl"
_METADATA_GLOB = "**/claude-code-sessions/**/*.json"
_LOG_GLOB = "**/Roaming/Claude/logs/main.log"


class ClaudeCodeParser(ArtifactParser):
    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="claude.code",
            name="Claude Code",
            category="service",
            version=__version__,
            services=(_SERVICE,),
            description="Parses Claude Code sessions, desktop session metadata, and application logs.",
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        return 0.95 if any(self.discover(source, ParseContext(source.location))) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        candidates: list[tuple[Path, str]] = []
        manifest: dict[str, dict[str, object]] = {}
        for search_root in _service_roots(source.location, "Claude_Code"):
            manifest.update(load_collection_manifest(search_root))
            for path in search_root.glob(_SESSION_GLOB):
                normalized = str(path).replace("\\", "/").lower()
                if path.is_file() and "/local-agent-mode-sessions/" not in normalized:
                    candidates.append((path, "claude_code_session_jsonl"))
            candidates.extend(
                (path, "claude_code_session_jsonl")
                for path in search_root.glob("project_sessions__*.jsonl")
                if path.is_file()
            )
            candidates.extend(
                (path, "claude_code_session_metadata")
                for pattern in (_METADATA_GLOB, "desktop_session_metadata__*.json")
                for path in search_root.glob(pattern)
                if path.is_file()
            )
            candidates.extend(
                (path, "claude_application_log")
                for pattern in (_LOG_GLOB, "application_logs__*.log")
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
                if artifact.artifact_type == "claude_code_session_jsonl":
                    for record in iter_json_lines(path, issues):
                        if context.cancelled():
                            break
                        for event in claude_record_events(
                            source,
                            parser_id=self.metadata.parser_id,
                            service=_SERVICE,
                            artifact=artifact,
                            payload=record.value,
                            line_number=record.line_number,
                        ):
                            emit(event)
                elif artifact.artifact_type == "claude_code_session_metadata":
                    emit(self._metadata_event(source, artifact, read_json_object(path)))
                elif artifact.artifact_type == "claude_application_log":
                    for record in iter_timestamped_log(path):
                        emit(
                            NormalizedEvent(
                                source_id=source.source_id,
                                parser_id=self.metadata.parser_id,
                                timestamp=record.timestamp or file_timestamp(path),
                                event_type="claude_application_log",
                                path=_path_from_log(record.message),
                                service=_SERVICE,
                                result=record.message,
                                raw_reference=f"{artifact.record_id}:line={record.line_number}",
                                metadata={"level": record.level, "line_number": record.line_number},
                            )
                        )
            except (OSError, ValueError) as exc:
                issues.append(StructuredDataIssue(str(path), "file", str(exc)))
            context.progress(round(index / max(len(artifact_list), 1) * 100), f"Parsed {path.name}")
        if issues:
            context.options.setdefault("claude_code_errors", []).extend(issues)

    def _metadata_event(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        payload: dict[str, object],
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
            event_type="claude_code_session_metadata",
            path=str(payload.get("cwd")) if payload.get("cwd") else None,
            service=_SERVICE,
            session_id=str(payload.get("sessionId")) if payload.get("sessionId") else None,
            result=str(payload.get("title")) if payload.get("title") else None,
            raw_reference=artifact.record_id,
            metadata=json_safe(payload),
        )


def _path_from_log(message: str) -> str | None:
    match = re.search(r"(?:[A-Za-z]:\\|/)[^\s'\"]+", message)
    return match.group(0) if match else None


def _service_roots(location: Path, service_directory: str) -> tuple[Path, ...]:
    compact = location / service_directory
    return (compact,) if compact.is_dir() else (location,)
