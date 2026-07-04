from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from version import __version__

_SERVICE_NAME = "Codex"

_CODEX_HOME_GLOB = "**/.codex"
_LOG_DB_GLOB = "logs_*.sqlite"
_STATE_DB_GLOB = "state_*.sqlite"
_SESSIONS_GLOB = "sessions/**/*.jsonl"

_LOG_DB_ARTIFACT_TYPE = "codex_log_db"
_STATE_DB_ARTIFACT_TYPE = "codex_state_db"
_SESSION_ARTIFACT_TYPE = "codex_session_jsonl"

_TIMESTAMP_COLUMN_CANDIDATES = (
    "timestamp", "created_at", "createdat", "updated_at", "updatedat",
    "ts", "time", "started_at", "startedat",
)


def _find_codex_homes(location: Path) -> tuple[Path, ...]:
    if not location.exists():
        return ()
    homes: set[Path] = set()

    # The source may already be the .codex home itself (named ".codex" or not,
    # e.g. after a manual extraction that dropped the original folder name).
    if (
        location.name == ".codex"
        or any(location.glob(_LOG_DB_GLOB))
        or any(location.glob(_STATE_DB_GLOB))
        or (location / "sessions").is_dir()
    ):
        homes.add(location)

    homes.update(path for path in location.glob(_CODEX_HOME_GLOB) if path.is_dir())
    return tuple(sorted(homes))


def _mtime_fallback(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sanitize_payload(payload: dict) -> dict:
    sanitized = dict(payload)
    encrypted_content = sanitized.pop("encrypted_content", None)
    if encrypted_content is not None:
        sanitized["encrypted_content_length"] = (
            len(encrypted_content) if isinstance(encrypted_content, str) else None
        )
    if sanitized.get("type") == "message" and isinstance(sanitized.get("content"), list):
        texts = [
            part.get("text")
            for part in sanitized["content"]
            if isinstance(part, dict) and part.get("text")
        ]
        if texts:
            sanitized["text"] = "\n".join(texts)
    return sanitized


def _derive_actor(record_type: str, payload: dict) -> str | None:
    if record_type == "response_item":
        role = payload.get("role")
        if isinstance(role, str):
            return role
        sub_type = payload.get("type")
        if sub_type == "function_call":
            return "assistant"
        if sub_type == "function_call_output":
            return "tool"
    if record_type == "event_msg":
        sub_type = payload.get("type")
        if sub_type == "user_message":
            return "user"
        if sub_type == "agent_message":
            return "assistant"
    return None


def _guess_timestamp_column(columns: list[str]) -> str | None:
    lowered = {column.lower(): column for column in columns}
    for candidate in _TIMESTAMP_COLUMN_CANDIDATES:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _coerce_timestamp(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**12 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        return _parse_iso(value)
    return None


def _json_safe(value: object) -> object:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return value


class CodexParser(ArtifactParser):
    """Parses Codex's .codex sqlite logs/threads tables and session JSONL transcripts."""

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="codex.desktop",
            name="Codex",
            category="service",
            version=__version__,
            services=(_SERVICE_NAME,),
            description=(
                "Parses Codex's .codex sqlite logs/threads tables and .codex/sessions JSONL transcripts."
            ),
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        location = source.location
        if not location.exists():
            return 0.0
        return 0.85 if _find_codex_homes(location) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        location = source.location
        codex_homes = _find_codex_homes(location)

        records: list[ArtifactRecord] = []
        total = len(codex_homes) or 1
        scanned = 0

        for codex_home in codex_homes:
            if context.cancelled():
                return tuple(records)

            for log_db in codex_home.glob(_LOG_DB_GLOB):
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(log_db),
                        artifact_type=_LOG_DB_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            for state_db in codex_home.glob(_STATE_DB_GLOB):
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(state_db),
                        artifact_type=_STATE_DB_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            for session_file in codex_home.glob(_SESSIONS_GLOB):
                if session_file.is_file():
                    records.append(
                        ArtifactRecord(
                            source_id=source.source_id,
                            producer_id=self.metadata.parser_id,
                            path=str(session_file),
                            artifact_type=_SESSION_ARTIFACT_TYPE,
                            service=_SERVICE_NAME,
                        )
                    )

            scanned += 1
            context.progress(int(scanned / total * 100), f"Scanned {codex_home}")

        return tuple(records)

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = tuple(artifacts)
        total = len(artifact_list) or 1
        for index, artifact in enumerate(artifact_list):
            if context.cancelled():
                return

            try:
                if artifact.artifact_type == _LOG_DB_ARTIFACT_TYPE:
                    self._parse_sqlite_table(source, artifact, "logs", emit, context)
                elif artifact.artifact_type == _STATE_DB_ARTIFACT_TYPE:
                    self._parse_sqlite_table(source, artifact, "threads", emit, context)
                elif artifact.artifact_type == _SESSION_ARTIFACT_TYPE:
                    self._parse_session_jsonl(source, artifact, emit, context)
            except Exception as exc:  # noqa: BLE001 - one bad artifact must not sink the rest
                context.options.setdefault("codex_errors", []).append(
                    f"{artifact.path}: {exc}"
                )

            context.progress(int((index + 1) / total * 100), f"Parsed {artifact.path}")

    def _parse_sqlite_table(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        table_name: str,
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        db_path = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(db_path)

        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(f"SELECT * FROM {table_name}")
            columns = [description[0] for description in cursor.description]
            timestamp_column = _guess_timestamp_column(columns)

            for row in cursor:
                if context.cancelled():
                    return

                row_dict = {column: _json_safe(row[column]) for column in columns}
                timestamp = None
                if timestamp_column is not None:
                    timestamp = _coerce_timestamp(row_dict.get(timestamp_column))
                timestamp = timestamp or fallback_timestamp
                session_id = row_dict.get("id") if table_name == "threads" else None

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type=f"codex_{table_name}_record",
                        service=_SERVICE_NAME,
                        session_id=session_id,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=(f"codex_desktop_{table_name}_table",),
                        raw_reference=artifact.record_id,
                        metadata=row_dict,
                    )
                )
        finally:
            connection.close()

    def _parse_session_jsonl(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        session_path = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(session_path)
        current_session_id: str | None = None

        with session_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if context.cancelled():
                    return

                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                record_type = record.get("type", "unknown")
                payload = record.get("payload")
                payload = payload if isinstance(payload, dict) else {}

                if record_type == "session_meta":
                    current_session_id = payload.get("session_id") or current_session_id

                sub_type = payload.get("type") if record_type in ("event_msg", "response_item") else None
                event_type = f"codex_{record_type}.{sub_type}" if sub_type else f"codex_{record_type}"
                timestamp = _parse_iso(record.get("timestamp")) or fallback_timestamp

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type=event_type,
                        service=_SERVICE_NAME,
                        session_id=current_session_id,
                        actor=_derive_actor(record_type, payload),
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("codex_desktop_session_log_path",),
                        raw_reference=artifact.record_id,
                        metadata=_sanitize_payload(payload),
                    )
                )
