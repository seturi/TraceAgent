from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp, iter_sqlite_rows, parse_timestamp, sqlite_tables
from version import __version__

_SERVICE_NAME = "Codex"

_CODEX_HOME_GLOB = "**/.codex"
_LOG_DB_GLOB = "logs_*.sqlite"
_STATE_DB_GLOB = "state_*.sqlite"
_SESSIONS_GLOB = "sessions/**/*.jsonl"

_LOG_DB_ARTIFACT_TYPE = "codex_log_db"
_STATE_DB_ARTIFACT_TYPE = "codex_state_db"
_SESSION_ARTIFACT_TYPE = "codex_session_jsonl"
_HISTORY_ARTIFACT_TYPE = "codex_history_jsonl"

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


def _function_call_command(payload: dict) -> str | None:
    arguments = payload.get("arguments")
    if not isinstance(arguments, str):
        return None
    try:
        parsed = json.loads(arguments)
    except json.JSONDecodeError:
        return arguments
    if isinstance(parsed, dict):
        command = parsed.get("command")
        if isinstance(command, str):
            return command
        if isinstance(command, list):
            return " ".join(str(part) for part in command)
    return arguments


def _derive_display(
    record_type: str, payload: dict, sanitized: dict
) -> tuple[str | None, str | None, str | None]:
    """Map a session-log record onto the UI's (tool_name, command, result) fields."""
    if record_type == "response_item":
        sub_type = payload.get("type")
        if sub_type == "message":
            text = sanitized.get("text")
            return None, None, (text if isinstance(text, str) else None)
        if sub_type == "function_call":
            name = payload.get("name")
            return (
                name if isinstance(name, str) else None,
                _function_call_command(payload),
                None,
            )
        if sub_type == "function_call_output":
            output = payload.get("output")
            return None, None, (output if isinstance(output, str) else None)
    if record_type == "event_msg":
        sub_type = payload.get("type")
        if sub_type in ("user_message", "agent_message"):
            message = payload.get("message")
            return None, None, (message if isinstance(message, str) else None)
    return None, None, None


# Verified against real state_*.sqlite `threads` / logs_*.sqlite `logs` tables:
# these columns hold actual human-readable content, in priority order, so
# prefer them over the generic key=value dump.
_TABLE_RESULT_COLUMNS = {
    "threads": ("first_user_message", "title", "preview"),
    "logs": ("feedback_log_body",),
}

# `logs` rows carry the session/thread UUID in `thread_id`, not `id` (verified:
# values there match real thread ids from `threads.id` and the session JSONL).
_TABLE_SESSION_ID_COLUMNS = {
    "threads": "id",
    "logs": "thread_id",
}


def _row_result(table_name: str, values: dict[str, object]) -> str | None:
    for column in _TABLE_RESULT_COLUMNS.get(table_name, ()):
        value = values.get(column)
        if isinstance(value, str) and value:
            return value
    return _row_summary(values)


def _row_session_id(table_name: str, values: dict[str, object]) -> str | None:
    column = _TABLE_SESSION_ID_COLUMNS.get(table_name)
    if column is None:
        return None
    value = values.get(column)
    return value if isinstance(value, str) else None


def _row_summary(
    values: dict[str, object],
    *,
    max_fields: int = 6,
    max_field_length: int = 200,
    max_total_length: int = 1500,
) -> str | None:
    """Render a sqlite row as a readable one-line summary for the UI's result field.

    Generic fallback for tables/columns that haven't been individually verified
    yet — surfaces every non-empty column instead of leaving the event body blank.
    """
    parts: list[str] = []
    for key, value in values.items():
        if value is None or value == "":
            continue
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        if len(text) > max_field_length:
            text = text[:max_field_length] + "…"
        parts.append(f"{key}={text}")
        if len(parts) >= max_fields:
            break
    if not parts:
        return None
    summary = " | ".join(parts)
    return summary if len(summary) <= max_total_length else summary[:max_total_length] + "…"


def _row_timestamp(values: dict[str, object]) -> datetime | None:
    # `logs` rows pack sub-second precision into `ts` (whole seconds) + `ts_nanos`
    # separately (verified: hundreds of rows can share the same whole second),
    # so combine them before falling back to the generic single-column guess.
    ts, ts_nanos = values.get("ts"), values.get("ts_nanos")
    if isinstance(ts, (int, float)) and isinstance(ts_nanos, (int, float)):
        try:
            return datetime.fromtimestamp(ts + ts_nanos / 1_000_000_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    lowered = {key.lower(): key for key in values}
    for candidate in _TIMESTAMP_COLUMN_CANDIDATES:
        key = lowered.get(candidate)
        if key is None:
            continue
        timestamp = parse_timestamp(values[key])
        if timestamp is not None:
            return timestamp
    return None


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
        location = _service_root(source.location)
        if not location.exists():
            return 0.0
        has_compact = any(
            any(location.glob(pattern))
            for pattern in (
                "session_logs__*.jsonl",
                "state_database__*.sqlite",
                "history__*.jsonl",
            )
        )
        return 0.85 if (_find_codex_homes(location) or has_compact) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        location = _service_root(source.location)
        codex_homes = (
            ()
            if (location / "collection_manifest.jsonl").is_file()
            else _find_codex_homes(location)
        )

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

        compact_patterns = (
            ("session_logs__*.jsonl", _SESSION_ARTIFACT_TYPE),
            ("state_database__*.sqlite", _STATE_DB_ARTIFACT_TYPE),
            ("history__*.jsonl", _HISTORY_ARTIFACT_TYPE),
        )
        for pattern, artifact_type in compact_patterns:
            for path in location.glob(pattern):
                if path.is_file():
                    records.append(
                        ArtifactRecord(
                            source_id=source.source_id,
                            producer_id=self.metadata.parser_id,
                            path=str(path),
                            artifact_type=artifact_type,
                            service=_SERVICE_NAME,
                        )
                    )

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
                elif artifact.artifact_type == _HISTORY_ARTIFACT_TYPE:
                    self._parse_history_jsonl(source, artifact, emit, context)
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
        fallback_timestamp = file_timestamp(db_path)

        # A `logs_*.sqlite` with no rows logged yet has no `logs` table at all
        # (verified against a real sample) — that's an empty file, not an error.
        if table_name not in sqlite_tables(db_path):
            return

        for row in iter_sqlite_rows(db_path, tables=(table_name,)):
            if context.cancelled():
                return

            timestamp = _row_timestamp(row.values) or fallback_timestamp
            session_id = _row_session_id(table_name, row.values)

            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=timestamp,
                    event_type=f"codex_{table_name}_record",
                    service=_SERVICE_NAME,
                    session_id=session_id,
                    result=_row_result(table_name, row.values),
                    attribution=AgentAttribution.HIGH,
                    attribution_score=0.8,
                    attribution_reasons=(f"codex_desktop_{table_name}_table",),
                    raw_reference=f"{artifact.record_id}:table={row.table}:row={row.row_number}",
                    metadata=row.values,
                )
            )

    def _parse_session_jsonl(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        session_path = Path(artifact.path)
        fallback_timestamp = file_timestamp(session_path)
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
                timestamp = parse_timestamp(record.get("timestamp")) or fallback_timestamp
                sanitized = _sanitize_payload(payload)
                tool_name, command, result = _derive_display(record_type, payload, sanitized)

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type=event_type,
                        service=_SERVICE_NAME,
                        session_id=current_session_id,
                        actor=_derive_actor(record_type, payload),
                        tool_name=tool_name,
                        command=command,
                        result=result,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("codex_desktop_session_log_path",),
                        raw_reference=artifact.record_id,
                        metadata=sanitized,
                    )
                )

    def _parse_history_jsonl(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        path = Path(artifact.path)
        fallback = file_timestamp(path)
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                if context.cancelled():
                    return
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=parse_timestamp(record.get("ts")) or fallback,
                        event_type="codex_history_entry",
                        service=_SERVICE_NAME,
                        session_id=record.get("session_id"),
                        actor="user",
                        result=record.get("text"),
                        raw_reference=f"{artifact.record_id}:line={line_number}",
                        metadata=record,
                    )
                )


def _service_root(location: Path) -> Path:
    compact = location / "Codex"
    return compact if compact.is_dir() else location
