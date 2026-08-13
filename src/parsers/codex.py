from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp, iter_sqlite_rows, parse_timestamp, sqlite_tables
from utils.text_encoding import repair_text_tree
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

_SESSION_ID_PATTERN = re.compile(
    r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})",
    re.IGNORECASE,
)
_TRANSCRIPT_BLOCK_PATTERN = re.compile(
    r">>>\s*(?P<kind>TRANSCRIPT(?:\s+DELTA)?)\s+START\s*"
    r"(?P<body>.*?)\s*>>>\s*(?P=kind)\s+END",
    re.DOTALL | re.IGNORECASE,
)
_TRANSCRIPT_ENTRY_PATTERN = re.compile(
    r"(?m)^\[(?P<index>\d+)]\s+"
    r"(?:(?P<role>user|assistant)\s*:|tool\s+(?P<tool>.+?)\s+(?P<tool_kind>call|result)\s*:)\s*",
    re.IGNORECASE,
)
_REVIEWED_SESSION_PATTERN = re.compile(
    r"Reviewed Codex session id:\s*([0-9a-f-]{36})",
    re.IGNORECASE,
)

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


# Codex's own session-event stream (``event_msg``) names shell/patch/MCP tool
# invocations as *_begin / *_end pairs (see codex-rs's protocol.rs event enum) —
# this hasn't been verified against a captured real session, so it's applied as
# a naming-convention match rather than an exact enum, and always degrades to
# the generic payload dump (_payload_fallback) if the guess is wrong.
_TOOL_FAMILY_HINTS = ("exec_command", "exec", "command", "patch", "mcp_tool_call", "web_search")


def _event_msg_tool_family(sub_type: str) -> str | None:
    """Short tool-family name (e.g. "exec_command") for a *_begin/*_end event_msg."""
    for suffix in ("_begin", "_end"):
        if sub_type.endswith(suffix):
            base = sub_type[: -len(suffix)]
            if any(hint in base for hint in _TOOL_FAMILY_HINTS):
                return base
    return None


def _reasoning_text(payload: dict) -> str | None:
    """Text of a Responses-API ``reasoning`` item: a list of summary parts."""
    summary = payload.get("summary")
    if isinstance(summary, list):
        texts = [
            part.get("text")
            for part in summary
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        if texts:
            return "\n".join(texts)
    text = payload.get("text")
    return text if isinstance(text, str) else None


_COMMAND_FIELDS = ("command", "cmd", "invocation", "changes")
_OUTPUT_FIELDS = ("aggregated_output", "output", "stdout", "result")


def _first_text_field(payload: dict, fields: tuple[str, ...]) -> str | None:
    for field in fields:
        value = payload.get(field)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            joined = " ".join(str(item) for item in value)
            if joined:
                return joined
    return None


def _payload_fallback(payload: dict, *, max_length: int = 1500) -> str | None:
    """Readable stand-in for event_msg/response_item sub-types this parser
    doesn't extract dedicated fields for (task lifecycle, approvals, token
    counts, plan updates, etc.) — indented JSON instead of a blank event body.
    """
    if not payload:
        return None
    try:
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    except (TypeError, ValueError):
        text = str(payload)
    return text if len(text) <= max_length else text[:max_length] + "…"


def _derive_actor(record_type: str, payload: dict) -> str | None:
    if record_type == "response_item":
        role = payload.get("role")
        if isinstance(role, str):
            return role
        sub_type = payload.get("type")
        if sub_type in ("function_call", "custom_tool_call"):
            return "assistant"
        if sub_type in ("function_call_output", "custom_tool_call_output"):
            return "tool"
        if sub_type == "reasoning":
            return "assistant"
    if record_type == "event_msg":
        sub_type = payload.get("type") or ""
        if sub_type == "user_message":
            return "user"
        if sub_type in ("agent_message", "agent_message_delta", "agent_reasoning", "agent_reasoning_delta"):
            return "assistant"
        if _event_msg_tool_family(sub_type):
            return "tool" if sub_type.endswith("_end") else "assistant"
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
        if sub_type == "custom_tool_call":
            name = payload.get("name")
            tool_input = payload.get("input")
            return (
                name if isinstance(name, str) else None,
                tool_input if isinstance(tool_input, str) else _payload_fallback({"input": tool_input}),
                None,
            )
        if sub_type == "function_call_output":
            output = payload.get("output")
            return None, None, (output if isinstance(output, str) else None)
        if sub_type == "custom_tool_call_output":
            output = payload.get("output")
            return None, None, (output if isinstance(output, str) else None)
        if sub_type == "reasoning":
            return None, None, _reasoning_text(payload)
    if record_type == "event_msg":
        sub_type = payload.get("type") or ""
        if sub_type in ("user_message", "agent_message"):
            message = payload.get("message")
            return None, None, (message if isinstance(message, str) else None)
        if sub_type == "agent_message_delta":
            delta = payload.get("delta")
            return None, None, (delta if isinstance(delta, str) else None)
        if sub_type in ("agent_reasoning", "agent_reasoning_delta"):
            text = payload.get("text") or payload.get("delta")
            return None, None, (text if isinstance(text, str) else None)
        family = _event_msg_tool_family(sub_type)
        if family:
            if sub_type.endswith("_begin"):
                return family, _first_text_field(payload, _COMMAND_FIELDS), None
            return family, None, _first_text_field(payload, _OUTPUT_FIELDS)
    return None, None, None


def expand_codex_embedded_transcript(
    event: NormalizedEvent,
) -> tuple[NormalizedEvent, ...]:
    """Split an approval/subagent history wrapper into individual chat events.

    Codex stores the reviewed parent transcript inside one subagent user message.
    The wrapper remains available as low-signal evidence while the numbered
    entries become normal USER/AGENT/TOOL rows for conversation reconstruction.
    """
    if (
        event.event_type != "codex_event_msg.user_message"
        or not event.result
    ):
        return (event,)
    block = _TRANSCRIPT_BLOCK_PATTERN.search(event.result)
    if block is None:
        return (event,)
    body = block.group("body")
    matches = list(_TRANSCRIPT_ENTRY_PATTERN.finditer(body))
    if not matches:
        return (event,)

    reviewed_match = _REVIEWED_SESSION_PATTERN.search(event.result)
    reviewed_session_id = reviewed_match.group(1) if reviewed_match else None
    target_session_id = (
        reviewed_session_id
        or event.metadata.get("parent_session_id")
        or event.session_id
    )
    transcript_kind = "delta" if "DELTA" in block.group("kind").upper() else "full"
    wrapper_metadata = {
        **event.metadata,
        "importance": "low",
        "embedded_transcript_expanded": True,
        "embedded_transcript_entries": len(matches),
    }
    wrapper = replace(event, metadata=wrapper_metadata)
    expanded: list[NormalizedEvent] = [wrapper]
    for position, match in enumerate(matches):
        end = matches[position + 1].start() if position + 1 < len(matches) else len(body)
        text = body[match.end() : end].strip()
        role = (match.group("role") or "").lower()
        tool_name = (match.group("tool") or "").strip() or None
        tool_kind = (match.group("tool_kind") or "").lower()
        if role == "user":
            event_type = "codex_embedded_transcript.user_message"
            actor = "user"
            command = None
            result = text
        elif role == "assistant":
            event_type = "codex_embedded_transcript.agent_message"
            actor = "assistant"
            command = None
            result = text
        elif tool_kind == "call":
            event_type = "codex_embedded_transcript.tool_call"
            actor = "assistant"
            command = text
            result = None
        else:
            event_type = "codex_embedded_transcript.tool_result"
            actor = "tool"
            command = None
            result = text
        fingerprint_source = "\0".join(
            (event_type, actor, tool_name or "", command or "", result or "")
        )
        entry_fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
        expanded.append(
            NormalizedEvent(
                source_id=event.source_id,
                parser_id=event.parser_id,
                timestamp=event.timestamp,
                event_type=event_type,
                service=event.service,
                session_id=target_session_id,
                actor=actor,
                tool_name=tool_name,
                command=command,
                result=result,
                attribution=event.attribution,
                attribution_score=event.attribution_score,
                attribution_reasons=event.attribution_reasons + ("codex_embedded_transcript",),
                actor_class=event.actor_class,
                raw_reference=(
                    f"{event.raw_reference}:transcript={match.group('index')}"
                    if event.raw_reference
                    else None
                ),
                metadata={
                    "embedded_transcript": True,
                    "embedded_transcript_kind": transcript_kind,
                    "embedded_transcript_fingerprint": entry_fingerprint,
                    "transcript_index": int(match.group("index")),
                    "transcript_role": role or f"tool_{tool_kind}",
                    "reviewed_session_id": reviewed_session_id,
                    "transcript_source_session_id": event.session_id,
                    "wrapper_event_id": event.event_id,
                },
            )
        )
    return tuple(expanded)


# Verified against a real state_*.sqlite `threads` table: `title` is a short
# auto-generated summary distinct from `first_user_message` (the full raw
# prompt text) - e.g. title="test3 폴더 생성" vs.
# first_user_message="C:\Users\...\Project 폴더에 test3 폴더를 생성해줘".
# `title` must come first, or the real title is never used since
# first_user_message is NOT NULL and therefore always non-empty.
_TABLE_RESULT_COLUMNS = {
    "threads": ("title", "first_user_message", "preview"),
    "logs": ("feedback_log_body",),
}

# `logs` rows carry the session/thread UUID in `thread_id`, not `id` (verified:
# values there match real thread ids from `threads.id` and the session JSONL).
_TABLE_SESSION_ID_COLUMNS = {
    "threads": "id",
    "logs": "thread_id",
}

# The `logs` table is Codex's internal feedback/telemetry log, not conversation
# content (unlike `threads`, which indexes actual sessions) - low-signal by
# default so it doesn't crowd out prompts/tool calls/messages in the UI.
_LOW_IMPORTANCE_TABLES = {"logs", "threads"}

# event_msg sub-types that are Codex's own streaming/lifecycle bookkeeping
# (superseded by the final agent_message/agent_reasoning, or pure protocol
# noise like token counts) rather than conversation content a reviewer needs
# to read by default.
_LOW_IMPORTANCE_EVENT_MSG_TYPES = {"agent_message_delta", "agent_reasoning_delta"}
_LOW_IMPORTANCE_RESPONSE_ITEM_TYPES = {"message", "reasoning"}


def _session_role(payload: dict) -> str | None:
    source = payload.get("source")
    if isinstance(source, dict):
        subagent = source.get("subagent")
        if isinstance(subagent, dict) and subagent.get("other") == "guardian":
            return "guardian"
        if subagent is not None:
            return "subagent"
    thread_source = payload.get("thread_source")
    return thread_source if isinstance(thread_source, str) else None


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


# Verified against a real `threads` table: `thread_source` matches the same
# "user"/"subagent" values seen in the session JSONL's session_meta payload.
_THREAD_SOURCE_ACTORS = {"user": "user", "subagent": "assistant"}


def _row_actor(table_name: str, values: dict[str, object]) -> str | None:
    if table_name == "threads":
        return _THREAD_SOURCE_ACTORS.get(values.get("thread_source"))
    return None


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
        available_session_ids = {
            session_id
            for artifact in artifact_list
            if artifact.artifact_type == _SESSION_ARTIFACT_TYPE
            if (session_id := _session_id_from_path(Path(artifact.path)))
        }
        embedded_transcript_seen: set[tuple[str, str]] = set()
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
                    self._parse_session_jsonl(
                        source,
                        artifact,
                        emit,
                        context,
                        available_session_ids=available_session_ids,
                        embedded_transcript_seen=embedded_transcript_seen,
                    )
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
            metadata = dict(row.values)
            if table_name in _LOW_IMPORTANCE_TABLES:
                metadata["importance"] = "low"

            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=timestamp,
                    event_type=f"codex_{table_name}_record",
                    service=_SERVICE_NAME,
                    session_id=session_id,
                    actor=_row_actor(table_name, row.values),
                    result=_row_result(table_name, row.values),
                    attribution=AgentAttribution.HIGH,
                    attribution_score=0.8,
                    attribution_reasons=(f"codex_desktop_{table_name}_table",),
                    raw_reference=f"{artifact.record_id}:table={row.table}:row={row.row_number}",
                    metadata=metadata,
                )
            )

    def _parse_session_jsonl(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        emit: EventSink,
        context: ParseContext,
        *,
        available_session_ids: set[str],
        embedded_transcript_seen: set[tuple[str, str]],
    ) -> None:
        session_path = Path(artifact.path)
        fallback_timestamp = file_timestamp(session_path)
        # A rollout file is one state-db thread. Newer subagent/fork records also
        # carry ``payload.session_id``, but that value is the parent thread and
        # must not be used to group this file's conversation.
        current_session_id = _session_id_from_path(session_path)
        parent_session_id: str | None = None
        primary_meta_seen = False
        session_role: str | None = None
        call_names: dict[str, str] = {}

        with session_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
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
                payload, encoding_repairs = repair_text_tree(payload)

                if record_type == "session_meta" and not primary_meta_seen:
                    record_session_id = payload.get("id") or payload.get("session_id")
                    if not current_session_id and isinstance(record_session_id, str):
                        current_session_id = record_session_id
                    candidate_parent = payload.get("session_id")
                    if (
                        isinstance(candidate_parent, str)
                        and candidate_parent != current_session_id
                    ):
                        parent_session_id = candidate_parent
                    primary_meta_seen = True
                    session_role = _session_role(payload)

                sub_type = payload.get("type") if record_type in ("event_msg", "response_item") else None
                sanitized = _sanitize_payload(payload)
                if encoding_repairs:
                    sanitized["encoding_repairs"] = encoding_repairs
                tool_name, command, result = _derive_display(record_type, payload, sanitized)
                call_id = payload.get("call_id")
                if (
                    record_type == "response_item"
                    and sub_type in ("function_call", "custom_tool_call")
                    and isinstance(call_id, str)
                    and tool_name
                ):
                    call_names[call_id] = tool_name
                elif (
                    record_type == "response_item"
                    and sub_type in ("function_call_output", "custom_tool_call_output")
                    and isinstance(call_id, str)
                ):
                    tool_name = call_names.get(call_id)

                tool_family = _event_msg_tool_family(sub_type) if record_type == "event_msg" and sub_type else None
                if tool_family:
                    # Give exec/patch/mcp *_begin/*_end pairs a tool_call/tool_result
                    # event_type (not just codex_event_msg.<sub_type>) so the UI's
                    # generic kind classifier recognizes them like Claude's tool blocks.
                    kind = "tool_call" if sub_type.endswith("_begin") else "tool_result"
                    event_type = f"codex_{kind}.{tool_family}"
                elif record_type == "response_item" and sub_type == "custom_tool_call":
                    event_type = f"codex_tool_call.{tool_name or 'custom'}"
                elif record_type == "response_item" and sub_type == "custom_tool_call_output":
                    event_type = f"codex_tool_result.{tool_name or 'custom'}"
                elif sub_type:
                    event_type = f"codex_{record_type}.{sub_type}"
                else:
                    event_type = f"codex_{record_type}"
                timestamp = parse_timestamp(record.get("timestamp")) or fallback_timestamp
                is_unrecognized = tool_name is None and command is None and result is None
                if is_unrecognized:
                    result = _payload_fallback(sanitized)
                # Anything this parser doesn't recognize as conversation content
                # (task lifecycle, token counts, approvals, ...) falls back to a
                # raw payload dump - that's exactly the noise a reviewer wants
                # collapsed by default, along with streaming deltas that are
                # superseded by their own final agent_message/agent_reasoning.
                if (
                    is_unrecognized
                    or sub_type in _LOW_IMPORTANCE_EVENT_MSG_TYPES
                    or (
                        record_type == "response_item"
                        and sub_type in _LOW_IMPORTANCE_RESPONSE_ITEM_TYPES
                    )
                ):
                    sanitized["importance"] = "low"
                sanitized["artifact_session_id"] = current_session_id
                if session_role:
                    sanitized["session_role"] = session_role
                if session_role == "guardian":
                    sanitized["importance"] = "low"
                if parent_session_id:
                    sanitized["parent_session_id"] = parent_session_id

                normalized_event = NormalizedEvent(
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
                    raw_reference=f"{artifact.record_id}:line={line_number}",
                    metadata=sanitized,
                )
                for expanded_event in expand_codex_embedded_transcript(normalized_event):
                    fingerprint = expanded_event.metadata.get("embedded_transcript_fingerprint")
                    if isinstance(fingerprint, str):
                        target_session = expanded_event.session_id or ""
                        # Guardian/approval transcripts are secondary copies of
                        # the parent rollout. Keep the low-signal wrapper as raw
                        # evidence, but prefer the canonical parent JSONL when it
                        # was collected with this case.
                        if target_session != current_session_id and target_session in available_session_ids:
                            continue
                        identity = (target_session, fingerprint)
                        if identity in embedded_transcript_seen:
                            continue
                        embedded_transcript_seen.add(identity)
                    emit(expanded_event)

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


def _session_id_from_path(path: Path) -> str | None:
    matches = _SESSION_ID_PATTERN.findall(path.name)
    return matches[-1] if matches else None
