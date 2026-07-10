from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from utils.structured_data import file_timestamp, json_safe, parse_timestamp


def claude_record_events(
    source: EvidenceSource,
    *,
    parser_id: str,
    service: str,
    artifact: ArtifactRecord,
    payload: dict[str, Any],
    line_number: int,
) -> tuple[NormalizedEvent, ...]:
    timestamp = _record_timestamp(payload, Path(artifact.path))
    session_id = _string(payload.get("sessionId") or payload.get("session_id"))
    record_type = _string(payload.get("type")) or "record"
    message = payload.get("message") if isinstance(payload.get("message"), Mapping) else {}
    actor = _string(message.get("role")) or _actor_from_type(record_type)
    raw_reference = f"{artifact.record_id}:line={line_number}"
    base_metadata = {
        "record_type": record_type,
        "uuid": payload.get("uuid"),
        "parent_uuid": payload.get("parentUuid"),
        "parent_tool_use_id": payload.get("parent_tool_use_id"),
        "cwd": payload.get("cwd"),
        "git_branch": payload.get("gitBranch"),
        "is_sidechain": payload.get("isSidechain"),
        "source_file": artifact.path,
        "line_number": line_number,
        "raw": json_safe(payload),
    }

    content = message.get("content")
    if content is None:
        content = payload.get("content")
    blocks = content if isinstance(content, list) else ()
    events: list[NormalizedEvent] = []

    for block_index, block in enumerate(blocks):
        if not isinstance(block, Mapping):
            continue
        block_type = _string(block.get("type")) or "content"
        metadata = {**base_metadata, "block_index": block_index, "block": json_safe(block)}
        if block_type == "tool_use":
            tool_name = _string(block.get("name"))
            tool_input = block.get("input")
            events.append(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=parser_id,
                    timestamp=timestamp,
                    event_type="claude_tool_call",
                    path=_path_from_value(tool_input),
                    service=service,
                    session_id=session_id,
                    actor=actor or "assistant",
                    tool_name=tool_name,
                    command=_command_value(tool_name, tool_input),
                    attribution=AgentAttribution.CONFIRMED,
                    attribution_score=1.0,
                    attribution_reasons=("claude_tool_use_block",),
                    raw_reference=raw_reference,
                    metadata=metadata,
                )
            )
        elif block_type == "tool_result":
            result = block.get("content")
            events.append(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=parser_id,
                    timestamp=timestamp,
                    event_type="claude_tool_result",
                    path=_path_from_value(result),
                    service=service,
                    session_id=session_id,
                    actor=actor,
                    result=_text_value(result),
                    attribution=AgentAttribution.CONFIRMED,
                    attribution_score=1.0,
                    attribution_reasons=("claude_tool_result_block",),
                    raw_reference=raw_reference,
                    metadata=metadata,
                )
            )
        elif block_type in {"text", "thinking"}:
            text = block.get("text") if block_type == "text" else block.get("thinking")
            events.append(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=parser_id,
                    timestamp=timestamp,
                    event_type=(
                        "claude_thinking" if block_type == "thinking" else "claude_message"
                    ),
                    service=service,
                    session_id=session_id,
                    actor=actor,
                    result=_text_value(text),
                    attribution=(
                        AgentAttribution.HIGH if actor == "assistant" else AgentAttribution.NONE
                    ),
                    attribution_score=0.85 if actor == "assistant" else 0.0,
                    attribution_reasons=("claude_assistant_message",) if actor == "assistant" else (),
                    raw_reference=raw_reference,
                    metadata=metadata,
                )
            )

    if not events:
        result = _text_value(content)
        if result is None:
            result = _text_value(payload.get("result") or payload.get("lastPrompt") or payload.get("aiTitle"))
        event_type = _record_event_type(record_type, payload)
        events.append(
            NormalizedEvent(
                source_id=source.source_id,
                parser_id=parser_id,
                timestamp=timestamp,
                event_type=event_type,
                path=_path_from_value(payload),
                service=service,
                session_id=session_id,
                actor=actor,
                tool_name=_string(payload.get("tool_name")),
                command=_command_value(_string(payload.get("tool_name")), payload.get("tool_input")),
                result=result,
                attribution=(
                    AgentAttribution.HIGH if actor == "assistant" else AgentAttribution.NONE
                ),
                attribution_score=0.8 if actor == "assistant" else 0.0,
                attribution_reasons=("claude_assistant_record",) if actor == "assistant" else (),
                raw_reference=raw_reference,
                metadata=base_metadata,
            )
        )

    tool_result = payload.get("toolUseResult") or payload.get("tool_use_result")
    if tool_result is not None and not any(event.event_type == "claude_tool_result" for event in events):
        events.append(
            NormalizedEvent(
                source_id=source.source_id,
                parser_id=parser_id,
                timestamp=timestamp,
                event_type="claude_tool_result",
                path=_path_from_value(tool_result),
                service=service,
                session_id=session_id,
                actor=actor,
                result=_text_value(tool_result),
                attribution=AgentAttribution.CONFIRMED,
                attribution_score=1.0,
                attribution_reasons=("claude_top_level_tool_result",),
                raw_reference=raw_reference,
                metadata={**base_metadata, "tool_result": json_safe(tool_result)},
            )
        )
    return tuple(events)


def _record_timestamp(payload: Mapping[str, Any], path: Path) -> datetime:
    for key in ("timestamp", "_audit_timestamp", "createdAt", "lastActivityAt"):
        if (timestamp := parse_timestamp(payload.get(key))) is not None:
            return timestamp
    return file_timestamp(path)


def _record_event_type(record_type: str, payload: Mapping[str, Any]) -> str:
    if record_type == "queue-operation":
        operation = _string(payload.get("operation")) or "operation"
        return f"claude_queue_{operation}"
    if record_type == "result":
        return "claude_session_result"
    if record_type == "system" and payload.get("subtype"):
        return f"claude_system_{payload['subtype']}"
    return f"claude_{record_type.replace('_', '-')}"


def _actor_from_type(record_type: str) -> str | None:
    return record_type if record_type in {"user", "assistant", "system"} else None


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _text_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(json_safe(value), ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _command_value(tool_name: str | None, value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("command", "cmd", "query", "pattern"):
            if isinstance(value.get(key), str):
                return value[key]
    serialized = _text_value(value)
    if tool_name and serialized:
        return f"{tool_name} {serialized}"
    return serialized


def _path_from_value(value: Any) -> str | None:
    path_keys = (
        "path",
        "file_path",
        "filepath",
        "source",
        "destination",
        "target",
        "directory",
        "cwd",
    )
    if isinstance(value, Mapping):
        lowered = {str(key).lower(): item for key, item in value.items()}
        for key in path_keys:
            candidate = lowered.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for child in value.values():
            if (candidate := _path_from_value(child)) is not None:
                return candidate
    elif isinstance(value, list):
        for child in value:
            if (candidate := _path_from_value(child)) is not None:
                return candidate
    return None
