from __future__ import annotations

import json
import re
from pathlib import Path

from core.models import NormalizedEvent


def write_parsed_events(
    parsed_root: Path,
    parser_id: str,
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
) -> tuple[Path, ...]:
    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        grouped.setdefault(event.service or "unknown", []).append(event)

    outputs: list[Path] = []
    for service, service_events in grouped.items():
        service_dir = parsed_root / _safe_name(service)
        service_dir.mkdir(parents=True, exist_ok=True)
        destination = service_dir / f"{_safe_name(parser_id)}.jsonl"
        temporary = destination.with_suffix(".jsonl.partial")
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            for event in service_events:
                stream.write(json.dumps(_event_payload(event), ensure_ascii=False, default=str))
                stream.write("\n")
        temporary.replace(destination)
        outputs.append(destination)
    return tuple(outputs)


def _event_payload(event: NormalizedEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "source_id": event.source_id,
        "parser_id": event.parser_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "path": event.path,
        "service": event.service,
        "session_id": event.session_id,
        "actor": event.actor,
        "tool_name": event.tool_name,
        "command": event.command,
        "result": event.result,
        "attribution": event.attribution.value,
        "attribution_score": event.attribution_score,
        "attribution_reasons": event.attribution_reasons,
        "raw_reference": event.raw_reference,
        "metadata": event.metadata,
    }


def _safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return name or "unknown"
