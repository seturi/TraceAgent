from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.models import (
    ActorClass,
    AgentAttribution,
    ArtifactRecord,
    EvidenceSource,
    NormalizedEvent,
    SourceKind,
)
from utils.case_paths import CasePaths
from utils.structured_data import parse_timestamp
from utils.text_encoding import repair_text_tree


_REMOVED_SERVICES = frozenset({"chatgpt", "chatgpt desktop"})


class CaseLoadError(ValueError):
    """Raised when a selected directory is not a readable TraceAgent case."""


@dataclass(frozen=True, slots=True)
class LoadedCase:
    paths: CasePaths
    source: EvidenceSource
    artifacts: tuple[ArtifactRecord, ...]
    events: tuple[NormalizedEvent, ...]
    issues: tuple[str, ...] = ()


def load_case(case_root: Path) -> LoadedCase:
    root = case_root.expanduser().resolve()
    artifacts_root = root / "artifacts"
    parsed_root = root / "parsed"
    if not root.is_dir():
        raise CaseLoadError(f"Case folder does not exist: {root}")
    if not artifacts_root.is_dir() or not parsed_root.is_dir():
        raise CaseLoadError(
            "The selected folder is not a TraceAgent case. Expected artifacts and parsed folders."
        )

    issues: list[str] = []
    events = _load_events(parsed_root, issues)
    source_id = next((event.source_id for event in events if event.source_id), None)
    source = EvidenceSource(
        SourceKind.ARTIFACT_DIRECTORY,
        artifacts_root,
        label=f"Saved case: {root.name}",
        read_only=True,
        **({"source_id": source_id} if source_id else {}),
    )
    artifacts = _load_artifacts(artifacts_root, source.source_id, issues)
    if not artifacts and not events:
        raise CaseLoadError("The case contains no collected artifacts or parsed events.")
    return LoadedCase(
        CasePaths(root, artifacts_root, parsed_root),
        source,
        artifacts,
        tuple(sorted(events, key=lambda event: event.timestamp)),
        tuple(issues),
    )


def _load_events(parsed_root: Path, issues: list[str]) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for path in sorted(parsed_root.rglob("*.jsonl")):
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                    if not isinstance(payload, dict):
                        raise ValueError("expected a JSON object")
                    event = _event_from_payload(payload)
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    issues.append(f"{path.name}:line {line_number}: {exc}")
                    continue
                if not _is_removed_chatgpt(
                    event.service, event.parser_id, event.event_type
                ):
                    events.append(event)
    return events


def _event_from_payload(payload: dict[str, Any]) -> NormalizedEvent:
    payload, _ = repair_text_tree(payload)
    timestamp = parse_timestamp(payload.get("timestamp"))
    if timestamp is None:
        raise ValueError("missing or invalid event timestamp")
    attribution = _enum_value(
        AgentAttribution, payload.get("attribution"), AgentAttribution.NONE
    )
    actor_class = _enum_value(ActorClass, payload.get("actor_class"), ActorClass.UNKNOWN)
    metadata = payload.get("metadata")
    kwargs: dict[str, Any] = {
        "source_id": str(payload.get("source_id") or "loaded-case"),
        "parser_id": str(payload.get("parser_id") or "unknown"),
        "timestamp": timestamp,
        "event_type": str(payload.get("event_type") or "unknown"),
        "path": _optional_string(payload.get("path")),
        "service": _optional_string(payload.get("service")),
        "session_id": _optional_string(payload.get("session_id")),
        "actor": _optional_string(payload.get("actor")),
        "tool_name": _optional_string(payload.get("tool_name")),
        "command": _optional_string(payload.get("command")),
        "result": _optional_string(payload.get("result")),
        "attribution": attribution,
        "attribution_score": float(payload.get("attribution_score") or 0.0),
        "attribution_reasons": tuple(
            str(reason) for reason in (payload.get("attribution_reasons") or ())
        ),
        "actor_class": actor_class,
        "raw_reference": _optional_string(payload.get("raw_reference")),
        "metadata": metadata if isinstance(metadata, dict) else {},
    }
    if payload.get("event_id"):
        kwargs["event_id"] = str(payload["event_id"])
    return NormalizedEvent(**kwargs)


def _load_artifacts(
    artifacts_root: Path,
    source_id: str,
    issues: list[str],
) -> tuple[ArtifactRecord, ...]:
    records: list[ArtifactRecord] = []
    seen: set[Path] = set()
    root_resolved = artifacts_root.resolve()
    for manifest in sorted(artifacts_root.glob("*/collection_manifest.jsonl")):
        with manifest.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        raise ValueError("expected a JSON object")
                    service = (
                        _optional_string(entry.get("service"))
                        or _service_name(manifest, root_resolved)
                    )
                    if _is_removed_chatgpt(service):
                        continue
                    path = _collected_path(root_resolved, entry.get("collected_path"))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    issues.append(f"{manifest.name}:line {line_number}: {exc}")
                    continue
                if not path.is_file():
                    issues.append(f"Missing collected artifact: {path}")
                    continue
                seen.add(path)
                records.append(
                    ArtifactRecord(
                        source_id=source_id,
                        producer_id="service_artifacts",
                        path=str(path),
                        artifact_type=str(entry.get("artifact_type") or _artifact_type(path)),
                        service=service,
                        sha256=_optional_string(entry.get("sha256")),
                        size=_optional_int(entry.get("size"), path.stat().st_size),
                        original_path=_optional_string(entry.get("original_path")),
                        metadata={
                            key: value
                            for key, value in entry.items()
                            if key not in {"collected_path", "artifact_type", "service", "sha256", "size", "original_path"}
                        },
                    )
                )

    for path in sorted(artifacts_root.rglob("*")):
        resolved = path.resolve()
        if not path.is_file() or path.name == "collection_manifest.jsonl" or resolved in seen:
            continue
        service = _service_name(path, root_resolved)
        if _is_removed_chatgpt(service):
            continue
        records.append(
            ArtifactRecord(
                source_id=source_id,
                producer_id="case_inventory",
                path=str(resolved),
                artifact_type=_artifact_type(path),
                service=service,
                size=path.stat().st_size,
                metadata={"loaded_from_case": True},
            )
        )
    return tuple(records)


def _collected_path(artifacts_root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("missing collected_path")
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else (artifacts_root / candidate).resolve()
    if not resolved.is_relative_to(artifacts_root):
        raise ValueError(f"collected_path escapes the case: {value}")
    return resolved


def _artifact_type(path: Path) -> str:
    return path.name.split("__", 1)[0] if "__" in path.name else path.name


def _service_name(path: Path, artifacts_root: Path) -> str:
    try:
        directory = path.relative_to(artifacts_root).parts[0]
    except (ValueError, IndexError):
        return "Unknown"
    return directory.replace("_", " ")


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _optional_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _is_removed_chatgpt(*values: str | None) -> bool:
    return any(
        value is not None
        and (
            value.strip().casefold() in _REMOVED_SERVICES
            or value.strip().casefold().startswith("chatgpt.")
            or value.strip().casefold().startswith("chatgpt_")
        )
        for value in values
    )


def _enum_value(enum_type, value: Any, fallback):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return fallback
