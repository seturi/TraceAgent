"""Two-layer human/AI-agent attribution for NTFS file-system operations.

Layer 1 (primary): reconstruct USN records into per-file operation *flows* and
match them against the paper's event-flow signatures (:mod:`analysis.ntfs.signatures`).

Layer 2 (confirmation, survives session deletion): cross-analyse the operations
against the agent session-log events already produced by the service parsers.
A path/time (or command-string) correlation both confirms the actor and pins the
exact service, upgrading confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

from analysis.attribution import score_attribution
from analysis.ntfs.events import NTFS_PARSER_ID
from analysis.ntfs.signatures import (
    ActorSignal,
    FileOperation,
    basename_of,
    evaluate,
    normalize_path,
)
from core.models import ActorClass, AgentAttribution, NormalizedEvent

_TERMINATORS = {"File_Closed", "File_Deleted"}
DEFAULT_WINDOW_SECONDS = 5.0
_TIGHT_WINDOW_SECONDS = 2.0

_AI_SERVICES = {
    "Claude Cowork",
    "Claude Code",
    "ChatGPT Desktop",
    "ChatGPT",
    "Antigravity",
    "Codex",
}


@dataclass(frozen=True, slots=True)
class AgentActivity:
    service: str
    session_id: str | None
    tool_name: str | None
    timestamp: datetime
    normalized_path: str | None
    basename: str | None
    command: str | None
    event_id: str


@dataclass(frozen=True, slots=True)
class OperationVerdict:
    operation_id: str
    behavior: str
    actor_class: ActorClass
    service: str | None
    confidence: float
    attribution: AgentAttribution
    reasons: tuple[str, ...]
    target_path: str | None
    start: datetime
    end: datetime
    event_ids: tuple[str, ...]
    matched_event_id: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttributionOutcome:
    events: tuple[NormalizedEvent, ...]
    verdicts: tuple[OperationVerdict, ...]


# --------------------------------------------------------------------------- #
# Layer 1: reconstruct operations from NTFS events
# --------------------------------------------------------------------------- #
def _segment_key(event: NormalizedEvent) -> int:
    ref = event.metadata.get("file_reference")
    return int(ref) if isinstance(ref, int) else -1


def reconstruct_operations(
    ntfs_events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
    *,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> list[FileOperation]:
    """Group NTFS events into logical file operations.

    First split each file's event stream at terminating reasons, then merge
    operations that resolve to the same target path within ``window_seconds``
    (this reunites the tmp-file / delete-original / rename composite that AI
    agents produce when they "edit" a text file).
    """
    by_file: dict[int, list[NormalizedEvent]] = {}
    for event in sorted(ntfs_events, key=lambda e: (_segment_key(e), _usn(e))):
        by_file.setdefault(_segment_key(event), []).append(event)

    raw_ops: list[FileOperation] = []
    for events in by_file.values():
        segment: list[NormalizedEvent] = []
        for event in events:
            segment.append(event)
            reasons = _reasons(event)
            if reasons & _TERMINATORS:
                raw_ops.append(_build_operation(segment))
                segment = []
        if segment:
            raw_ops.append(_build_operation(segment))

    return _merge_by_target(raw_ops, window_seconds)


def _usn(event: NormalizedEvent) -> int:
    usn = event.metadata.get("usn")
    return int(usn) if isinstance(usn, int) else 0


def _reasons(event: NormalizedEvent) -> set[str]:
    value = event.metadata.get("ntfs_reasons")
    return set(value) if isinstance(value, list) else set()


def _build_operation(events: list[NormalizedEvent]) -> FileOperation:
    ordered = sorted(events, key=_usn)
    reason_flow: list[str] = []
    filenames: list[str] = []
    paths: list[str] = []
    refs: list[int] = []
    for event in ordered:
        reason_flow.extend(str(r) for r in event.metadata.get("ntfs_reasons", []))
        name = event.metadata.get("filename")
        if isinstance(name, str) and name and name not in filenames:
            filenames.append(name)
        norm = normalize_path(event.path)
        if norm and norm not in paths:
            paths.append(norm)
        ref = event.metadata.get("file_reference")
        if isinstance(ref, int) and ref not in refs:
            refs.append(ref)

    target = _pick_target(ordered)
    normalized = normalize_path(target)
    return FileOperation(
        target_path=target,
        normalized_path=normalized,
        basename=basename_of(target),
        filenames=tuple(filenames),
        reason_flow=tuple(reason_flow),
        paths=tuple(paths),
        start=min(e.timestamp for e in ordered),
        end=max(e.timestamp for e in ordered),
        file_references=tuple(refs),
        event_ids=tuple(e.event_id for e in ordered),
    )


def _pick_target(events: list[NormalizedEvent]) -> str | None:
    """Prefer the last non-temporary path touched by the operation."""
    last_path: str | None = None
    non_tmp: str | None = None
    for event in events:
        full = event.metadata.get("full_path")
        if not isinstance(full, str) or not full:
            continue
        last_path = full
        if not full.lower().endswith((".tmp", ".pbtxt")):
            non_tmp = full
    return non_tmp or last_path


def _merge_by_target(
    ops: list[FileOperation], window_seconds: float
) -> list[FileOperation]:
    """Merge ops resolving to the same target path within the time window.

    Ops are processed in start-time order and only merged with the most recent
    op for the same path, giving O(n) behaviour on large journals.
    """
    ordered = sorted(ops, key=lambda o: o.start)
    merged: list[FileOperation] = []
    last_index_by_path: dict[str, int] = {}
    for op in ordered:
        target = op.normalized_path
        if target is not None:
            prev = last_index_by_path.get(target)
            if prev is not None and _within(merged[prev], op, window_seconds):
                merged[prev] = _combine(merged[prev], op)
                continue
        merged.append(op)
        if target is not None:
            last_index_by_path[target] = len(merged) - 1
    return merged


def _within(a: FileOperation, b: FileOperation, window_seconds: float) -> bool:
    latest_start = max(a.start, b.start)
    earliest_end = min(a.end, b.end)
    gap = (latest_start - earliest_end).total_seconds()
    return gap <= window_seconds


def _combine(a: FileOperation, b: FileOperation) -> FileOperation:
    def _dedup(*seqs: tuple[str, ...]) -> tuple[str, ...]:
        seen: list[str] = []
        for seq in seqs:
            for item in seq:
                if item not in seen:
                    seen.append(item)
        return tuple(seen)

    ordered = sorted((a, b), key=lambda o: o.start)
    target = a.target_path or b.target_path
    return FileOperation(
        target_path=target,
        normalized_path=normalize_path(target),
        basename=basename_of(target),
        filenames=_dedup(a.filenames, b.filenames),
        reason_flow=tuple(item for op in ordered for item in op.reason_flow),
        paths=_dedup(a.paths, b.paths),
        start=min(a.start, b.start),
        end=max(a.end, b.end),
        file_references=tuple(dict.fromkeys(a.file_references + b.file_references)),
        event_ids=tuple(dict.fromkeys(a.event_ids + b.event_ids)),
    )


# --------------------------------------------------------------------------- #
# Layer 2: agent session-log index and correlation
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class AgentIndex:
    by_path: dict[str, list[AgentActivity]] = field(default_factory=dict)
    by_name: dict[str, list[AgentActivity]] = field(default_factory=dict)
    with_command: list[AgentActivity] = field(default_factory=list)


def build_agent_index(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...]
) -> AgentIndex:
    index = AgentIndex()
    for event in events:
        if event.parser_id == NTFS_PARSER_ID:
            continue
        if event.service not in _AI_SERVICES:
            continue
        if not (event.path or event.command):
            continue
        activity = AgentActivity(
            service=event.service or "AI agent",
            session_id=event.session_id,
            tool_name=event.tool_name,
            timestamp=event.timestamp,
            normalized_path=normalize_path(event.path),
            basename=basename_of(event.path),
            command=(event.command or "").lower() or None,
            event_id=event.event_id,
        )
        if activity.normalized_path:
            index.by_path.setdefault(activity.normalized_path, []).append(activity)
        if activity.basename:
            index.by_name.setdefault(activity.basename, []).append(activity)
        if activity.command:
            index.with_command.append(activity)
    return index


def _candidate_activities(op: FileOperation, index: AgentIndex) -> list[AgentActivity]:
    seen: set[str] = set()
    candidates: list[AgentActivity] = []
    for activity in (
        tuple(index.by_path.get(op.normalized_path or "", ()))
        + tuple(index.by_name.get(op.basename or "", ()))
    ):
        if activity.event_id not in seen:
            seen.add(activity.event_id)
            candidates.append(activity)
    if op.basename:
        for activity in index.with_command:
            if activity.event_id in seen:
                continue
            if activity.command and op.basename in activity.command:
                candidates.append(activity)
    return candidates


def _best_match(
    op: FileOperation, index: AgentIndex, window_seconds: float
) -> tuple[AgentActivity, float, str] | None:
    best: tuple[AgentActivity, float, str] | None = None
    for activity in _candidate_activities(op, index):
        dt = abs((op_center(op) - activity.timestamp).total_seconds())
        if dt > window_seconds:
            continue
        kind: str | None = None
        if op.normalized_path and activity.normalized_path == op.normalized_path:
            kind = "path"
        elif op.basename and activity.basename == op.basename:
            kind = "basename"
        elif op.basename and activity.command and op.basename in activity.command:
            kind = "command"
        if kind is None:
            continue
        if kind == "path" and dt <= _TIGHT_WINDOW_SECONDS:
            score = 0.95
        elif kind == "path":
            score = 0.85
        elif kind == "basename":
            score = 0.8
        else:
            score = 0.75
        if best is None or score > best[1]:
            best = (activity, score, kind)
    return best


def op_center(op: FileOperation) -> datetime:
    return op.start + (op.end - op.start) / 2


# --------------------------------------------------------------------------- #
# Combine layers into a verdict
# --------------------------------------------------------------------------- #
def _verdict_for(
    op: FileOperation,
    signal: ActorSignal,
    match: tuple[AgentActivity, float, str] | None,
) -> OperationVerdict:
    operation_id = op.event_ids[0] if op.event_ids else "op"
    if match is not None:
        activity, score, kind = match
        conflict = activity.service in signal.forbidden_services
        reasons = signal.reasons + (
            f"session_log_{kind}_match:{activity.service}",
            f"tool:{activity.tool_name}" if activity.tool_name else "tool:unknown",
        )
        if conflict:
            reasons = reasons + ("signature_service_conflict",)
        result = score_attribution(score, reasons)
        return OperationVerdict(
            operation_id=operation_id,
            behavior=signal.behavior,
            actor_class=ActorClass.AI_AGENT,
            service=activity.service,
            confidence=score,
            attribution=result.level,
            reasons=result.reasons,
            target_path=op.target_path,
            start=op.start,
            end=op.end,
            event_ids=op.event_ids,
            matched_event_id=activity.event_id,
            metadata={"session_id": activity.session_id, "match_kind": kind},
        )

    # No cross-analysis hit: fall back to the signature layer.
    service = signal.service_hints[0] if len(signal.service_hints) == 1 else None
    if signal.actor_class == ActorClass.AI_AGENT:
        attribution = score_attribution(signal.confidence, signal.reasons).level
    else:
        attribution = AgentAttribution.NONE
    return OperationVerdict(
        operation_id=operation_id,
        behavior=signal.behavior,
        actor_class=signal.actor_class,
        service=service,
        confidence=signal.confidence,
        attribution=attribution,
        reasons=signal.reasons,
        target_path=op.target_path,
        start=op.start,
        end=op.end,
        event_ids=op.event_ids,
        metadata={"service_hints": list(signal.service_hints)},
    )


def attribute_ntfs_events(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
    *,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> AttributionOutcome:
    """Attribute every NTFS operation and return updated events plus verdicts."""
    events = tuple(events)
    ntfs_events = [e for e in events if e.parser_id == NTFS_PARSER_ID]
    operations = reconstruct_operations(ntfs_events, window_seconds=window_seconds)
    index = build_agent_index(events)

    verdicts: list[OperationVerdict] = []
    verdict_by_event: dict[str, OperationVerdict] = {}
    for op in operations:
        signal = evaluate(op)
        match = _best_match(op, index, window_seconds)
        verdict = _verdict_for(op, signal, match)
        verdicts.append(verdict)
        for event_id in op.event_ids:
            verdict_by_event[event_id] = verdict

    updated: list[NormalizedEvent] = []
    for event in events:
        verdict = verdict_by_event.get(event.event_id)
        if verdict is None:
            updated.append(event)
            continue
        metadata = {
            **event.metadata,
            "actor_class": verdict.actor_class.value,
            "actor_service": verdict.service,
            "actor_confidence": round(verdict.confidence, 3),
            "behavior": verdict.behavior,
            "operation_id": verdict.operation_id,
        }
        if verdict.matched_event_id:
            metadata["matched_event_id"] = verdict.matched_event_id
        updated.append(
            replace(
                event,
                actor_class=verdict.actor_class,
                attribution=verdict.attribution,
                attribution_score=(
                    verdict.confidence if verdict.actor_class == ActorClass.AI_AGENT else 0.0
                ),
                attribution_reasons=verdict.reasons,
                service=verdict.service or event.service,
                metadata=metadata,
            )
        )
    return AttributionOutcome(tuple(updated), tuple(verdicts))
