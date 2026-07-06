"""NTFS $UsnJrnl ($J) event vocabulary and record-to-event normalization.

The USN reason bitmask is *cumulative*: Windows keeps OR-ing new reason bits
into successive records for the same file until a record carries ``CLOSE``,
after which the mask restarts.  To reconstruct the event *flow* described in the
research paper (e.g. ``File_Created -> Data_Added -> Data_Overwritten ->
File_Closed``) we diff each record's cumulative mask against the previous record
of the same file and emit one event per newly-introduced reason.

This module is intentionally free of any ``dissect`` dependency so the mapping
and diffing logic can be unit-tested with lightweight record views.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from core.models import ActorClass, AgentAttribution, NormalizedEvent

# USN reason flag name (as defined by NTFS) -> friendly event name used by the
# paper's signature tables.
REASON_EVENT_NAMES: dict[str, str] = {
    "FILE_CREATE": "File_Created",
    "FILE_DELETE": "File_Deleted",
    "RENAME_OLD_NAME": "File_Renamed_Old",
    "RENAME_NEW_NAME": "File_Renamed_New",
    "DATA_TRUNCATION": "Data_Truncated",
    "DATA_EXTEND": "Data_Added",
    "DATA_OVERWRITE": "Data_Overwritten",
    "NAMED_DATA_TRUNCATION": "Data_Truncated",
    "NAMED_DATA_EXTEND": "Data_Added",
    "NAMED_DATA_OVERWRITE": "Data_Overwritten",
    "EA_CHANGE": "EA_Changed",
    "REPARSE_POINT_CHANGE": "Reparse_Point_Changed",
    "STREAM_CHANGE": "Stream_Changed",
    "OBJECT_ID_CHANGE": "Object_ID_Changed",
    "HARD_LINK_CHANGE": "Hard_Link_Changed",
    "INDEXABLE_CHANGE": "Indexable_Changed",
    "COMPRESSION_CHANGE": "Compression_Changed",
    "ENCRYPTION_CHANGE": "Encryption_Changed",
    "INTEGRITY_CHANGE": "Integrity_Changed",
    "BASIC_INFO_CHANGE": "Basic_Info_Changed",
    "SECURITY_CHANGE": "Access_Right_Changed",
    "TRANSACTED_CHANGE": "Transacted_Changed",
    "CLOSE": "File_Closed",
}

# Canonical order in which several reasons introduced by a single record are
# reported, matching the semantic ordering used by the paper's flows.
REASON_ORDER: tuple[str, ...] = (
    "FILE_CREATE",
    "RENAME_OLD_NAME",
    "RENAME_NEW_NAME",
    "FILE_DELETE",
    "DATA_TRUNCATION",
    "DATA_EXTEND",
    "DATA_OVERWRITE",
    "NAMED_DATA_TRUNCATION",
    "NAMED_DATA_EXTEND",
    "NAMED_DATA_OVERWRITE",
    "EA_CHANGE",
    "REPARSE_POINT_CHANGE",
    "STREAM_CHANGE",
    "OBJECT_ID_CHANGE",
    "HARD_LINK_CHANGE",
    "INDEXABLE_CHANGE",
    "COMPRESSION_CHANGE",
    "ENCRYPTION_CHANGE",
    "INTEGRITY_CHANGE",
    "BASIC_INFO_CHANGE",
    "SECURITY_CHANGE",
    "TRANSACTED_CHANGE",
    "CLOSE",
)

NTFS_PARSER_ID = "ntfs.usnjrnl"
NTFS_SERVICE = "NTFS"

# User document file types — what the $MFT/$LogFile recovery parsers surface, so
# investigators see their documents instead of OS/app temp-file churn.
USER_DOCUMENT_EXTENSIONS = (
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".hwp", ".hwpx", ".pdf", ".csv", ".rtf", ".md", ".odt", ".ods",
)


def is_user_document(name: str | None) -> bool:
    return bool(name) and name.lower().endswith(USER_DOCUMENT_EXTENSIONS)

# USN reason flag name -> bit value (NTFS ``USN_REASON``).  Kept here (rather than
# importing dissect) so record decoding stays dependency-free and testable.
REASON_BITS: dict[str, int] = {
    "DATA_OVERWRITE": 0x00000001,
    "DATA_EXTEND": 0x00000002,
    "DATA_TRUNCATION": 0x00000004,
    "NAMED_DATA_OVERWRITE": 0x00000010,
    "NAMED_DATA_EXTEND": 0x00000020,
    "NAMED_DATA_TRUNCATION": 0x00000040,
    "FILE_CREATE": 0x00000100,
    "FILE_DELETE": 0x00000200,
    "EA_CHANGE": 0x00000400,
    "SECURITY_CHANGE": 0x00000800,
    "RENAME_OLD_NAME": 0x00001000,
    "RENAME_NEW_NAME": 0x00002000,
    "INDEXABLE_CHANGE": 0x00004000,
    "BASIC_INFO_CHANGE": 0x00008000,
    "HARD_LINK_CHANGE": 0x00010000,
    "COMPRESSION_CHANGE": 0x00020000,
    "ENCRYPTION_CHANGE": 0x00040000,
    "OBJECT_ID_CHANGE": 0x00080000,
    "REPARSE_POINT_CHANGE": 0x00100000,
    "STREAM_CHANGE": 0x00200000,
    "TRANSACTED_CHANGE": 0x00400000,
    "INTEGRITY_CHANGE": 0x00800000,
    "CLOSE": 0x80000000,
}


def decompose_reason(mask: int) -> tuple[str, ...]:
    """Split a cumulative USN reason bitmask into its flag names (canonical order)."""
    present = {name for name, bit in REASON_BITS.items() if mask & bit}
    return _ordered(present)


@dataclass(frozen=True, slots=True)
class UsnRecordView:
    """A ``dissect``-independent view of a single ``$UsnJrnl`` record."""

    usn: int
    timestamp: datetime
    file_reference: int
    parent_reference: int
    filename: str | None
    full_path: str | None
    reason_flags: tuple[str, ...]  # cumulative reason flag names in this record
    source_info: tuple[str, ...] = ()
    file_attributes: int = 0


@dataclass(slots=True)
class _ReasonState:
    cumulative: frozenset[str] = field(default_factory=frozenset)


def _ordered(reasons: set[str]) -> tuple[str, ...]:
    known = tuple(name for name in REASON_ORDER if name in reasons)
    extra = tuple(sorted(reasons.difference(REASON_ORDER)))
    return known + extra


def reason_event_name(flag: str) -> str:
    return REASON_EVENT_NAMES.get(flag, flag.title().replace("_", "_"))


def event_type_for(primary_flag: str) -> str:
    return "ntfs_" + reason_event_name(primary_flag).lower()


def new_reasons_for_record(
    view: UsnRecordView, state: dict[int, _ReasonState]
) -> tuple[str, ...]:
    """Return the reasons newly introduced by ``view`` versus its file's history."""
    current = frozenset(view.reason_flags)
    entry = state.get(view.file_reference)
    previous = entry.cumulative if entry is not None else frozenset()
    new = set(current) - set(previous)
    if "CLOSE" in current:
        # A CLOSE terminates the accumulation window; the next change restarts.
        state[view.file_reference] = _ReasonState(frozenset())
    else:
        state[view.file_reference] = _ReasonState(current)
    return _ordered(new)


def usn_records_to_events(
    records: list[UsnRecordView] | tuple[UsnRecordView, ...],
    *,
    source_id: str,
    parser_id: str = NTFS_PARSER_ID,
    service: str | None = NTFS_SERVICE,
) -> tuple[NormalizedEvent, ...]:
    """Convert ordered USN record views into normalized NTFS events.

    Records must be supplied in ascending USN order.  One event is emitted per
    record, carrying the *newly introduced* reasons (paper vocabulary) in
    ``metadata['ntfs_reasons']`` and the record's primary reason as event type.
    Actor attribution is deliberately left at ``UNKNOWN`` / ``NONE`` here; it is
    assigned later by :mod:`analysis.ntfs.attribution`.
    """
    state: dict[int, _ReasonState] = {}
    events: list[NormalizedEvent] = []
    for view in records:
        new_flags = new_reasons_for_record(view, state)
        if not new_flags:
            continue
        reasons = [reason_event_name(flag) for flag in new_flags]
        primary = new_flags[0]
        events.append(
            NormalizedEvent(
                source_id=source_id,
                parser_id=parser_id,
                timestamp=view.timestamp,
                event_type=event_type_for(primary),
                path=view.full_path,
                service=service,
                actor=None,
                attribution=AgentAttribution.NONE,
                attribution_score=0.0,
                actor_class=ActorClass.UNKNOWN,
                raw_reference=f"usn={view.usn}",
                metadata={
                    "usn": view.usn,
                    "file_reference": view.file_reference,
                    "parent_reference": view.parent_reference,
                    "filename": view.filename,
                    "full_path": view.full_path,
                    "ntfs_reasons": reasons,
                    "ntfs_reason_flags": list(new_flags),
                    "ntfs_reasons_cumulative": [
                        reason_event_name(flag) for flag in _ordered(set(view.reason_flags))
                    ],
                    "source_info": list(view.source_info),
                    "file_attributes": view.file_attributes,
                },
            )
        )
    return tuple(events)
