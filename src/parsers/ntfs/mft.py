"""Parser for an extracted NTFS master file table (``$MFT``).

The parser walks valid MFT records with :mod:`dissect.ntfs` instead of carving
the complete file as an unstructured byte stream.  This preserves record
identity and allocation state while keeping memory use bounded for large MFTs.
Only user-document records are emitted; system and application-storage paths
are intentionally excluded from TraceAgent's focused NTFS analysis.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO

from analysis.ntfs.events import NTFS_SERVICE, is_user_document
from core.models import (
    ActorClass,
    AgentAttribution,
    ArtifactRecord,
    EvidenceSource,
    NormalizedEvent,
)
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp
from version import __version__

_MFT_PARSER_ID = "ntfs.mft"
_MFT_GLOBS = ("**/ntfs_mft__*.bin", "**/$MFT")
_FILE_RECORD_SEGMENT_IN_USE = 0x0001
_FILE_NAME_DOS = 0x02
_MAX_RECORDED_ERRORS = 100

# Volume locations that are system/application storage rather than user files.
_BACKGROUND = (
    "/windows/",
    "/programdata/",
    "/program files",
    "/$recycle.bin/",
    "/system volume information/",
    "/appdata/",
    "/$extend/",
)

MftFactory = Callable[[BinaryIO], Any]


@dataclass(frozen=True, slots=True)
class MftRecordView:
    """A library-independent view of one MFT file-name record."""

    filename: str
    full_path: str | None
    parent_reference: int | None
    segment: int
    sequence_number: int | None
    offset: int | None
    link_index: int
    record_flags: int
    allocated: bool
    is_dir: bool
    size: int | None
    resident: bool | None
    fn_created: datetime | None
    fn_modified: datetime | None
    fn_mft_changed: datetime | None
    fn_accessed: datetime | None
    si_created: datetime | None
    si_modified: datetime | None
    si_mft_changed: datetime | None
    si_accessed: datetime | None


class NtfsMftParser(ArtifactParser):
    def __init__(self, mft_factory: MftFactory | None = None) -> None:
        self._mft_factory = mft_factory or _default_mft_factory

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id=_MFT_PARSER_ID,
            name="NTFS $MFT",
            category="ntfs",
            version=__version__,
            services=("NTFS $MFT",),
            description=(
                "Parses allocated and deleted user-document records and their NTFS timestamps."
            ),
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        return 0.9 if any(self._tables(source.location)) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        for index, table in enumerate(self._tables(source.location), start=1):
            yield ArtifactRecord(
                source_id=source.source_id,
                producer_id=self.metadata.parser_id,
                path=str(table),
                artifact_type="ntfs_mft",
                service=NTFS_SERVICE,
                size=table.stat().st_size,
                metadata={"volume": table.parent.name},
            )
            context.progress(index, f"Discovered {table.name}")

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = tuple(artifacts)
        errors: list[dict[str, object]] = []
        for index, artifact in enumerate(artifact_list, start=1):
            if context.cancelled():
                break
            table = Path(artifact.path)
            fallback = file_timestamp(table)
            record_error_count = 0

            def record_error(segment: int | None, exc: Exception) -> None:
                nonlocal record_error_count
                record_error_count += 1
                if len(errors) < _MAX_RECORDED_ERRORS:
                    errors.append(
                        {"path": str(table), "segment": segment, "error": str(exc)}
                    )

            def artifact_progress(file_percent: int) -> None:
                overall = ((index - 1) + file_percent / 100) / max(
                    len(artifact_list), 1
                )
                context.progress(round(overall * 100), f"Parsing {table.name}")

            try:
                for view in _read_mft_records(
                    table,
                    mft_factory=self._mft_factory,
                    cancelled=context.cancelled,
                    on_error=record_error,
                    progress=artifact_progress,
                ):
                    emit(_mft_event(source, self.metadata.parser_id, view, fallback))
            except Exception as exc:  # noqa: BLE001
                errors.append({"path": str(table), "segment": None, "error": str(exc)})

            if record_error_count:
                context.options.setdefault("ntfs_mft_record_error_count", 0)
                context.options["ntfs_mft_record_error_count"] += record_error_count
            context.progress(
                round(index / max(len(artifact_list), 1) * 100), f"Parsed {table.name}"
            )
        if errors:
            context.options.setdefault("ntfs_mft_errors", []).extend(errors)

    @staticmethod
    def _tables(location: Path) -> Iterable[Path]:
        try:
            tables = sorted({path for pattern in _MFT_GLOBS for path in location.glob(pattern)})
        except OSError:
            return
        for table in tables:
            if table.is_file():
                yield table


def _mft_event(
    source: EvidenceSource,
    parser_id: str,
    view: MftRecordView,
    fallback: datetime,
) -> NormalizedEvent:
    timestamp = (
        view.si_modified
        or view.fn_modified
        or view.si_created
        or view.fn_created
        or fallback
    )
    object_type = "directory" if view.is_dir else "file"
    event_type = (
        f"ntfs_mft_{object_type}"
        if view.allocated
        else f"ntfs_mft_deleted_{object_type}"
    )
    return NormalizedEvent(
        source_id=source.source_id,
        parser_id=parser_id,
        timestamp=timestamp,
        event_type=event_type,
        path=view.full_path or view.filename,
        service=NTFS_SERVICE,
        attribution=AgentAttribution.NONE,
        actor_class=ActorClass.UNKNOWN,
        raw_reference=(
            f"mft_segment={view.segment}:sequence={view.sequence_number}:"
            f"filename_index={view.link_index}"
        ),
        metadata={
            "filename": view.filename,
            "full_path": view.full_path,
            "is_dir": view.is_dir,
            "allocated": view.allocated,
            "deleted": not view.allocated,
            "mft_segment": view.segment,
            "mft_sequence_number": view.sequence_number,
            "mft_offset": view.offset,
            "mft_record_flags": view.record_flags,
            "filename_index": view.link_index,
            "parent_reference": view.parent_reference,
            "size": view.size,
            "resident": view.resident,
            "fn_created": _iso(view.fn_created),
            "fn_modified": _iso(view.fn_modified),
            "fn_mft_changed": _iso(view.fn_mft_changed),
            "fn_accessed": _iso(view.fn_accessed),
            "si_created": _iso(view.si_created),
            "si_modified": _iso(view.si_modified),
            "si_mft_changed": _iso(view.si_mft_changed),
            "si_accessed": _iso(view.si_accessed),
        },
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _default_mft_factory(stream: BinaryIO):
    """Build an MFT reader whose records retain parent-path resolution."""
    from dissect.ntfs.ntfs import NTFS

    return NTFS(mft=stream).mft


def _read_mft_records(
    table: Path,
    *,
    mft_factory: MftFactory = _default_mft_factory,
    cancelled: Callable[[], bool] = lambda: False,
    on_error: Callable[[int | None, Exception], None] | None = None,
    progress: Callable[[int], None] = lambda _percent: None,
) -> Iterator[MftRecordView]:
    """Stream document records from ``table`` without loading the MFT into RAM."""
    with table.open("rb") as stream:
        mft = mft_factory(stream)
        table_size = table.stat().st_size
        last_percent = -1
        for record in mft.segments():
            if cancelled():
                return
            segment = _as_int(_safe_attr(record, "segment"), -1)
            offset = _optional_int(_safe_attr(record, "offset"))
            if offset is not None and table_size:
                file_percent = min(99, int(offset / table_size * 100))
                if file_percent > last_percent:
                    progress(file_percent)
                    last_percent = file_percent
            try:
                yield from _record_views(record)
            except Exception as exc:  # noqa: BLE001
                if on_error is not None:
                    on_error(segment, exc)


def _record_views(record: Any) -> Iterator[MftRecordView]:
    header = _safe_attr(record, "header")
    flags = _as_int(_safe_attr(header, "Flags"), 0)
    segment = _as_int(_safe_attr(record, "segment"), -1)
    sequence = _optional_int(_safe_attr(header, "SequenceNumber"))
    offset = _optional_int(_safe_attr(record, "offset"))
    allocated = bool(flags & _FILE_RECORD_SEGMENT_IN_USE)
    is_dir = bool(_safe_call(record, "is_dir", False))
    # Attribute parsing failures are record-level errors and must be reported;
    # silently treating them as an empty record hides damaged MFT segments.
    attributes = record.attributes
    if attributes is None:
        raise ValueError(f"MFT segment {segment} has no parsed attributes")

    standard = _first(_attribute_list(attributes, "STANDARD_INFORMATION"))
    size = None if is_dir else _optional_int(_safe_call(record, "size", None))
    resident = None if is_dir else _default_data_resident(attributes)

    for link_index, file_name in enumerate(_attribute_list(attributes, "FILE_NAME")):
        if _as_int(_safe_attr(file_name, "flags"), -1) == _FILE_NAME_DOS:
            continue
        filename = _safe_attr(file_name, "file_name")
        if not isinstance(filename, str) or not filename or not is_user_document(filename):
            continue
        full_path = _safe_call(file_name, "full_path", None)
        if not isinstance(full_path, str) or not full_path:
            full_path = None
        if full_path is not None and _is_background_path(full_path):
            continue

        yield MftRecordView(
            filename=filename,
            full_path=full_path,
            parent_reference=_parent_reference(file_name),
            segment=segment,
            sequence_number=sequence,
            offset=offset,
            link_index=link_index,
            record_flags=flags,
            allocated=allocated,
            is_dir=is_dir,
            size=size,
            resident=resident,
            fn_created=_datetime_attr(file_name, "creation_time"),
            fn_modified=_datetime_attr(file_name, "last_modification_time"),
            fn_mft_changed=_datetime_attr(file_name, "last_change_time"),
            fn_accessed=_datetime_attr(file_name, "last_access_time"),
            si_created=_datetime_attr(standard, "creation_time"),
            si_modified=_datetime_attr(standard, "last_modification_time"),
            si_mft_changed=_datetime_attr(standard, "last_change_time"),
            si_accessed=_datetime_attr(standard, "last_access_time"),
        )


def _attribute_list(attributes: Any, name: str) -> list[Any]:
    try:
        value = getattr(attributes, name)
    except AttributeError:
        return []
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return [value]


def _default_data_resident(attributes: Any) -> bool | None:
    for data_attribute in _attribute_list(attributes, "DATA"):
        if _safe_attr(data_attribute, "name", "") == "":
            value = _safe_attr(data_attribute, "resident")
            return value if isinstance(value, bool) else None
    return None


def _parent_reference(file_name: Any) -> int | None:
    reference = _safe_attr(file_name, "ParentDirectory")
    if reference is None:
        reference = _safe_attr(_safe_attr(file_name, "attribute"), "ParentDirectory")
    if reference is None:
        return None
    try:
        from dissect.ntfs.util import segment_reference

        return int(segment_reference(reference))
    except Exception:  # noqa: BLE001
        return _optional_int(reference)


def _is_background_path(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/").strip("/").lower() + "/"
    return any(marker in normalized for marker in _BACKGROUND)


def _datetime_attr(value: Any, name: str) -> datetime | None:
    result = _safe_attr(value, name)
    return result if isinstance(result, datetime) else None


def _first(values: list[Any]) -> Any | None:
    return values[0] if values else None


def _safe_attr(value: Any, name: str, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return getattr(value, name)
    except Exception:  # noqa: BLE001
        return default


def _safe_call(value: Any, name: str, default: Any) -> Any:
    method = _safe_attr(value, name)
    if not callable(method):
        return default
    try:
        return method()
    except Exception:  # noqa: BLE001
        return default


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _as_int(value: Any, default: int) -> int:
    converted = _optional_int(value)
    return default if converted is None else converted
