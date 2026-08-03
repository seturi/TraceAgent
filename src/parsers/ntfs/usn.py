"""Parser for the collected NTFS USN journal ($UsnJrnl:$J).

Reads the ``$MFT`` + ``$J`` copies produced by
:class:`collection.ntfs.collector.NtfsArtifactCollector`, reconstructs the USN
records with :mod:`dissect.ntfs`, and normalizes them into the paper's event
vocabulary via :mod:`analysis.ntfs.events`.  Actor attribution (human vs AI) is
performed later by :mod:`analysis.ntfs.attribution` once agent session-log events
are available for cross-analysis.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from analysis.ntfs.events import (
    NTFS_PARSER_ID,
    NTFS_SERVICE,
    UsnRecordView,
    decompose_reason,
    usn_records_to_events,
)
from core.models import ArtifactRecord, EvidenceSource
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp
from version import __version__

_USN_GLOBS = ("**/ntfs_usnjrnl__*.bin", "**/$J")
# $J is written in 4 KiB pages and a USN record never spans a page boundary, so
# a page boundary is the safe place to resync after damaged data.
_USN_PAGE = 0x1000


class NtfsUsnParser(ArtifactParser):
    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id=NTFS_PARSER_ID,
            name="NTFS $UsnJrnl",
            category="ntfs",
            version=__version__,
            services=("NTFS $UsnJrnl",),
            description="Reconstructs $UsnJrnl:$J change events and file operation flows.",
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        return 0.9 if any(self._journals(source.location)) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        for index, (journal, mft) in enumerate(self._journals(source.location), start=1):
            yield ArtifactRecord(
                source_id=source.source_id,
                producer_id=self.metadata.parser_id,
                path=str(journal),
                artifact_type="ntfs_usnjrnl",
                service=NTFS_SERVICE,
                size=journal.stat().st_size,
                metadata={"mft_path": str(mft) if mft else None, "volume": journal.parent.name},
            )
            context.progress(index, f"Discovered {journal.name}")

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = tuple(artifacts)
        errors: list[dict[str, str]] = []
        for index, artifact in enumerate(artifact_list, start=1):
            if context.cancelled():
                break
            journal = Path(artifact.path)
            mft_path = artifact.metadata.get("mft_path")
            mft = Path(mft_path) if isinstance(mft_path, str) and mft_path else None
            try:
                views, damaged = _read_usn_records(journal, mft)
                if damaged:
                    # Surfaced as a parser warning rather than silently dropped:
                    # a wrapped or over-extracted $J routinely contains torn
                    # regions, and the investigator should know how much of the
                    # journal could not be read.
                    errors.append(
                        {
                            "path": str(journal),
                            "error": f"{damaged} damaged page(s) skipped while reading $J",
                        }
                    )
                events = usn_records_to_events(views, source_id=source.source_id)
                for event in events:
                    if context.cancelled():
                        break
                    emit(event)
            except Exception as exc:  # noqa: BLE001
                errors.append({"path": str(journal), "error": str(exc)})
            context.progress(
                round(index / max(len(artifact_list), 1) * 100), f"Parsed {journal.name}"
            )
        if errors:
            context.options.setdefault("ntfs_usn_errors", []).extend(errors)

    @staticmethod
    def _journals(location: Path) -> Iterable[tuple[Path, Path | None]]:
        try:
            journals = sorted(
                {path for pattern in _USN_GLOBS for path in location.glob(pattern)}
            )
        except OSError:
            return
        for journal in journals:
            if not journal.is_file():
                continue
            mft = _sibling_mft(journal)
            yield journal, mft


def _sibling_mft(journal: Path) -> Path | None:
    for pattern in ("ntfs_mft__*.bin", "$MFT"):
        for candidate in journal.parent.glob(pattern):
            if candidate.is_file():
                return candidate
    return None


def _read_usn_records(journal: Path, mft: Path | None) -> tuple[list[UsnRecordView], int]:
    """Read every recoverable record from ``$J``; also report damaged pages."""
    from dissect.ntfs.ntfs import NTFS

    mft_stream = mft.open("rb") if mft is not None else None
    journal_stream = journal.open("rb")
    try:
        ntfs = NTFS(mft=mft_stream, usnjrnl=journal_stream)
        resolve_parent = _parent_path_resolver(ntfs)
        views: list[UsnRecordView] = []
        fallback = file_timestamp(journal)
        damaged = 0
        for record, bad_pages in _iter_usn_records(ntfs.usnjrnl, journal.stat().st_size):
            damaged += bad_pages
            if record is not None:
                views.append(_to_view(record, fallback, resolve_parent))
        views.sort(key=lambda view: view.usn)
        return views, damaged
    finally:
        journal_stream.close()
        if mft_stream is not None:
            mft_stream.close()


def _iter_usn_records(usnjrnl, size: int):
    """Walk ``$J`` page by page, tolerating torn and non-USN regions.

    ``dissect``'s own ``UsnJrnl.records()`` guards only ``EOFError``: the first
    record with an unrecognised version raises ``ValueError`` out of the
    generator, which then cannot be resumed — so a single damaged record
    discards the *entire* journal (observed on real evidence: 345k valid records
    lost to one bad offset where the extraction ran past the end of the $J
    stream).  A wrapped journal, or one extracted with slack attached, routinely
    contains such regions, so walk the pages ourselves and resync on the next
    page boundary instead of giving up.

    Yields ``(record_or_None, damaged_pages)`` so the caller can both collect
    records and count what had to be skipped.
    """
    from dissect.ntfs.usnjrnl import UsnRecord

    fh = usnjrnl.fh
    offset = 0
    while offset < size:
        fh.seek(offset)
        head = fh.read(4)
        if len(head) < 4:
            break
        if head == b"\x00\x00\x00\x00":
            offset += _USN_PAGE - (offset % _USN_PAGE)  # sparse/unused page
            continue
        try:
            record = UsnRecord(usnjrnl, fh, offset)
            length = int(record.record.RecordLength)
        except Exception:  # noqa: BLE001 - torn or non-USN data
            offset += _USN_PAGE - (offset % _USN_PAGE)
            yield None, 1
            continue
        # A record lives wholly inside its page; anything else is garbage length.
        if not 0 < length <= _USN_PAGE - (offset % _USN_PAGE) or offset + length > size:
            offset += _USN_PAGE - (offset % _USN_PAGE)
            yield None, 1
            continue
        if record.header.MajorVersion == 2:
            yield record, 0
        offset += length
        if offset % 8:
            offset += -offset & 7


def _parent_path_resolver(ntfs):
    """Return a cached parent-reference -> directory-path resolver.

    ``UsnRecord.full_path`` walks the parent chain through the $MFT for *every*
    record; with hundreds of thousands of records sharing a few thousand parent
    directories that is the dominant cost of parsing a real journal.  Caching by
    (segment, sequence) keeps the sequence-number check that detects a parent
    slot which has since been reused — such a reference resolves to ``None``
    (unresolved) rather than to a wrong, confidently-stated folder.
    """
    cache: dict[tuple[int, int], str | None] = {}

    def resolve(reference) -> str | None:
        from dissect.ntfs.util import segment_reference

        if reference is None:
            return None
        try:
            key = (int(segment_reference(reference)), int(reference.SequenceNumber))
        except Exception:  # noqa: BLE001
            return None
        if key in cache:
            return cache[key]
        segment, sequence = key
        try:
            record = ntfs.mft(segment)
            path = record.full_path() if record.header.SequenceNumber == sequence else None
        except Exception:  # noqa: BLE001
            path = None
        cache[key] = path
        return path

    return resolve


def _to_view(record, fallback, resolve_parent) -> UsnRecordView:
    from dissect.ntfs.util import segment_reference

    try:
        timestamp = record.timestamp
    except Exception:  # noqa: BLE001
        timestamp = fallback
    filename = getattr(record, "filename", None)
    parent_path = resolve_parent(_safe_attr(record, "ParentFileReferenceNumber", None))
    # The volume root resolves to an empty path, so test for None (unresolved)
    # rather than falsiness — otherwise every root-level file loses its path.
    full_path = f"{parent_path}\\{filename}" if parent_path is not None and filename else None
    return UsnRecordView(
        usn=int(_safe_attr(record, "Usn", 0)),
        timestamp=timestamp or fallback,
        file_reference=_reference(record, "FileReferenceNumber", segment_reference),
        parent_reference=_reference(record, "ParentFileReferenceNumber", segment_reference),
        filename=filename,
        full_path=full_path,
        reason_flags=decompose_reason(int(_safe_attr(record, "Reason", 0))),
        source_info=(),
        file_attributes=int(_safe_attr(record, "FileAttributes", 0)),
    )


def _safe_attr(record, name: str, default):
    try:
        return getattr(record, name)
    except Exception:  # noqa: BLE001
        return default


def _reference(record, name: str, segment_reference) -> int:
    raw = _safe_attr(record, name, None)
    if raw is None:
        return -1
    try:
        return int(segment_reference(raw))
    except Exception:  # noqa: BLE001
        try:
            return int(raw)
        except Exception:  # noqa: BLE001
            return -1
