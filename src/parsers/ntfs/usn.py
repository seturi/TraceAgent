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

_USN_GLOB = "**/ntfs_usnjrnl__*.bin"


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
                views = _read_usn_records(journal, mft)
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
            journals = sorted(location.glob(_USN_GLOB))
        except OSError:
            return
        for journal in journals:
            if not journal.is_file():
                continue
            mft = _sibling_mft(journal)
            yield journal, mft


def _sibling_mft(journal: Path) -> Path | None:
    for candidate in journal.parent.glob("ntfs_mft__*.bin"):
        if candidate.is_file():
            return candidate
    return None


def _read_usn_records(journal: Path, mft: Path | None) -> list[UsnRecordView]:
    from dissect.ntfs.ntfs import NTFS

    mft_stream = mft.open("rb") if mft is not None else None
    journal_stream = journal.open("rb")
    try:
        ntfs = NTFS(mft=mft_stream, usnjrnl=journal_stream)
        views: list[UsnRecordView] = []
        fallback = file_timestamp(journal)
        for record in ntfs.usnjrnl.records():
            views.append(_to_view(record, fallback))
        views.sort(key=lambda view: view.usn)
        return views
    finally:
        journal_stream.close()
        if mft_stream is not None:
            mft_stream.close()


def _to_view(record, fallback) -> UsnRecordView:
    from dissect.ntfs.util import segment_reference

    try:
        timestamp = record.timestamp
    except Exception:  # noqa: BLE001
        timestamp = fallback
    try:
        full_path = record.full_path
    except Exception:  # noqa: BLE001
        full_path = None
    return UsnRecordView(
        usn=int(_safe_attr(record, "Usn", 0)),
        timestamp=timestamp or fallback,
        file_reference=_reference(record, "FileReferenceNumber", segment_reference),
        parent_reference=_reference(record, "ParentFileReferenceNumber", segment_reference),
        filename=getattr(record, "filename", None),
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
