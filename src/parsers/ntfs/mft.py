"""Parser for the collected NTFS master file table ($MFT).

Unlike the USN/$LogFile parsers (which record *operations*), the $MFT is the
file-system *inventory*: a record per file/folder that exists, plus ``$FILE_NAME``
attributes left in record slack for recently deleted files.  Parsing it surfaces
the actual files — real names, paths and ``$FILE_NAME`` timestamps — independently
of the volatile, wrap-prone USN journal, so files whose USN history was purged
still appear.

Records are recovered by carving ``$FILE_NAME`` attributes (fast, and also picks
up deleted entries); parent references are resolved to full paths through the
same ``$MFT``.  System/application storage (Windows, ProgramData, AppData, …) is
skipped so the user's own documents are what surfaces.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from analysis.ntfs.carver import carve_file_names, dedupe
from analysis.ntfs.events import NTFS_SERVICE, is_user_document
from core.models import ActorClass, AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp
from version import __version__

_MFT_PARSER_ID = "ntfs.mft"
_MFT_GLOB = "**/ntfs_mft__*.bin"
# Volume locations that are system / application storage rather than user files.
_BACKGROUND = (
    "/windows/",
    "/programdata/",
    "/program files",
    "/$recycle.bin/",
    "/system volume information/",
    "/appdata/",
    "/$extend/",
)
_FN_DIRECTORY = 0x10000000  # $FILE_NAME flags bit for a directory


@dataclass(frozen=True, slots=True)
class MftRecordView:
    """A ``dissect``-independent view of one recovered $MFT file record."""

    filename: str
    full_path: str | None
    parent_reference: int
    is_dir: bool
    created: datetime | None
    modified: datetime | None
    mft_changed: datetime | None
    accessed: datetime | None


class NtfsMftParser(ArtifactParser):
    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id=_MFT_PARSER_ID,
            name="NTFS $MFT",
            category="ntfs",
            version=__version__,
            services=("NTFS $MFT",),
            description="Recovers user files/folders (existing and deleted) from $MFT with $FILE_NAME times.",
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
        errors: list[dict[str, str]] = []
        for index, artifact in enumerate(artifact_list, start=1):
            if context.cancelled():
                break
            table = Path(artifact.path)
            fallback = file_timestamp(table)
            try:
                for view in _read_mft_records(table):
                    if context.cancelled():
                        break
                    emit(_mft_event(source, self.metadata.parser_id, view, fallback))
            except Exception as exc:  # noqa: BLE001
                errors.append({"path": str(table), "error": str(exc)})
            context.progress(
                round(index / max(len(artifact_list), 1) * 100), f"Parsed {table.name}"
            )
        if errors:
            context.options.setdefault("ntfs_mft_errors", []).extend(errors)

    @staticmethod
    def _tables(location: Path) -> Iterable[Path]:
        try:
            tables = sorted(location.glob(_MFT_GLOB))
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
    timestamp = view.modified or view.created or fallback
    return NormalizedEvent(
        source_id=source.source_id,
        parser_id=parser_id,
        timestamp=timestamp,
        event_type="ntfs_mft_directory" if view.is_dir else "ntfs_mft_file",
        path=view.full_path,
        service=NTFS_SERVICE,
        attribution=AgentAttribution.NONE,
        actor_class=ActorClass.UNKNOWN,
        raw_reference=f"mft_parent={view.parent_reference}",
        metadata={
            "filename": view.filename,
            "full_path": view.full_path,
            "is_dir": view.is_dir,
            "parent_reference": view.parent_reference,
            "fn_created": _iso(view.created),
            "fn_modified": _iso(view.modified),
            "fn_mft_changed": _iso(view.mft_changed),
            "fn_accessed": _iso(view.accessed),
        },
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _read_mft_records(table: Path) -> Iterable[MftRecordView]:
    carved = dedupe(carve_file_names(table.read_bytes()))
    resolve = _path_resolver(table)
    for item in carved:
        # Filter by document extension *before* resolving the path, so only the
        # handful of user documents pay the parent-chain resolution cost.
        if not is_user_document(item.name):
            continue
        parent_path = resolve(item.parent_reference)
        full_path = f"{parent_path}\\{item.name}" if parent_path else None
        if full_path is not None:
            normalized = full_path.replace("\\", "/").lower()
            if any(marker in normalized for marker in _BACKGROUND):
                continue  # system / application storage, not a user file
        yield MftRecordView(
            filename=item.name,
            full_path=full_path,
            parent_reference=item.parent_reference,
            is_dir=bool(item.flags & _FN_DIRECTORY),
            created=item.created,
            modified=item.modified,
            mft_changed=item.mft_modified,
            accessed=item.accessed,
        )


def _path_resolver(table: Path):
    """Return a parent-reference -> directory-path resolver backed by the $MFT."""
    try:
        from dissect.ntfs.ntfs import NTFS

        ntfs = NTFS(mft=table.open("rb"))
    except Exception:  # noqa: BLE001
        return lambda _ref: None

    cache: dict[int, str | None] = {}

    def resolve(ref: int) -> str | None:
        if ref in cache:
            return cache[ref]
        try:
            path = ntfs.mft(ref).full_path()
        except Exception:  # noqa: BLE001
            path = None
        cache[ref] = path
        return path

    return resolve


def _time(attribute, name: str) -> datetime | None:
    if attribute is None:
        return None
    try:
        return getattr(attribute, name)
    except Exception:  # noqa: BLE001
        return None
