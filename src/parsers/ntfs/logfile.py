"""Parser for the NTFS transaction log ($LogFile).

``dissect`` has no ``$LogFile`` support and a full LFS transaction decoder is out
of scope, so this parser recovers the file references embedded in the log by
carving ``$FILE_NAME`` attributes (see :mod:`analysis.ntfs.carver`).
Each recovered name is resolved to a full path via the sibling ``$MFT`` and
emitted as a timeline event.  Because ``$LogFile`` retains only very recent
transactions, this mainly corroborates and recovers file names/timestamps that
may already be gone from other artifacts; it does not reconstruct full
create/delete/rename operation semantics.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from analysis.ntfs.events import NTFS_SERVICE, is_user_document
from analysis.ntfs.carver import CarvedFileName, carve_index_operations
from core.models import ActorClass, AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.structured_data import file_timestamp
from version import __version__

_LOG_PARSER_ID = "ntfs.logfile"
_LOG_GLOBS = ("**/ntfs_logfile__*.bin", "**/$LogFile")


class NtfsLogFileParser(ArtifactParser):
    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id=_LOG_PARSER_ID,
            name="NTFS $LogFile",
            category="ntfs",
            version=__version__,
            services=("NTFS $LogFile",),
            description="Recovers file names, parent paths and $FILE_NAME timestamps from $LogFile.",
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        return 0.85 if any(self._logs(source.location)) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        for index, (log, mft) in enumerate(self._logs(source.location), start=1):
            yield ArtifactRecord(
                source_id=source.source_id,
                producer_id=self.metadata.parser_id,
                path=str(log),
                artifact_type="ntfs_logfile",
                service=NTFS_SERVICE,
                size=log.stat().st_size,
                metadata={"mft_path": str(mft) if mft else None, "volume": log.parent.name},
            )
            context.progress(index, f"Discovered {log.name}")

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
            log = Path(artifact.path)
            mft_path = artifact.metadata.get("mft_path")
            resolver = _path_resolver(mft_path if isinstance(mft_path, str) else None)
            fallback = file_timestamp(log)
            try:
                seen: set[tuple] = set()
                for item, operation in carve_index_operations(log.read_bytes()):
                    if context.cancelled():
                        break
                    if not is_user_document(item.name):
                        continue  # skip OS/app temp churn — surface user documents
                    key = (
                        item.parent_reference,
                        item.name,
                        operation,
                        item.modified.isoformat() if item.modified else "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    emit(
                        _carved_event(
                            source, self.metadata.parser_id, item, operation, resolver, fallback
                        )
                    )
            except (OSError, ValueError) as exc:
                errors.append({"path": str(log), "error": str(exc)})
            context.progress(
                round(index / max(len(artifact_list), 1) * 100), f"Parsed {log.name}"
            )
        if errors:
            context.options.setdefault("ntfs_logfile_errors", []).extend(errors)

    @staticmethod
    def _logs(location: Path) -> Iterable[tuple[Path, Path | None]]:
        try:
            logs = sorted(
                {path for pattern in _LOG_GLOBS for path in location.glob(pattern)}
            )
        except OSError:
            return
        for log in logs:
            if not log.is_file():
                continue
            yield log, _sibling_mft(log)


def _sibling_mft(log: Path) -> Path | None:
    for pattern in ("ntfs_mft__*.bin", "$MFT"):
        for candidate in log.parent.glob(pattern):
            if candidate.is_file():
                return candidate
    return None


def _carved_event(
    source: EvidenceSource,
    parser_id: str,
    item: CarvedFileName,
    operation: str,
    resolver,
    fallback,
) -> NormalizedEvent:
    parent_path = resolver(item.parent_reference)
    full_path = f"{parent_path}\\{item.name}" if parent_path else None
    timestamp = item.mft_modified or item.modified or item.created or fallback
    return NormalizedEvent(
        source_id=source.source_id,
        parser_id=parser_id,
        timestamp=timestamp,
        event_type=f"ntfs_logfile_{operation}",
        path=full_path,
        service=NTFS_SERVICE,
        attribution=AgentAttribution.NONE,
        actor_class=ActorClass.UNKNOWN,
        raw_reference=f"logfile_offset={item.offset}",
        metadata={
            "filename": item.name,
            "operation": operation,
            "parent_reference": item.parent_reference,
            "namespace": item.namespace,
            "full_path": full_path,
            "fn_created": item.created.isoformat() if item.created else None,
            "fn_modified": item.modified.isoformat() if item.modified else None,
            "fn_mft_modified": item.mft_modified.isoformat() if item.mft_modified else None,
            "fn_accessed": item.accessed.isoformat() if item.accessed else None,
            "flags": item.flags,
        },
    )


def _path_resolver(mft_path: str | None):
    """Return a parent-reference -> directory-path resolver backed by the $MFT."""
    if not mft_path:
        return lambda _ref: None
    try:
        from dissect.ntfs.ntfs import NTFS

        ntfs = NTFS(mft=Path(mft_path).open("rb"))
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
