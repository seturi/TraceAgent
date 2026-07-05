"""Collector for NTFS filesystem journals ($MFT and $UsnJrnl:$J).

Unlike the service-artifact collector (which copies files from a mounted user
profile), NTFS journals require *volume-level* access, so this collector opens
the evidence with :mod:`dissect.target` — a disk image for ``DISK_IMAGE`` sources
or the live machine for ``LIVE_SYSTEM`` sources.  For each NTFS volume it copies
the ``$MFT`` (needed to resolve full paths) and the ``$J`` data stream of the USN
journal into ``artifacts/NTFS/<volume>/`` so the USN parser can reconstruct the
event flow reproducibly from the copies.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from collection.base import CollectionContext, Collector, CollectorMetadata
from core.models import ArtifactRecord, EvidenceSource, SourceKind

_CHUNK = 1024 * 1024
_MFT_NAME = "ntfs_mft"
_USN_NAME = "ntfs_usnjrnl"
_LOG_NAME = "ntfs_logfile"


@dataclass(frozen=True, slots=True)
class ExtractedNtfsArtifacts:
    """NTFS metadata files extracted from one volume into a directory."""

    directory: Path
    volume: str
    mft: Path | None = None
    usn: Path | None = None
    logfile: Path | None = None

    @property
    def files(self) -> tuple[tuple[str, str, Path], ...]:
        values = (
            (_MFT_NAME, "$MFT", self.mft),
            (_USN_NAME, "$J", self.usn),
            (_LOG_NAME, "$LogFile", self.logfile),
        )
        return tuple((kind, name, path) for kind, name, path in values if path is not None)


class NtfsArtifactCollector(Collector):
    """Copy NTFS metadata from a volume or extracted folder, read-only."""

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            collector_id="ntfs_filesystem",
            name="NTFS filesystem journals",
            source_kinds=(
                SourceKind.LIVE_SYSTEM,
                SourceKind.DISK_IMAGE,
                SourceKind.ARTIFACT_DIRECTORY,
            ),
            description=(
                "Collect $MFT, $UsnJrnl:$J and $LogFile from NTFS volumes, or "
                "reference them directly from an extracted artifact folder."
            ),
        )

    def scan(self, source: EvidenceSource) -> tuple[ExtractedNtfsArtifacts, ...]:
        if source.kind != SourceKind.ARTIFACT_DIRECTORY or not source.location.is_dir():
            return ()
        return _find_extracted_artifacts(source.location)

    def collect(
        self, source: EvidenceSource, context: CollectionContext
    ) -> Iterable[ArtifactRecord]:
        if source.kind not in self.metadata.source_kinds:
            context.progress(100, "Unsupported source type for NTFS collection.")
            return

        if source.kind == SourceKind.ARTIFACT_DIRECTORY:
            yield from self._collect_extracted(source, context)
            return

        output_root = context.workspace / "artifacts" / "NTFS"
        output_root.mkdir(parents=True, exist_ok=True)
        errors: list[dict[str, str]] = []

        try:
            target = _open_target(source)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI as an error
            context.options["ntfs_collection_errors"] = [
                {"path": str(source.location), "error": f"open target: {exc}"}
            ]
            context.progress(100, f"Unable to open evidence for NTFS collection: {exc}")
            return

        try:
            volumes = list(_iter_ntfs_volumes(target))
            if not volumes:
                context.progress(100, "No NTFS volumes found for USN collection.")
                return
            for index, (label, filesystem, ntfs) in enumerate(volumes, start=1):
                if context.cancelled():
                    break
                volume_dir = output_root / _safe(label)
                volume_dir.mkdir(parents=True, exist_ok=True)
                for artifact_type, name, stream_opener in (
                    (_MFT_NAME, "$MFT", lambda n=ntfs: _open_mft(n)),
                    (_USN_NAME, "$J", lambda n=ntfs: _open_usn(n)),
                    (_LOG_NAME, "$LogFile", lambda f=filesystem: _open_named(f, "$LogFile")),
                ):
                    try:
                        destination = volume_dir / f"{artifact_type}__{_safe(label)}.bin"
                        digest, size = _copy_stream(
                            stream_opener(),
                            destination,
                            trim_leading_zeros=(artifact_type == _USN_NAME),
                            calculate_sha256=context.calculate_sha256,
                        )
                        yield ArtifactRecord(
                            source_id=source.source_id,
                            producer_id=self.metadata.collector_id,
                            path=str(destination),
                            artifact_type=artifact_type,
                            service="NTFS",
                            sha256=digest,
                            size=size,
                            original_path=f"{label}:{name}",
                            metadata={"volume": label, "source_kind": source.kind.value},
                        )
                    except Exception as exc:  # noqa: BLE001
                        errors.append({"path": f"{label}:{name}", "error": str(exc)})
                context.progress(
                    round(index / max(len(volumes), 1) * 100),
                    f"Collected NTFS journals: {label}",
                )
        finally:
            context.options["ntfs_collection_errors"] = errors
            _close_target(target)

    def _collect_extracted(
        self, source: EvidenceSource, context: CollectionContext
    ) -> Iterable[ArtifactRecord]:
        sets = self.scan(source)
        errors: list[dict[str, str]] = []
        pending = [(item, artifact) for item in sets for artifact in item.files]

        for index, (item, (artifact_type, original_name, source_path)) in enumerate(
            pending, start=1
        ):
            if context.cancelled():
                break
            try:
                stat = source_path.stat()
                digest = _hash_file(source_path) if context.calculate_sha256 else None
                yield ArtifactRecord(
                    source_id=source.source_id,
                    producer_id=self.metadata.collector_id,
                    path=str(source_path),
                    artifact_type=artifact_type,
                    service="NTFS",
                    sha256=digest,
                    size=stat.st_size,
                    original_path=str(source_path),
                    metadata={
                        "volume": item.volume,
                        "source_kind": source.kind.value,
                        "original_name": original_name,
                        "referenced_in_place": True,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                errors.append({"path": str(source_path), "error": str(exc)})
            context.progress(
                round(index / max(len(pending), 1) * 100),
                f"Registering extracted NTFS artifact: {source_path.name}",
            )

        context.options["ntfs_collection_errors"] = errors
        if not pending:
            context.progress(100, "No extracted NTFS artifacts found.")


def _open_target(source: EvidenceSource):
    import logging

    from dissect.target import Target

    # dissect logs benign WARNINGs while probing RAID volume systems; quiet them.
    logging.getLogger("dissect").setLevel(logging.ERROR)
    if source.kind == SourceKind.DISK_IMAGE:
        return Target.open(str(source.location))
    return Target.open("local")


def _iter_ntfs_volumes(target):
    seen: set[int] = set()
    for index, filesystem in enumerate(getattr(target, "filesystems", []) or []):
        ntfs = getattr(filesystem, "ntfs", None)
        if ntfs is None or getattr(ntfs, "usnjrnl", None) is None:
            continue
        if id(ntfs) in seen:
            continue
        seen.add(id(ntfs))
        label = _volume_label(filesystem, index)
        yield label, filesystem, ntfs


def _volume_label(filesystem, index: int) -> str:
    for attr in ("volume", "name"):
        value = getattr(filesystem, attr, None)
        name = getattr(value, "name", value)
        if isinstance(name, str) and name:
            return name
    return f"volume_{index}"


def _open_mft(ntfs):
    fh = getattr(getattr(ntfs, "mft", None), "fh", None)
    if fh is None:
        raise ValueError("NTFS volume has no readable $MFT stream")
    fh.seek(0)
    return fh


def _open_usn(ntfs):
    fh = getattr(getattr(ntfs, "usnjrnl", None), "fh", None)
    if fh is None:
        raise ValueError("NTFS volume has no readable $UsnJrnl:$J stream")
    fh.seek(0)
    return fh


def _open_named(filesystem, name: str):
    entry = filesystem.get(name)
    fh = entry.open()
    fh.seek(0)
    return fh


def _copy_stream(
    stream,
    destination: Path,
    *,
    trim_leading_zeros: bool,
    calculate_sha256: bool,
) -> tuple[str | None, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.name}.partial")
    digest = hashlib.sha256() if calculate_sha256 else None
    size = 0
    started = not trim_leading_zeros
    try:
        with temporary.open("wb") as output:
            while chunk := stream.read(_CHUNK):
                if not started:
                    if not chunk.strip(b"\x00"):
                        continue  # skip leading sparse/zero region of $J
                    started = True
                output.write(chunk)
                size += len(chunk)
                if digest is not None:
                    digest.update(chunk)
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return (digest.hexdigest() if digest is not None else None), size


def _close_target(target) -> None:
    for name in ("filesystems", "volumes", "disks"):
        try:
            items = tuple(getattr(target, name, ()) or ())
        except Exception:  # noqa: BLE001
            continue
        for item in items:
            close = getattr(item, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001
                    pass


def _find_extracted_artifacts(root: Path) -> tuple[ExtractedNtfsArtifacts, ...]:
    grouped: dict[Path, dict[str, Path]] = {}
    try:
        candidates = root.rglob("*")
        for path in candidates:
            try:
                if not path.is_file() or path.is_symlink():
                    continue
            except OSError:
                continue
            artifact_type = _artifact_type_for_name(path.name)
            if artifact_type is not None:
                grouped.setdefault(path.parent, {}).setdefault(artifact_type, path)
    except OSError:
        return ()

    results: list[ExtractedNtfsArtifacts] = []
    for directory, files in sorted(grouped.items(), key=lambda item: str(item[0]).lower()):
        # $MFT alone cannot produce a timeline. Keep sets that have at least one
        # journal that an NTFS parser can consume.
        if _USN_NAME not in files and _LOG_NAME not in files:
            continue
        volume = directory.name if directory != root else root.name
        results.append(
            ExtractedNtfsArtifacts(
                directory=directory,
                volume=_safe(volume),
                mft=files.get(_MFT_NAME),
                usn=files.get(_USN_NAME),
                logfile=files.get(_LOG_NAME),
            )
        )
    return tuple(results)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_type_for_name(name: str) -> str | None:
    lowered = name.lower()
    if lowered == "$mft" or (lowered.startswith(f"{_MFT_NAME}__") and lowered.endswith(".bin")):
        return _MFT_NAME
    if lowered == "$j" or (lowered.startswith(f"{_USN_NAME}__") and lowered.endswith(".bin")):
        return _USN_NAME
    if lowered == "$logfile" or (lowered.startswith(f"{_LOG_NAME}__") and lowered.endswith(".bin")):
        return _LOG_NAME
    return None




def _safe(value: str) -> str:
    import re

    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    return cleaned or "volume"
