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
from pathlib import Path

from collection.base import CollectionContext, Collector, CollectorMetadata
from core.models import ArtifactRecord, EvidenceSource, SourceKind

_CHUNK = 1024 * 1024
_MFT_NAME = "ntfs_mft"
_USN_NAME = "ntfs_usnjrnl"
_LOG_NAME = "ntfs_logfile"


class NtfsArtifactCollector(Collector):
    """Copy $MFT and $UsnJrnl:$J from every NTFS volume, read-only."""

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            collector_id="ntfs_filesystem",
            name="NTFS filesystem journals",
            source_kinds=(SourceKind.LIVE_SYSTEM, SourceKind.DISK_IMAGE),
            description="Copy $MFT and $UsnJrnl:$J from NTFS volumes for USN event analysis.",
        )

    def collect(
        self, source: EvidenceSource, context: CollectionContext
    ) -> Iterable[ArtifactRecord]:
        if source.kind not in self.metadata.source_kinds:
            context.progress(100, "NTFS collection needs a live system or disk image.")
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


def _safe(value: str) -> str:
    import re

    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    return cleaned or "volume"
