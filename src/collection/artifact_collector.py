from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from collection.base import CollectionContext, Collector, CollectorMetadata
from collection.service_catalog import DetectedArtifactRoot, ServiceDetection, detect_service_artifacts
from core.models import ArtifactRecord, EvidenceSource, SourceKind
from utils.evidence_access import EvidenceAccessor, EvidenceEntry, open_evidence_accessor

_COMPOUND_ARTIFACT_TYPES = {"indexeddb", "local_storage", "cache_data"}


class ServiceArtifactCollector(Collector):
    """Detect and copy supported AI-agent artifacts without modifying evidence."""

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            collector_id="service_artifacts",
            name="AI service artifacts",
            source_kinds=(
                SourceKind.LIVE_SYSTEM,
                SourceKind.DISK_IMAGE,
                SourceKind.ARTIFACT_DIRECTORY,
            ),
            description="Detect supported services and copy their artifacts read-only.",
        )

    def scan(
        self,
        source: EvidenceSource,
        accessor: EvidenceAccessor | None = None,
    ) -> tuple[ServiceDetection, ...]:
        if accessor is not None:
            return detect_service_artifacts(accessor)
        with open_evidence_accessor(source) as opened:
            return detect_service_artifacts(opened)

    def collect(
        self,
        source: EvidenceSource,
        context: CollectionContext,
    ) -> Iterable[ArtifactRecord]:
        output_root = context.workspace / "artifacts"
        output_root.mkdir(parents=True, exist_ok=True)
        errors: list[dict[str, str]] = []
        manifest_entries: dict[str, list[dict[str, object]]] = {}

        with open_evidence_accessor(source) as accessor:
            detections = detect_service_artifacts(accessor)
            context.options["service_detections"] = detections
            pending = self._pending_files(accessor, detections)
            copied: dict[tuple[str, str], tuple[Path, str | None]] = {}

            for index, (root, entry) in enumerate(pending, start=1):
                if context.cancelled():
                    break
                try:
                    destination = self._destination(
                        output_root,
                        root,
                        entry,
                    )
                    cache_key = (root.service, entry.path.lower())
                    if cache_key in copied:
                        destination, digest = copied[cache_key]
                    else:
                        digest = self._copy_file(
                            accessor,
                            entry,
                            destination,
                            calculate_sha256=context.calculate_sha256,
                        )
                        copied[cache_key] = (destination, digest)
                    record = ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.collector_id,
                        path=str(destination),
                        artifact_type=root.artifact_type,
                        service=root.service,
                        sha256=digest,
                        size=entry.size,
                        original_path=entry.path,
                        metadata={
                            "user": root.user.name,
                            "user_home": root.user.display_path,
                            "detected_root": root.entry.path,
                            "source_kind": source.kind.value,
                            "modified_time": entry.modified_time,
                        },
                    )
                    manifest_entries.setdefault(root.service, []).append(
                        {
                            "collected_path": str(destination.relative_to(output_root)),
                            "original_path": entry.path,
                            "artifact_type": root.artifact_type,
                            "service": root.service,
                            "user": root.user.name,
                            "detected_root": root.entry.path,
                            "size": entry.size,
                            "sha256": digest,
                        }
                    )
                    yield record
                except Exception as exc:
                    errors.append({"path": entry.path, "error": str(exc)})
                context.progress(
                    round(index / max(len(pending), 1) * 100),
                    f"Collecting {root.service}: {entry.name}",
                )

        context.options["collection_errors"] = errors
        self._write_manifests(output_root, manifest_entries)
        if not pending:
            context.progress(100, "No supported service artifacts found.")

    @staticmethod
    def _write_manifests(
        output_root: Path,
        entries_by_service: dict[str, list[dict[str, object]]],
    ) -> None:
        for service, entries in entries_by_service.items():
            service_dir = output_root / _safe_component(service).replace(" ", "_")
            service_dir.mkdir(parents=True, exist_ok=True)
            destination = service_dir / "collection_manifest.jsonl"
            temporary = destination.with_suffix(".jsonl.partial")
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                for entry in entries:
                    stream.write(json.dumps(entry, ensure_ascii=False, default=str))
                    stream.write("\n")
            temporary.replace(destination)

    @staticmethod
    def _pending_files(
        accessor: EvidenceAccessor,
        detections: tuple[ServiceDetection, ...],
    ) -> list[tuple[DetectedArtifactRoot, EvidenceEntry]]:
        pending: list[tuple[DetectedArtifactRoot, EvidenceEntry]] = []
        seen: set[tuple[str, str]] = set()
        for detection in detections:
            for root in detection.roots:
                for entry in accessor.iter_files(root.entry):
                    relative = _relative_to_root(entry.path, root.entry.path)
                    if not any(relative.match(pattern) for pattern in root.include_file_patterns):
                        continue
                    identity = (root.service, entry.path.lower())
                    if identity in seen:
                        continue
                    seen.add(identity)
                    pending.append((root, entry))
        return pending

    @staticmethod
    def _destination(
        output_root: Path,
        root: DetectedArtifactRoot,
        entry: EvidenceEntry,
    ) -> Path:
        service_dir = output_root / _safe_component(root.service).replace(" ", "_")
        if root.artifact_type in _COMPOUND_ARTIFACT_TYPES and root.entry.is_dir:
            group_hash = hashlib.sha256(root.entry.path.lower().encode("utf-8")).hexdigest()[:8]
            group_name = _compound_group_name(
                root.artifact_type,
                root.entry.name,
                group_hash,
            )
            relative = _relative_to_root(entry.path, root.entry.path)
            parts = [
                _safe_component(part)
                for part in relative.parts
                if part not in {"", ".", ".."}
            ]
            destination = service_dir.joinpath(group_name, *parts)
        else:
            filename = _prefixed_filename(root.artifact_type, entry.name)
            destination = service_dir / filename
            if destination.exists():
                suffix_hash = hashlib.sha256(entry.path.lower().encode("utf-8")).hexdigest()[:8]
                destination = destination.with_name(
                    f"{destination.stem}_{suffix_hash}{destination.suffix}"
                )
        resolved_root = output_root.resolve()
        resolved_destination = destination.resolve()
        if not resolved_destination.is_relative_to(resolved_root):
            raise ValueError(f"Unsafe artifact destination: {destination}")
        return destination

    @staticmethod
    def _copy_file(
        accessor: EvidenceAccessor,
        entry: EvidenceEntry,
        destination: Path,
        *,
        calculate_sha256: bool,
    ) -> str | None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f"{destination.name}.partial")
        digest = hashlib.sha256() if calculate_sha256 else None
        try:
            with accessor.open_binary(entry) as source_stream, temporary.open("wb") as output_stream:
                while chunk := source_stream.read(1024 * 1024):
                    output_stream.write(chunk)
                    if digest is not None:
                        digest.update(chunk)
            temporary.replace(destination)
            if entry.modified_time is not None:
                try:
                    os.utime(destination, (entry.modified_time, entry.modified_time))
                except OSError:
                    pass
        finally:
            if temporary.exists():
                temporary.unlink()
        return digest.hexdigest() if digest is not None else None


def _safe_component(value: str) -> str:
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).rstrip(" .")
    return sanitized or "_"


def _prefixed_filename(artifact_type: str, filename: str) -> str:
    safe_name = _safe_component(filename)
    return f"{_safe_component(artifact_type)}__{safe_name}"


def _compound_group_name(artifact_type: str, root_name: str, group_hash: str) -> str:
    safe_type = _safe_component(artifact_type)
    safe_name = _safe_component(root_name)
    indexeddb_suffix = ".indexeddb.leveldb"
    if safe_name.lower().endswith(indexeddb_suffix):
        stem = safe_name[: -len(indexeddb_suffix)]
        return f"{safe_type}__{stem}_{group_hash}{indexeddb_suffix}"
    return f"{safe_type}__{safe_name}_{group_hash}"


def _relative_to_root(entry_path: str, root_path: str) -> PurePosixPath:
    entry = PurePosixPath(entry_path.replace("\\", "/"))
    root = PurePosixPath(root_path.replace("\\", "/"))
    try:
        relative = entry.relative_to(root)
        return PurePosixPath(entry.name) if str(relative) == "." else relative
    except ValueError:
        return PurePosixPath(entry.name)
