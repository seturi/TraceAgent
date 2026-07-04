from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from collection.base import CollectionContext, Collector, CollectorMetadata
from collection.service_catalog import DetectedArtifactRoot, ServiceDetection, detect_service_artifacts
from core.models import ArtifactRecord, EvidenceSource, SourceKind
from utils.evidence_access import EvidenceAccessor, EvidenceEntry, open_evidence_accessor


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

        with open_evidence_accessor(source) as accessor:
            detections = detect_service_artifacts(accessor)
            context.options["service_detections"] = detections
            pending = self._pending_files(accessor, detections)
            copied: dict[tuple[str, str], tuple[Path, str | None]] = {}

            for index, (root, entry) in enumerate(pending, start=1):
                if context.cancelled():
                    break
                try:
                    relative = accessor.relative_to_home(entry, root.user)
                    destination = self._destination(
                        output_root,
                        root.service,
                        root.user.name,
                        relative,
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
                    yield ArtifactRecord(
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
                except Exception as exc:
                    errors.append({"path": entry.path, "error": str(exc)})
                context.progress(
                    round(index / max(len(pending), 1) * 100),
                    f"Collecting {root.service}: {entry.name}",
                )

        context.options["collection_errors"] = errors
        if not pending:
            context.progress(100, "No supported service artifacts found.")

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
        service: str,
        user_name: str,
        relative: PurePosixPath,
    ) -> Path:
        parts = [_safe_component(service).replace(" ", "_"), _safe_component(user_name)]
        parts.extend(_safe_component(part) for part in relative.parts if part not in {"", ".", ".."})
        destination = output_root.joinpath(*parts)
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
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    return sanitized or "_"


def _relative_to_root(entry_path: str, root_path: str) -> PurePosixPath:
    entry = PurePosixPath(entry_path.replace("\\", "/"))
    root = PurePosixPath(root_path.replace("\\", "/"))
    try:
        return entry.relative_to(root)
    except ValueError:
        return PurePosixPath(entry.name)
