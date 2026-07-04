from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable

from core.models import EvidenceSource, SourceKind


class SourceAccessError(RuntimeError):
    """Raised when an evidence source cannot be opened read-only."""


@dataclass(frozen=True, slots=True)
class EvidenceUserHome:
    identity: str
    name: str
    display_path: str
    handle: Any


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    path: str
    name: str
    is_file: bool
    is_dir: bool
    size: int | None
    modified_time: float | None
    handle: Any


@dataclass(frozen=True, slots=True)
class SourceOpenInfo:
    source_kind: SourceKind
    description: str
    user_homes: int
    filesystems: int | None = None


class EvidenceAccessor(ABC):
    def __init__(self, source: EvidenceSource) -> None:
        self.source = source

    def __enter__(self) -> "EvidenceAccessor":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @abstractmethod
    def user_homes(self) -> tuple[EvidenceUserHome, ...]:
        raise NotImplementedError

    @abstractmethod
    def glob(self, home: EvidenceUserHome, pattern: str) -> tuple[EvidenceEntry, ...]:
        raise NotImplementedError

    @abstractmethod
    def iter_files(self, entry: EvidenceEntry) -> Iterator[EvidenceEntry]:
        raise NotImplementedError

    @abstractmethod
    def open_binary(self, entry: EvidenceEntry) -> BinaryIO:
        raise NotImplementedError

    @abstractmethod
    def relative_to_home(self, entry: EvidenceEntry, home: EvidenceUserHome) -> PurePosixPath:
        raise NotImplementedError

    @abstractmethod
    def info(self) -> SourceOpenInfo:
        raise NotImplementedError

    def close(self) -> None:
        return None


class LocalEvidenceAccessor(EvidenceAccessor):
    """Read-only path facade for a live system or extracted artifact directory."""

    def __init__(self, source: EvidenceSource, homes: Iterable[Path] | None = None) -> None:
        super().__init__(source)
        if source.kind not in {SourceKind.LIVE_SYSTEM, SourceKind.ARTIFACT_DIRECTORY}:
            raise ValueError(f"Unsupported source kind for local access: {source.kind}")
        if source.kind == SourceKind.ARTIFACT_DIRECTORY and not source.location.is_dir():
            raise SourceAccessError(f"Artifact directory does not exist: {source.location}")
        self._configured_homes = tuple(homes) if homes is not None else None
        self._homes = self._find_homes()

    def _find_homes(self) -> tuple[EvidenceUserHome, ...]:
        if self.source.kind == SourceKind.ARTIFACT_DIRECTORY:
            roots = self._configured_homes or (self.source.location,)
        elif self._configured_homes is not None:
            roots = self._configured_homes
        else:
            roots = self._live_user_homes()

        homes: list[EvidenceUserHome] = []
        seen: set[Path] = set()
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_dir():
                continue
            seen.add(resolved)
            name = "artifact-root" if self.source.kind == SourceKind.ARTIFACT_DIRECTORY else resolved.name
            homes.append(EvidenceUserHome(str(resolved).lower(), name, str(resolved), resolved))
        return tuple(homes)

    @staticmethod
    def _live_user_homes() -> tuple[Path, ...]:
        current = Path.home()
        candidates = [current]
        if os.name == "nt":
            users_root = Path(os.environ.get("SystemDrive", current.drive or "C:")) / "Users"
            try:
                candidates.extend(path for path in users_root.iterdir() if path.is_dir())
            except OSError:
                pass
        return tuple(candidates)

    def user_homes(self) -> tuple[EvidenceUserHome, ...]:
        return self._homes

    def glob(self, home: EvidenceUserHome, pattern: str) -> tuple[EvidenceEntry, ...]:
        root = Path(home.handle)
        entries: list[EvidenceEntry] = []
        try:
            matches = root.glob(pattern)
            for match in matches:
                entry = self._entry(match)
                if entry is not None:
                    entries.append(entry)
        except (OSError, RuntimeError):
            return ()
        return tuple(entries)

    def iter_files(self, entry: EvidenceEntry) -> Iterator[EvidenceEntry]:
        path = Path(entry.handle)
        if entry.is_file:
            yield entry
            return
        if not entry.is_dir:
            return
        try:
            for child in path.rglob("*"):
                item = self._entry(child)
                if item is not None and item.is_file:
                    yield item
        except OSError:
            return

    def open_binary(self, entry: EvidenceEntry) -> BinaryIO:
        if not entry.is_file:
            raise IsADirectoryError(entry.path)
        return Path(entry.handle).open("rb")

    def relative_to_home(self, entry: EvidenceEntry, home: EvidenceUserHome) -> PurePosixPath:
        relative = Path(entry.handle).resolve().relative_to(Path(home.handle).resolve())
        return PurePosixPath(*relative.parts)

    def info(self) -> SourceOpenInfo:
        label = "Current PC" if self.source.kind == SourceKind.LIVE_SYSTEM else "Extracted artifact directory"
        return SourceOpenInfo(self.source.kind, label, len(self._homes), 1)

    @staticmethod
    def _entry(path: Path) -> EvidenceEntry | None:
        try:
            if path.is_symlink():
                return None
            stat = path.stat()
            is_file = path.is_file()
            is_dir = path.is_dir()
        except OSError:
            return None
        return EvidenceEntry(
            path=str(path),
            name=path.name,
            is_file=is_file,
            is_dir=is_dir,
            size=stat.st_size if is_file else None,
            modified_time=stat.st_mtime,
            handle=path,
        )


TargetFactory = Callable[[Path], Any]


def _default_target_factory(image_path: Path) -> Any:
    try:
        from dissect.target import Target
    except ImportError as exc:
        raise SourceAccessError(
            "dissect.target is required to open E01, RAW/DD, VHD and VHDX images."
        ) from exc
    try:
        return Target.open(image_path)
    except Exception as exc:
        raise SourceAccessError(f"Unable to open disk image read-only: {image_path}: {exc}") from exc


class DiskImageEvidenceAccessor(EvidenceAccessor):
    """Read-only filesystem facade over a disk image opened by dissect.target."""

    def __init__(self, source: EvidenceSource, target_factory: TargetFactory | None = None) -> None:
        super().__init__(source)
        if source.kind != SourceKind.DISK_IMAGE:
            raise ValueError(f"Unsupported source kind for image access: {source.kind}")
        if not source.location.is_file():
            raise SourceAccessError(f"Disk image does not exist: {source.location}")
        self._target = (target_factory or _default_target_factory)(source.location)
        self._homes = self._find_homes()
        if not self._homes:
            self.close()
            raise SourceAccessError("No Windows user profile directories were found in the disk image.")

    def _find_homes(self) -> tuple[EvidenceUserHome, ...]:
        homes: list[EvidenceUserHome] = []
        seen: set[str] = set()
        for users_path in ("sysvol/Users", "c:/Users"):
            try:
                root = self._target.fs.path(users_path)
                if not root.exists() or not root.is_dir():
                    continue
                candidates = root.glob("*")
            except Exception:
                continue
            for candidate in candidates:
                try:
                    if not candidate.is_dir() or candidate.is_symlink():
                        continue
                except Exception:
                    continue
                normalized = str(candidate).lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                homes.append(
                    EvidenceUserHome(normalized, candidate.name, str(candidate), candidate)
                )
            if homes:
                break
        return tuple(homes)

    def user_homes(self) -> tuple[EvidenceUserHome, ...]:
        return self._homes

    def glob(self, home: EvidenceUserHome, pattern: str) -> tuple[EvidenceEntry, ...]:
        try:
            return tuple(
                entry
                for path in home.handle.glob(pattern)
                if (entry := self._entry(path)) is not None
            )
        except Exception:
            return ()

    def iter_files(self, entry: EvidenceEntry) -> Iterator[EvidenceEntry]:
        if entry.is_file:
            yield entry
            return
        if not entry.is_dir:
            return
        try:
            paths = entry.handle.rglob("*")
            for path in paths:
                item = self._entry(path)
                if item is not None and item.is_file:
                    yield item
        except Exception:
            return

    def open_binary(self, entry: EvidenceEntry) -> BinaryIO:
        if not entry.is_file:
            raise IsADirectoryError(entry.path)
        return entry.handle.open("rb")

    def relative_to_home(self, entry: EvidenceEntry, home: EvidenceUserHome) -> PurePosixPath:
        relative = entry.handle.relative_to(home.handle)
        return PurePosixPath(*relative.parts)

    def info(self) -> SourceOpenInfo:
        try:
            filesystems = len(tuple(self._target.filesystems))
        except Exception:
            filesystems = None
        return SourceOpenInfo(
            SourceKind.DISK_IMAGE,
            f"Disk image: {self.source.location.name}",
            len(self._homes),
            filesystems,
        )

    def close(self) -> None:
        target = getattr(self, "_target", None)
        if target is None:
            return
        for collection_name in ("filesystems", "volumes", "disks"):
            try:
                collection = tuple(getattr(target, collection_name))
            except Exception:
                continue
            for item in collection:
                close = getattr(item, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass
        self._target = None

    @staticmethod
    def _entry(path: Any) -> EvidenceEntry | None:
        try:
            if path.is_symlink():
                return None
            is_file = path.is_file()
            is_dir = path.is_dir()
            stat = path.stat()
        except Exception:
            return None
        return EvidenceEntry(
            path=str(path),
            name=path.name,
            is_file=is_file,
            is_dir=is_dir,
            size=stat.st_size if is_file else None,
            modified_time=getattr(stat, "st_mtime", None),
            handle=path,
        )


def open_evidence_accessor(source: EvidenceSource) -> EvidenceAccessor:
    if source.kind == SourceKind.DISK_IMAGE:
        return DiskImageEvidenceAccessor(source)
    return LocalEvidenceAccessor(source)


def validate_evidence_source(source: EvidenceSource) -> SourceOpenInfo:
    with open_evidence_accessor(source) as accessor:
        return accessor.info()
