from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.chromium_indexeddb import ChromiumStorageDependencyError, to_json_safe

ReaderFactory = Callable[[Path], Any]


@dataclass(frozen=True, slots=True)
class ChromiumLocalStorageArtifact:
    leveldb_path: Path
    size: int


@dataclass(frozen=True, slots=True)
class ChromiumLocalStorageRecord:
    storage_key: Any
    script_key: Any
    value: Any
    sequence_number: int
    is_live: bool
    timestamp: datetime | None = None

    @property
    def raw_reference(self) -> str:
        return f"{self.storage_key}#seq={self.sequence_number}"


@dataclass(frozen=True, slots=True)
class ChromiumLocalStorageIssue:
    sequence_number: int | None
    error: str


@dataclass(frozen=True, slots=True)
class ChromiumLocalStorageResult:
    artifact: ChromiumLocalStorageArtifact
    records: tuple[ChromiumLocalStorageRecord, ...]
    issues: tuple[ChromiumLocalStorageIssue, ...] = ()


def _default_reader_factory(leveldb_path: Path) -> Any:
    try:
        from ccl_chromium_reader.ccl_chromium_localstorage import LocalStoreDb
    except ImportError as exc:
        raise ChromiumStorageDependencyError(
            "ccl_chromium_reader is required for Chromium Local Storage parsing. "
            "Install the TraceAgent dependencies and retry."
        ) from exc
    return LocalStoreDb(leveldb_path)


class ChromiumLocalStorageParser:
    """Service-neutral Chromium Local Storage LevelDB parser backed by CCL."""

    def __init__(
        self,
        reader_factory: ReaderFactory | None = None,
        *,
        decode_nested_json: bool = True,
    ) -> None:
        self._reader_factory = reader_factory or _default_reader_factory
        self._decode_nested_json = decode_nested_json

    @staticmethod
    def is_leveldb_directory(path: Path) -> bool:
        return path.is_dir() and (
            (path / "CURRENT").is_file() or any(path.glob("MANIFEST-*"))
        )

    def discover(self, root: Path) -> tuple[ChromiumLocalStorageArtifact, ...]:
        if self.is_leveldb_directory(root):
            return (self._artifact(root),)
        if not root.is_dir():
            return ()

        discovered: list[ChromiumLocalStorageArtifact] = []
        seen: set[Path] = set()
        for current, directories, _files in os.walk(root):
            current_path = Path(current)
            for name in tuple(directories):
                candidate = current_path / name
                if name.lower() != "leveldb" or current_path.name.lower() != "local storage":
                    continue
                directories.remove(name)
                resolved = candidate.resolve()
                if resolved in seen or not self.is_leveldb_directory(candidate):
                    continue
                seen.add(resolved)
                discovered.append(self._artifact(candidate))
        return tuple(discovered)

    def parse(self, artifact: ChromiumLocalStorageArtifact | Path) -> ChromiumLocalStorageResult:
        artifact = self._coerce_artifact(artifact)
        records: list[ChromiumLocalStorageRecord] = []
        issues: list[ChromiumLocalStorageIssue] = []
        database = self._reader_factory(artifact.leveldb_path)
        try:
            try:
                iterator = iter(database.iter_all_records(include_deletions=True))
            except Exception as exc:  # noqa: BLE001 - surface as an issue instead of aborting
                issues.append(ChromiumLocalStorageIssue(None, str(exc)))
                iterator = iter(())

            while True:
                try:
                    record = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:  # noqa: BLE001 - a corrupt record ends iteration; keep what we have
                    issues.append(ChromiumLocalStorageIssue(None, str(exc)))
                    break

                try:
                    find_batch = getattr(database, "find_batch", None)
                    batch = find_batch(record.leveldb_seq_number) if callable(find_batch) else None
                    records.append(
                        ChromiumLocalStorageRecord(
                            storage_key=to_json_safe(
                                record.storage_key,
                                decode_nested_json=self._decode_nested_json,
                            ),
                            script_key=to_json_safe(
                                record.script_key,
                                decode_nested_json=self._decode_nested_json,
                            ),
                            value=to_json_safe(
                                record.value,
                                decode_nested_json=self._decode_nested_json,
                            ),
                            sequence_number=record.leveldb_seq_number,
                            is_live=record.is_live,
                            timestamp=getattr(batch, "timestamp", None),
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - isolate one corrupt record from the rest
                    sequence_number = getattr(record, "leveldb_seq_number", None)
                    issues.append(ChromiumLocalStorageIssue(sequence_number, str(exc)))
        finally:
            close = getattr(database, "close", None)
            if callable(close):
                close()

        records.sort(key=lambda item: item.sequence_number)
        return ChromiumLocalStorageResult(artifact, tuple(records), tuple(issues))

    def _artifact(self, leveldb_path: Path) -> ChromiumLocalStorageArtifact:
        return ChromiumLocalStorageArtifact(
            leveldb_path=leveldb_path,
            size=sum(item.stat().st_size for item in leveldb_path.iterdir() if item.is_file()),
        )

    def _coerce_artifact(
        self,
        artifact: ChromiumLocalStorageArtifact | Path,
    ) -> ChromiumLocalStorageArtifact:
        if isinstance(artifact, ChromiumLocalStorageArtifact):
            return artifact
        if not self.is_leveldb_directory(artifact):
            raise ValueError(f"Not a LevelDB directory: {artifact}")
        return self._artifact(artifact)
