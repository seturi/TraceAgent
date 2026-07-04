from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEVELDB_SUFFIX = ".indexeddb.leveldb"
ReaderFactory = Callable[[Path, Path | None], Any]


class ChromiumStorageDependencyError(RuntimeError):
    """Raised when a required CCL Chromium reader cannot be imported."""


@dataclass(frozen=True, slots=True)
class ChromiumIndexedDbArtifact:
    leveldb_path: Path
    blob_path: Path | None
    size: int


@dataclass(frozen=True, slots=True)
class ChromiumIndexedDbRecord:
    database_id: int | None
    database_name: str | None
    database_origin: str | None
    object_store_id: int | None
    object_store_name: str
    key: Any
    value: Any
    is_live: bool
    sequence_number: int | None
    origin_file: Path
    external_value_path: Path | None = None

    @property
    def raw_reference(self) -> str:
        return f"{self.origin_file}#seq={self.sequence_number}"


@dataclass(frozen=True, slots=True)
class ChromiumIndexedDbIssue:
    database_id: int | None
    database_name: str | None
    object_store_name: str
    key: Any
    raw_size: int


@dataclass(frozen=True, slots=True)
class ChromiumIndexedDbResult:
    artifact: ChromiumIndexedDbArtifact
    records: tuple[ChromiumIndexedDbRecord, ...]
    issues: tuple[ChromiumIndexedDbIssue, ...]


def _default_reader_factory(leveldb_path: Path, blob_path: Path | None) -> Any:
    try:
        from ccl_chromium_reader import ccl_chromium_indexeddb
    except ImportError as exc:
        raise ChromiumStorageDependencyError(
            "ccl_chromium_reader is required for Chromium IndexedDB parsing. "
            "Install the TraceAgent dependencies and retry."
        ) from exc

    return ccl_chromium_indexeddb.WrappedIndexDB(
        str(leveldb_path),
        str(blob_path) if blob_path is not None else None,
    )


class ChromiumIndexedDbParser:
    """Service-neutral Chromium IndexedDB/LevelDB parser backed by CCL."""

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
        if not path.is_dir() or not path.name.endswith(LEVELDB_SUFFIX):
            return False
        return (path / "CURRENT").is_file() or any(path.glob("MANIFEST-*"))

    @staticmethod
    def find_blob_directory(leveldb_path: Path) -> Path | None:
        if not leveldb_path.name.endswith(LEVELDB_SUFFIX):
            return None
        stem = leveldb_path.name[: -len(LEVELDB_SUFFIX)]
        candidate = leveldb_path.with_name(f"{stem}.indexeddb.blob")
        return candidate if candidate.is_dir() else None

    def discover(self, root: Path) -> tuple[ChromiumIndexedDbArtifact, ...]:
        if self.is_leveldb_directory(root):
            return (self._artifact(root),)
        if not root.is_dir():
            return ()

        discovered: list[ChromiumIndexedDbArtifact] = []
        seen: set[Path] = set()
        for current, directories, _files in os.walk(root):
            current_path = Path(current)
            for name in tuple(directories):
                if not name.endswith(LEVELDB_SUFFIX):
                    continue
                directories.remove(name)
                candidate = current_path / name
                resolved = candidate.resolve()
                if resolved in seen or not self.is_leveldb_directory(candidate):
                    continue
                seen.add(resolved)
                discovered.append(self._artifact(candidate))
        return tuple(discovered)

    def parse(
        self,
        artifact: ChromiumIndexedDbArtifact | Path,
        *,
        database_names: Iterable[str] | None = None,
        object_store_names: Iterable[str] | None = None,
    ) -> ChromiumIndexedDbResult:
        artifact = self._coerce_artifact(artifact)
        database_filter = set(database_names) if database_names is not None else None
        store_filter = set(object_store_names) if object_store_names is not None else None
        records: list[ChromiumIndexedDbRecord] = []
        issues: list[ChromiumIndexedDbIssue] = []

        wrapper = self._reader_factory(artifact.leveldb_path, artifact.blob_path)
        try:
            for database_id in wrapper.database_ids:
                database = wrapper[database_id]
                database_name = getattr(database, "name", None)
                if database_filter is not None and database_name not in database_filter:
                    continue
                for store_name in database.object_store_names:
                    if store_filter is not None and store_name not in store_filter:
                        continue
                    store = database[store_name]

                    def bad_record_handler(key: Any, raw_value: bytes) -> None:
                        issues.append(
                            ChromiumIndexedDbIssue(
                                database_id=getattr(database, "db_number", None),
                                database_name=database_name,
                                object_store_name=store_name,
                                key=self._safe_value(key),
                                raw_size=len(raw_value),
                            )
                        )

                    for record in store.iterate_records(
                        live_only=False,
                        errors_to_stdout=False,
                        bad_deserializer_data_handler=bad_record_handler,
                    ):
                        records.append(self._convert_record(database, store, store_name, record))
        finally:
            close = getattr(wrapper, "close", None)
            if callable(close):
                close()

        records.sort(
            key=lambda item: (
                item.sequence_number is None,
                item.sequence_number or 0,
                str(item.origin_file),
            )
        )
        return ChromiumIndexedDbResult(artifact, tuple(records), tuple(issues))

    def _artifact(self, leveldb_path: Path) -> ChromiumIndexedDbArtifact:
        size = sum(item.stat().st_size for item in leveldb_path.iterdir() if item.is_file())
        return ChromiumIndexedDbArtifact(
            leveldb_path=leveldb_path,
            blob_path=self.find_blob_directory(leveldb_path),
            size=size,
        )

    def _coerce_artifact(self, artifact: ChromiumIndexedDbArtifact | Path) -> ChromiumIndexedDbArtifact:
        if isinstance(artifact, ChromiumIndexedDbArtifact):
            return artifact
        if not self.is_leveldb_directory(artifact):
            raise ValueError(f"Not a Chromium IndexedDB LevelDB directory: {artifact}")
        return self._artifact(artifact)

    def _convert_record(
        self,
        database: Any,
        store: Any,
        store_name: str,
        record: Any,
    ) -> ChromiumIndexedDbRecord:
        key_object = getattr(record, "key", None)
        key = self._safe_value(getattr(key_object, "value", key_object))
        return ChromiumIndexedDbRecord(
            database_id=getattr(database, "db_number", None),
            database_name=getattr(database, "name", None),
            database_origin=getattr(database, "origin", None),
            object_store_id=getattr(store, "object_store_id", None),
            object_store_name=store_name,
            key=key,
            value=self._safe_value(getattr(record, "value", None)),
            is_live=bool(getattr(record, "is_live", False)),
            sequence_number=getattr(record, "ldb_seq_no", None),
            origin_file=Path(getattr(record, "origin_file", "")),
            external_value_path=(
                Path(record.external_value_path)
                if getattr(record, "external_value_path", None)
                else None
            ),
        )

    def _safe_value(self, value: Any) -> Any:
        return to_json_safe(value, decode_nested_json=self._decode_nested_json)


def to_json_safe(value: Any, *, decode_nested_json: bool = True) -> Any:
    """Convert CCL Blink/V8 values into stable Python JSON-compatible values."""
    if isinstance(value, str):
        candidate: Any = value
        if decode_nested_json:
            for _ in range(8):
                if not isinstance(candidate, str):
                    break
                try:
                    decoded = json.loads(candidate)
                except (json.JSONDecodeError, TypeError):
                    break
                if decoded == candidate:
                    break
                candidate = decoded
        if candidate is not value:
            return to_json_safe(candidate, decode_nested_json=decode_nested_json)
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, bytes):
        return {"encoding": "hex", "data": value.hex()}
    if isinstance(value, Mapping):
        return {
            str(key): to_json_safe(item, decode_nested_json=decode_nested_json)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [to_json_safe(item, decode_nested_json=decode_nested_json) for item in value]

    wrapped_value = getattr(value, "value", value)
    if wrapped_value is not value:
        return to_json_safe(wrapped_value, decode_nested_json=decode_nested_json)
    return str(value)
