from __future__ import annotations

import gzip
import json
import zlib
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import brotli

from utils.chromium_indexeddb import ChromiumStorageDependencyError

ReaderFactory = Callable[[Path], Any]
CacheKeyFactory = Callable[[Any], Any]
CancelCheck = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class ChromiumCacheArtifact:
    cache_path: Path
    size: int


@dataclass(frozen=True, slots=True)
class ChromiumCacheRecord:
    key: str
    url: str
    request_time: datetime | None
    response_time: datetime | None
    headers: dict[str, tuple[str, ...]]
    body: bytes

    @property
    def content_encoding(self) -> str:
        values = self.headers.get("content-encoding", ())
        return values[0] if values else ""

    @property
    def raw_reference(self) -> str:
        return self.key


@dataclass(frozen=True, slots=True)
class ChromiumCacheIssue:
    key: str
    error: str


@dataclass(frozen=True, slots=True)
class ChromiumCacheResult:
    artifact: ChromiumCacheArtifact
    records: tuple[ChromiumCacheRecord, ...]
    issues: tuple[ChromiumCacheIssue, ...] = ()


def _default_reader_factory(cache_path: Path) -> Any:
    try:
        from ccl_chromium_reader import ccl_chromium_cache
    except ImportError as exc:
        raise ChromiumStorageDependencyError(
            "ccl_chromium_reader is required for Chromium cache parsing. "
            "Install the TraceAgent dependencies and retry."
        ) from exc
    cache_class = (
        ccl_chromium_cache.guess_cache_class(cache_path)
        or ccl_chromium_cache.ChromiumSimpleFileCache
    )
    return cache_class(cache_path)


def _default_cache_key_factory(key: Any) -> Any:
    try:
        from ccl_chromium_reader.ccl_chromium_cache import CacheKey
    except ImportError as exc:
        raise ChromiumStorageDependencyError(
            "ccl_chromium_reader is required for Chromium cache parsing."
        ) from exc
    return CacheKey(key)


def decode_body(body: bytes, encoding: str) -> bytes:
    """Decode a Chromium cache response body from its content encoding."""
    encoding = encoding.strip().lower()
    if not body or not encoding:
        return body
    if encoding == "gzip":
        try:
            return gzip.decompress(body)
        except (EOFError, gzip.BadGzipFile):
            return body
    if encoding == "br":
        try:
            return brotli.decompress(body)
        except brotli.error:
            return body
    if encoding == "deflate":
        try:
            return zlib.decompress(body, -zlib.MAX_WBITS)
        except zlib.error:
            return body
    return body


def try_parse_json(body: bytes) -> object | None:
    """Return a decoded JSON cache body, or None when it is not valid JSON."""
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


class ChromiumCacheParser:
    """Service-neutral Chromium Simple Cache parser backed by CCL."""

    def __init__(
        self,
        reader_factory: ReaderFactory | None = None,
        cache_key_factory: CacheKeyFactory | None = None,
    ) -> None:
        self._reader_factory = reader_factory or _default_reader_factory
        self._cache_key_factory = cache_key_factory or _default_cache_key_factory

    @staticmethod
    def is_cache_directory(path: Path) -> bool:
        return path.is_dir()

    def discover(self, root: Path) -> tuple[ChromiumCacheArtifact, ...]:
        if not root.is_dir():
            return ()
        if root.name.lower() == "cache_data":
            return (self._artifact(root),)
        return tuple(
            self._artifact(path)
            for path in sorted(root.rglob("Cache_Data"))
            if path.is_dir()
        )

    def parse(
        self,
        artifact: ChromiumCacheArtifact | Path,
        *,
        include_body: bool = True,
        cancelled: CancelCheck | None = None,
    ) -> ChromiumCacheResult:
        artifact = self._coerce_artifact(artifact)
        records: list[ChromiumCacheRecord] = []
        issues: list[ChromiumCacheIssue] = []

        with ExitStack() as stack:
            reader = self._reader_factory(artifact.cache_path)
            if hasattr(reader, "__enter__") and hasattr(reader, "__exit__"):
                cache = stack.enter_context(reader)
            else:
                cache = reader
                close = getattr(reader, "close", None)
                if callable(close):
                    stack.callback(close)

            for key in cache.keys():
                if cancelled is not None and cancelled():
                    break
                try:
                    cache_key = self._cache_key_factory(key)
                    metadata = next(iter(cache.get_metadata(key)), None)
                    headers: dict[str, list[str]] = {}
                    if metadata is not None:
                        for name, value in metadata.http_header_attributes:
                            headers.setdefault(name.lower(), []).append(value)
                    body = next(iter(cache.get_cachefile(key)), b"") if include_body else b""
                except Exception as exc:  # noqa: BLE001 - isolate one corrupt entry from the rest
                    issues.append(ChromiumCacheIssue(key=str(key), error=str(exc)))
                    continue
                records.append(
                    ChromiumCacheRecord(
                        key=str(key),
                        url=cache_key.url,
                        request_time=getattr(metadata, "request_time", None),
                        response_time=getattr(metadata, "response_time", None),
                        headers={name: tuple(values) for name, values in headers.items()},
                        body=body,
                    )
                )

        return ChromiumCacheResult(artifact, tuple(records), tuple(issues))

    def _artifact(self, cache_path: Path) -> ChromiumCacheArtifact:
        return ChromiumCacheArtifact(
            cache_path=cache_path,
            size=sum(path.stat().st_size for path in cache_path.rglob("*") if path.is_file()),
        )

    def _coerce_artifact(self, artifact: ChromiumCacheArtifact | Path) -> ChromiumCacheArtifact:
        if isinstance(artifact, ChromiumCacheArtifact):
            return artifact
        if not self.is_cache_directory(artifact):
            raise ValueError(f"Not a Chromium cache directory: {artifact}")
        return self._artifact(artifact)
