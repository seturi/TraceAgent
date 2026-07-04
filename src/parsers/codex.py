from __future__ import annotations

import gzip
import json
import sqlite3
import zlib
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

import brotli
from ccl_chromium_reader import ccl_chromium_cache

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from version import __version__

_SERVICE_NAME = "Codex Desktop"

_CACHE_GLOB = "**/Packages/OpenAI.Codex_*/LocalCache/Roaming/Codex/web/Codex/Default/Cache/Cache_Data"
_CODEX_HOME_GLOB = "**/.codex"
_LOG_DB_GLOB = "log_*.sqlite"
_STATE_DB_GLOB = "state_*.sqlite"
_SESSIONS_GLOB = "sessions/**/*.jsonl"

_CACHE_ARTIFACT_TYPE = "codex_cache"
_LOG_DB_ARTIFACT_TYPE = "codex_log_db"
_STATE_DB_ARTIFACT_TYPE = "codex_state_db"
_SESSION_ARTIFACT_TYPE = "codex_session_jsonl"

_TIMESTAMP_COLUMN_CANDIDATES = (
    "timestamp", "created_at", "createdat", "updated_at", "updatedat",
    "ts", "time", "started_at", "startedat",
)


def _mtime_fallback(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _decode_body(body: bytes, encoding: str) -> bytes:
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


def _try_parse_json(body: bytes) -> object | None:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _sanitize_payload(payload: dict) -> dict:
    sanitized = dict(payload)
    encrypted_content = sanitized.pop("encrypted_content", None)
    if encrypted_content is not None:
        sanitized["encrypted_content_length"] = (
            len(encrypted_content) if isinstance(encrypted_content, str) else None
        )
    if sanitized.get("type") == "message" and isinstance(sanitized.get("content"), list):
        texts = [
            part.get("text")
            for part in sanitized["content"]
            if isinstance(part, dict) and part.get("text")
        ]
        if texts:
            sanitized["text"] = "\n".join(texts)
    return sanitized


def _derive_actor(record_type: str, payload: dict) -> str | None:
    if record_type == "response_item":
        role = payload.get("role")
        if isinstance(role, str):
            return role
    if record_type == "event_msg":
        sub_type = payload.get("type")
        if sub_type == "user_message":
            return "user"
        if sub_type == "agent_message":
            return "assistant"
    return None


def _guess_timestamp_column(columns: list[str]) -> str | None:
    lowered = {column.lower(): column for column in columns}
    for candidate in _TIMESTAMP_COLUMN_CANDIDATES:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _coerce_timestamp(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**12 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        return _parse_iso(value)
    return None


def _json_safe(value: object) -> object:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return value


class CodexParser(ArtifactParser):
    """Parses Codex Desktop's Chromium cache, sqlite logs/threads, and session JSONL artifacts."""

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="codex.desktop",
            name="Codex",
            category="service",
            version=__version__,
            services=(_SERVICE_NAME,),
            description=(
                "Parses Codex Desktop's Chromium disk cache, .codex sqlite logs/threads tables, "
                "and .codex/sessions JSONL transcripts."
            ),
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        location = source.location
        if not location.exists():
            return 0.0
        has_cache = any(path.is_dir() for path in location.glob(_CACHE_GLOB))
        has_home = any(path.is_dir() for path in location.glob(_CODEX_HOME_GLOB))
        return 0.85 if (has_cache or has_home) else 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        location = source.location
        cache_dirs = tuple(path for path in location.glob(_CACHE_GLOB) if path.is_dir())
        codex_homes = tuple(path for path in location.glob(_CODEX_HOME_GLOB) if path.is_dir())

        records: list[ArtifactRecord] = []
        total = len(cache_dirs) + len(codex_homes) or 1
        scanned = 0

        for cache_dir in cache_dirs:
            if context.cancelled():
                return tuple(records)
            records.append(
                ArtifactRecord(
                    source_id=source.source_id,
                    producer_id=self.metadata.parser_id,
                    path=str(cache_dir),
                    artifact_type=_CACHE_ARTIFACT_TYPE,
                    service=_SERVICE_NAME,
                )
            )
            scanned += 1
            context.progress(int(scanned / total * 100), f"Scanned {cache_dir}")

        for codex_home in codex_homes:
            if context.cancelled():
                return tuple(records)

            for log_db in codex_home.glob(_LOG_DB_GLOB):
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(log_db),
                        artifact_type=_LOG_DB_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            for state_db in codex_home.glob(_STATE_DB_GLOB):
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(state_db),
                        artifact_type=_STATE_DB_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            for session_file in codex_home.glob(_SESSIONS_GLOB):
                if session_file.is_file():
                    records.append(
                        ArtifactRecord(
                            source_id=source.source_id,
                            producer_id=self.metadata.parser_id,
                            path=str(session_file),
                            artifact_type=_SESSION_ARTIFACT_TYPE,
                            service=_SERVICE_NAME,
                        )
                    )

            scanned += 1
            context.progress(int(scanned / total * 100), f"Scanned {codex_home}")

        return tuple(records)

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        artifact_list = tuple(artifacts)
        total = len(artifact_list) or 1
        for index, artifact in enumerate(artifact_list):
            if context.cancelled():
                return

            if artifact.artifact_type == _CACHE_ARTIFACT_TYPE:
                self._parse_cache(source, artifact, emit, context)
            elif artifact.artifact_type == _LOG_DB_ARTIFACT_TYPE:
                self._parse_sqlite_table(source, artifact, "logs", emit, context)
            elif artifact.artifact_type == _STATE_DB_ARTIFACT_TYPE:
                self._parse_sqlite_table(source, artifact, "threads", emit, context)
            elif artifact.artifact_type == _SESSION_ARTIFACT_TYPE:
                self._parse_session_jsonl(source, artifact, emit, context)

            context.progress(int((index + 1) / total * 100), f"Parsed {artifact.path}")

    def _parse_cache(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        cache_dir = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(cache_dir)

        with ccl_chromium_cache.ChromiumSimpleFileCache(cache_dir) as cache:
            for key in cache.keys():
                if context.cancelled():
                    return

                cache_key = ccl_chromium_cache.CacheKey(key)
                if "conversation" not in cache_key.url.lower():
                    continue

                meta = next(iter(cache.get_metadata(key)), None)
                body = next(iter(cache.get_cachefile(key)), b"")
                encoding = (meta.get_attribute("content-encoding") or [""])[0] if meta is not None else ""
                conversation = _try_parse_json(_decode_body(body, encoding))
                if conversation is None:
                    continue

                timestamp = (meta.response_time if meta is not None else None) or fallback_timestamp

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type="codex_cache_conversation",
                        path=cache_key.url,
                        service=_SERVICE_NAME,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("codex_desktop_cache_conversation_url",),
                        raw_reference=artifact.record_id,
                        metadata={"cache_key": key, "conversation": conversation},
                    )
                )

    def _parse_sqlite_table(
        self,
        source: EvidenceSource,
        artifact: ArtifactRecord,
        table_name: str,
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        db_path = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(db_path)

        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(f"SELECT * FROM {table_name}")
            columns = [description[0] for description in cursor.description]
            timestamp_column = _guess_timestamp_column(columns)

            for row in cursor:
                if context.cancelled():
                    return

                row_dict = {column: _json_safe(row[column]) for column in columns}
                timestamp = None
                if timestamp_column is not None:
                    timestamp = _coerce_timestamp(row_dict.get(timestamp_column))
                timestamp = timestamp or fallback_timestamp

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type=f"codex_{table_name}_record",
                        service=_SERVICE_NAME,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=(f"codex_desktop_{table_name}_table",),
                        raw_reference=artifact.record_id,
                        metadata=row_dict,
                    )
                )
        finally:
            connection.close()

    def _parse_session_jsonl(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        session_path = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(session_path)
        current_session_id: str | None = None

        with session_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if context.cancelled():
                    return

                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                record_type = record.get("type", "unknown")
                payload = record.get("payload")
                payload = payload if isinstance(payload, dict) else {}

                if record_type == "session_meta":
                    current_session_id = payload.get("session_id") or current_session_id

                sub_type = payload.get("type") if record_type in ("event_msg", "response_item") else None
                event_type = f"codex_{record_type}.{sub_type}" if sub_type else f"codex_{record_type}"
                timestamp = _parse_iso(record.get("timestamp")) or fallback_timestamp

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type=event_type,
                        service=_SERVICE_NAME,
                        session_id=current_session_id,
                        actor=_derive_actor(record_type, payload),
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("codex_desktop_session_log_path",),
                        raw_reference=artifact.record_id,
                        metadata=_sanitize_payload(payload),
                    )
                )
