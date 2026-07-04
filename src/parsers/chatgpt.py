from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from ccl_chromium_reader import ccl_chromium_cache, ccl_chromium_localstorage

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from version import __version__

_SERVICE_NAME = "ChatGPT Desktop"
_PACKAGE_ROOT_GLOB = "**/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT"
_CACHE_ARTIFACT_TYPE = "chromium_simple_cache"
_LOCAL_STORAGE_ARTIFACT_TYPE = "chromium_local_storage"


def _find_chatgpt_roots(location: Path) -> tuple[Path, ...]:
    if not location.exists():
        return ()
    return tuple(sorted(path for path in location.glob(_PACKAGE_ROOT_GLOB) if path.is_dir()))


def _mtime_fallback(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


class ChatGPTParser(ArtifactParser):
    """Parses ChatGPT Desktop's local Chromium cache and Local Storage artifacts."""

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="chatgpt.desktop",
            name="ChatGPT",
            category="service",
            version=__version__,
            services=(_SERVICE_NAME,),
            description="Parses ChatGPT Desktop's Chromium disk cache and Local Storage leveldb artifacts.",
            implementation_status="ready",
        )

    def probe(self, source: EvidenceSource) -> float:
        roots = _find_chatgpt_roots(source.location)
        if not roots:
            return 0.0
        for root in roots:
            if (root / "Cache" / "Cache_Data").is_dir() or (root / "Local Storage" / "leveldb").is_dir():
                return 0.85
        return 0.3

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        roots = _find_chatgpt_roots(source.location)
        records: list[ArtifactRecord] = []
        total = len(roots) or 1
        for index, root in enumerate(roots):
            if context.cancelled():
                break

            cache_dir = root / "Cache" / "Cache_Data"
            if cache_dir.is_dir():
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(cache_dir),
                        artifact_type=_CACHE_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            leveldb_dir = root / "Local Storage" / "leveldb"
            if leveldb_dir.is_dir():
                records.append(
                    ArtifactRecord(
                        source_id=source.source_id,
                        producer_id=self.metadata.parser_id,
                        path=str(leveldb_dir),
                        artifact_type=_LOCAL_STORAGE_ARTIFACT_TYPE,
                        service=_SERVICE_NAME,
                    )
                )

            context.progress(int((index + 1) / total * 100), f"Scanned {root}")

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

            if artifact.artifact_type == _LOCAL_STORAGE_ARTIFACT_TYPE:
                self._parse_local_storage(source, artifact, emit, context)
            elif artifact.artifact_type == _CACHE_ARTIFACT_TYPE:
                self._parse_cache(source, artifact, emit, context)

            context.progress(int((index + 1) / total * 100), f"Parsed {artifact.path}")

    def _parse_local_storage(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        leveldb_dir = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(leveldb_dir)

        with ccl_chromium_localstorage.LocalStoreDb(leveldb_dir) as local_storage:
            for record in local_storage.iter_all_records():
                if context.cancelled():
                    return

                batch = local_storage.find_batch(record.leveldb_seq_number)
                timestamp = batch.timestamp if batch is not None else fallback_timestamp

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type="chatgpt_local_storage_record",
                        service=_SERVICE_NAME,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("chatgpt_desktop_local_storage_path",),
                        raw_reference=artifact.record_id,
                        metadata={
                            "storage_key": record.storage_key,
                            "script_key": record.script_key,
                            "value": record.value,
                            "leveldb_seq_number": record.leveldb_seq_number,
                        },
                    )
                )

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
                meta = next(iter(cache.get_metadata(key)), None)
                timestamp = (meta.response_time if meta is not None else None) or fallback_timestamp

                headers: dict[str, list[str]] = {}
                if meta is not None:
                    for header_name, header_value in meta.http_header_attributes:
                        headers.setdefault(header_name, []).append(header_value)

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=timestamp,
                        event_type="chatgpt_cache_entry",
                        path=cache_key.url,
                        service=_SERVICE_NAME,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.8,
                        attribution_reasons=("chatgpt_desktop_cache_path",),
                        raw_reference=artifact.record_id,
                        metadata={
                            "cache_key": key,
                            "request_time": (
                                meta.request_time.isoformat() if meta is not None and meta.request_time else None
                            ),
                            "http_headers": headers,
                        },
                    )
                )
