from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from ccl_chromium_reader import ccl_chromium_cache, ccl_chromium_localstorage

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers._cache_utils import decode_body, try_parse_json
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from version import __version__

_SERVICE_NAME = "ChatGPT Desktop"
# The app folder under Roaming has been observed as both "ChatGPT" and "ChatGPT-Desktop"
# across versions, so the trailing wildcard matches either.
_PACKAGE_ROOT_GLOB = "**/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT*"
_CACHE_ARTIFACT_TYPE = "chromium_simple_cache"
_LOCAL_STORAGE_ARTIFACT_TYPE = "chromium_local_storage"


def _find_chatgpt_roots(location: Path) -> tuple[Path, ...]:
    if not location.exists():
        return ()
    return tuple(sorted(path for path in location.glob(_PACKAGE_ROOT_GLOB) if path.is_dir()))


def _mtime_fallback(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _from_unix(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _extract_text(content: object) -> str | None:
    if not isinstance(content, dict) or content.get("content_type") != "text":
        return None
    parts = content.get("parts")
    if not isinstance(parts, list):
        return None
    texts = [part for part in parts if isinstance(part, str) and part]
    return "\n".join(texts) if texts else None


def _iter_conversation_messages(conversation: dict):
    mapping = conversation.get("mapping")
    if not isinstance(mapping, dict):
        return
    for node_id, node in mapping.items():
        if not isinstance(node, dict):
            continue
        message = node.get("message")
        if isinstance(message, dict):
            yield node_id, node, message


class ChatGPTParser(ArtifactParser):
    """Parses ChatGPT Desktop's local Chromium cache (conversation JSON) and Local Storage artifacts."""

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="chatgpt.desktop",
            name="ChatGPT",
            category="service",
            version=__version__,
            services=(_SERVICE_NAME,),
            description=(
                "Parses ChatGPT Desktop's Chromium disk cache (extracting cached conversation JSON) "
                "and Local Storage leveldb artifacts."
            ),
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
        cache_class = ccl_chromium_cache.guess_cache_class(cache_dir) or ccl_chromium_cache.ChromiumSimpleFileCache

        with cache_class(cache_dir) as cache:
            for key in cache.keys():
                if context.cancelled():
                    return

                cache_key = ccl_chromium_cache.CacheKey(key)
                if "conversation" not in cache_key.url.lower():
                    continue

                meta = next(iter(cache.get_metadata(key)), None)
                body = next(iter(cache.get_cachefile(key)), b"")
                encoding = (meta.get_attribute("content-encoding") or [""])[0] if meta is not None else ""
                conversation = try_parse_json(decode_body(body, encoding))
                if not isinstance(conversation, dict) or "mapping" not in conversation:
                    continue

                conversation_id = conversation.get("conversation_id")
                base_timestamp = (
                    _from_unix(conversation.get("create_time"))
                    or (meta.response_time if meta is not None else None)
                    or fallback_timestamp
                )

                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=base_timestamp,
                        event_type="chatgpt_conversation",
                        path=cache_key.url,
                        service=_SERVICE_NAME,
                        session_id=conversation_id,
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.85,
                        attribution_reasons=("chatgpt_desktop_cache_conversation_json",),
                        raw_reference=artifact.record_id,
                        metadata={
                            "cache_key": key,
                            "title": conversation.get("title"),
                            "default_model_slug": conversation.get("default_model_slug"),
                            "current_node": conversation.get("current_node"),
                            "create_time": conversation.get("create_time"),
                            "update_time": conversation.get("update_time"),
                            "gizmo_id": conversation.get("gizmo_id"),
                            "is_archived": conversation.get("is_archived"),
                        },
                    )
                )

                for node_id, node, message in _iter_conversation_messages(conversation):
                    if context.cancelled():
                        return

                    author = message.get("author") if isinstance(message.get("author"), dict) else {}
                    content = message.get("content") if isinstance(message.get("content"), dict) else {}
                    message_metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
                    text = _extract_text(content)
                    message_timestamp = _from_unix(message.get("create_time")) or base_timestamp

                    emit(
                        NormalizedEvent(
                            source_id=source.source_id,
                            parser_id=self.metadata.parser_id,
                            timestamp=message_timestamp,
                            event_type="chatgpt_conversation_message",
                            path=cache_key.url,
                            service=_SERVICE_NAME,
                            session_id=conversation_id,
                            actor=author.get("role"),
                            attribution=AgentAttribution.HIGH,
                            attribution_score=0.85,
                            attribution_reasons=("chatgpt_desktop_cache_conversation_json",),
                            raw_reference=artifact.record_id,
                            metadata={
                                "cache_key": key,
                                "message_id": node_id,
                                "parent_id": node.get("parent"),
                                "author_role": author.get("role"),
                                "author_name": author.get("name"),
                                "channel": message.get("channel"),
                                "recipient": message.get("recipient"),
                                "status": message.get("status"),
                                "end_turn": message.get("end_turn"),
                                "content_type": content.get("content_type"),
                                "text": text,
                                "content": content if text is None else None,
                                "model_slug": message_metadata.get("model_slug"),
                                "finish_details": message_metadata.get("finish_details"),
                            },
                        )
                    )
