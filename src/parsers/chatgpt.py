from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from core.models import AgentAttribution, ArtifactRecord, EvidenceSource, NormalizedEvent
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from utils.chromium_cache import ChromiumCacheParser, decode_body, try_parse_json
from utils.chromium_localstorage import ChromiumLocalStorageParser
from utils.structured_data import load_collection_manifest
from version import __version__

_SERVICE_NAME = "ChatGPT Desktop"
_PACKAGE_ROOT_GLOBS = (
    "**/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT-Desktop",
    "**/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT",
)
_CACHE_ARTIFACT_TYPE = "chromium_simple_cache"
_LOCAL_STORAGE_ARTIFACT_TYPE = "chromium_local_storage"


def _find_chatgpt_roots(location: Path) -> tuple[Path, ...]:
    if not location.exists():
        return ()
    roots: set[Path] = set()

    # The source may already point straight at the ChatGPT-Desktop root itself
    # (e.g. after a manual extraction that dropped the Packages/... ancestry).
    if (location / "Cache" / "Cache_Data").is_dir() or (location / "Local Storage" / "leveldb").is_dir():
        roots.add(location)

    # Or straight at one of the artifact folders themselves (e.g. the leveldb
    # directory was pasted in directly) — walk back up to the root in that case.
    if location.name.lower() == "leveldb" and location.parent.name.lower() == "local storage":
        roots.add(location.parent.parent)
    if location.name.lower() == "cache_data" and location.parent.name.lower() == "cache":
        roots.add(location.parent.parent)

    roots.update(
        path
        for pattern in _PACKAGE_ROOT_GLOBS
        for path in location.glob(pattern)
        if path.is_dir()
    )

    return tuple(sorted(roots))


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

    def __init__(
        self,
        *,
        cache_parser: ChromiumCacheParser | None = None,
        local_storage_parser: ChromiumLocalStorageParser | None = None,
    ) -> None:
        self._cache_parser = cache_parser or ChromiumCacheParser()
        self._local_storage_parser = local_storage_parser or ChromiumLocalStorageParser()

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
        compact = source.location / "ChatGPT_Desktop"
        if compact.is_dir() and (
            any(compact.glob("cache_data__*"))
            or any(compact.glob("local_storage__*"))
        ):
            return 0.85
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

        compact = source.location / "ChatGPT_Desktop"
        if compact.is_dir():
            manifest = load_collection_manifest(compact)
            compact_artifacts = (
                ("cache_data__*", _CACHE_ARTIFACT_TYPE),
                ("local_storage__*", _LOCAL_STORAGE_ARTIFACT_TYPE),
            )
            for pattern, artifact_type in compact_artifacts:
                for path in compact.glob(pattern):
                    if not path.is_dir():
                        continue
                    entry = manifest.get(str(path.resolve()).lower(), {})
                    records.append(
                        ArtifactRecord(
                            source_id=source.source_id,
                            producer_id=self.metadata.parser_id,
                            path=str(path),
                            artifact_type=artifact_type,
                            service=_SERVICE_NAME,
                            original_path=(
                                str(entry.get("original_path"))
                                if entry.get("original_path")
                                else None
                            ),
                            metadata=entry,
                        )
                    )

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

            try:
                if artifact.artifact_type == _LOCAL_STORAGE_ARTIFACT_TYPE:
                    self._parse_local_storage(source, artifact, emit, context)
                elif artifact.artifact_type == _CACHE_ARTIFACT_TYPE:
                    self._parse_cache(source, artifact, emit, context)
            except Exception as exc:  # noqa: BLE001 - one bad artifact must not sink the rest
                context.options.setdefault("chatgpt_errors", []).append(
                    f"{artifact.path}: {exc}"
                )

            context.progress(int((index + 1) / total * 100), f"Parsed {artifact.path}")

    def _parse_local_storage(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        leveldb_dir = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(leveldb_dir)

        result = self._local_storage_parser.parse(leveldb_dir)
        if result.issues:
            context.options.setdefault("chatgpt_local_storage_issues", []).extend(result.issues)
        for record in result.records:
            if context.cancelled():
                return
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=record.timestamp or fallback_timestamp,
                    event_type="chatgpt_local_storage_record",
                    service=_SERVICE_NAME,
                    attribution=AgentAttribution.HIGH,
                    attribution_score=0.8,
                    attribution_reasons=("chatgpt_desktop_local_storage_path",),
                    raw_reference=f"{artifact.record_id}:{record.raw_reference}",
                    metadata={
                        "storage_key": record.storage_key,
                        "script_key": record.script_key,
                        "value": record.value,
                        "leveldb_seq_number": record.sequence_number,
                        "is_live": record.is_live,
                    },
                )
            )

    def _parse_cache(
        self, source: EvidenceSource, artifact: ArtifactRecord, emit: EventSink, context: ParseContext
    ) -> None:
        cache_dir = Path(artifact.path)
        fallback_timestamp = _mtime_fallback(cache_dir)
        result = self._cache_parser.parse(
            cache_dir,
            include_body=True,
            cancelled=context.cancelled,
        )
        if result.issues:
            context.options.setdefault("chatgpt_cache_issues", []).extend(result.issues)
        for record in result.records:
            if "conversation" not in record.url.lower():
                continue
            conversation = try_parse_json(decode_body(record.body, record.content_encoding))
            if not isinstance(conversation, dict) or "mapping" not in conversation:
                continue

            conversation_id = conversation.get("conversation_id")
            base_timestamp = (
                _from_unix(conversation.get("create_time"))
                or record.response_time
                or fallback_timestamp
            )
            emit(
                NormalizedEvent(
                    source_id=source.source_id,
                    parser_id=self.metadata.parser_id,
                    timestamp=base_timestamp,
                    event_type="chatgpt_conversation",
                    path=record.url,
                    service=_SERVICE_NAME,
                    session_id=conversation_id,
                    attribution=AgentAttribution.HIGH,
                    attribution_score=0.85,
                    attribution_reasons=("chatgpt_desktop_cache_conversation_json",),
                    raw_reference=f"{artifact.record_id}:{record.raw_reference}",
                    metadata={
                        "cache_key": record.key,
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
                message_metadata = (
                    message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
                )
                text = _extract_text(content)
                message_timestamp = _from_unix(message.get("create_time")) or base_timestamp
                emit(
                    NormalizedEvent(
                        source_id=source.source_id,
                        parser_id=self.metadata.parser_id,
                        timestamp=message_timestamp,
                        event_type="chatgpt_conversation_message",
                        path=record.url,
                        service=_SERVICE_NAME,
                        session_id=conversation_id,
                        actor=author.get("role"),
                        attribution=AgentAttribution.HIGH,
                        attribution_score=0.85,
                        attribution_reasons=("chatgpt_desktop_cache_conversation_json",),
                        raw_reference=f"{artifact.record_id}:{record.raw_reference}",
                        metadata={
                            "cache_key": record.key,
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
