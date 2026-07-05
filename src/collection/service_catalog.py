from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from core.models import SourceKind
from utils.evidence_access import EvidenceAccessor, EvidenceEntry, EvidenceUserHome


@dataclass(frozen=True, slots=True)
class ServiceArtifactSpec:
    service: str
    artifact_type: str
    user_patterns: tuple[str, ...]
    extracted_patterns: tuple[str, ...] = ()
    exclude_contains: tuple[str, ...] = ()
    include_file_patterns: tuple[str, ...] = ("**/*", "*")

    def patterns_for(self, source_kind: SourceKind) -> tuple[str, ...]:
        if source_kind == SourceKind.ARTIFACT_DIRECTORY and self.extracted_patterns:
            return self.extracted_patterns
        return self.user_patterns


@dataclass(frozen=True, slots=True)
class DetectedArtifactRoot:
    service: str
    artifact_type: str
    user: EvidenceUserHome
    entry: EvidenceEntry
    include_file_patterns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceDetection:
    service: str
    present: bool
    roots: tuple[DetectedArtifactRoot, ...]


SERVICE_NAMES = (
    "Claude Cowork",
    "Claude Code",
    "ChatGPT Desktop",
    "Antigravity",
    "Codex",
)

_COMPOUND_ARTIFACT_TYPES = {"indexeddb", "local_storage", "cache_data"}


SERVICE_ARTIFACT_SPECS = (
    ServiceArtifactSpec(
        "Claude Cowork",
        "application_logs",
        ("AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/logs",),
        ("**/LocalCache/Roaming/Claude/logs",),
        include_file_patterns=("*.log", "**/*.log"),
    ),
    ServiceArtifactSpec(
        "Claude Cowork",
        "indexeddb",
        (
            "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.indexeddb.leveldb",
        ),
        ("**/LocalCache/Roaming/Claude/IndexedDB/*.indexeddb.leveldb",),
    ),
    ServiceArtifactSpec(
        "Claude Cowork",
        "agent_sessions",
        ("AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions",),
        ("**/LocalCache/Roaming/Claude/local-agent-mode-sessions",),
        include_file_patterns=(
            "**/audit.jsonl",
            "local_*.json",
            "**/.claude/projects/**/*.jsonl",
            "**/outputs/*",
            "**/outputs/**/*",
        ),
    ),
    ServiceArtifactSpec(
        "Claude Cowork",
        "mcp_logs",
        (
            "AppData/Local/Packages/Claude_*/LocalCache/Local/claude-cli-nodejs/Cache/**/mcp-logs-*",
        ),
        ("**/LocalCache/Local/claude-cli-nodejs/Cache/**/mcp-logs-*",),
        include_file_patterns=("*.jsonl", "**/*.jsonl"),
    ),
    ServiceArtifactSpec(
        "Claude Code",
        "project_sessions",
        (".claude/projects",),
        ("**/.claude/projects",),
        exclude_contains=("/local-agent-mode-sessions/",),
        include_file_patterns=("*.jsonl", "**/*.jsonl"),
    ),
    ServiceArtifactSpec(
        "Claude Code",
        "desktop_session_metadata",
        ("AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions",),
        ("**/LocalCache/Roaming/Claude/claude-code-sessions",),
        include_file_patterns=("*.json", "**/*.json"),
    ),
    ServiceArtifactSpec(
        "Claude Code",
        "application_logs",
        ("AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/logs",),
        ("**/LocalCache/Roaming/Claude/logs",),
        include_file_patterns=("main.log",),
    ),
    ServiceArtifactSpec(
        "ChatGPT Desktop",
        "local_storage",
        (
            "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT-Desktop/Local Storage/leveldb",
            "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT/Local Storage/leveldb",
        ),
        (
            "**/LocalCache/Roaming/ChatGPT-Desktop/Local Storage/leveldb",
            "**/LocalCache/Roaming/ChatGPT/Local Storage/leveldb",
        ),
    ),
    ServiceArtifactSpec(
        "ChatGPT Desktop",
        "cache_data",
        (
            "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT-Desktop/Cache/Cache_Data",
            "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_*/LocalCache/Roaming/ChatGPT/Cache/Cache_Data",
        ),
        (
            "**/LocalCache/Roaming/ChatGPT-Desktop/Cache/Cache_Data",
            "**/LocalCache/Roaming/ChatGPT/Cache/Cache_Data",
        ),
    ),
    ServiceArtifactSpec(
        "Antigravity",
        "brain_transcripts",
        (".gemini/antigravity/brain",),
        ("**/antigravity/brain",),
        include_file_patterns=(
            "**/logs/transcript*.jsonl",
            "**/messages/*.json",
        ),
    ),
    ServiceArtifactSpec(
        "Antigravity",
        "conversation_databases",
        (".gemini/antigravity/conversations",),
        ("**/antigravity/conversations",),
        include_file_patterns=("*.db", "**/*.db"),
    ),
    ServiceArtifactSpec(
        "Antigravity",
        "scratch_artifacts",
        (".gemini/antigravity/scratch",),
        ("**/antigravity/scratch",),
        include_file_patterns=("*", "**/*"),
    ),
    ServiceArtifactSpec(
        "Antigravity",
        "annotations",
        (".gemini/antigravity/annotations",),
        ("**/antigravity/annotations",),
        include_file_patterns=("*.pbtxt", "**/*.pbtxt"),
    ),
    ServiceArtifactSpec(
        "Antigravity",
        "application_state",
        (".gemini/antigravity/antigravity_state.pbtxt",),
        ("**/antigravity/antigravity_state.pbtxt",),
    ),
    ServiceArtifactSpec(
        "Codex",
        "session_logs",
        (".codex/sessions", ".codex/archived_sessions"),
        ("**/.codex/sessions", "**/.codex/archived_sessions"),
        include_file_patterns=("*.jsonl", "**/*.jsonl"),
    ),
    ServiceArtifactSpec(
        "Codex",
        "history",
        (".codex/history.jsonl",),
        ("**/.codex/history.jsonl",),
    ),
    ServiceArtifactSpec(
        "Codex",
        "state_database",
        (".codex/state*.sqlite",),
        ("**/.codex/state*.sqlite",),
    ),
    ServiceArtifactSpec(
        "Codex",
        "application_logs",
        (".codex/log",),
        ("**/.codex/log",),
        include_file_patterns=("*.log", "**/*.log"),
    ),
)


def detect_service_artifacts(accessor: EvidenceAccessor) -> tuple[ServiceDetection, ...]:
    roots_by_service: dict[str, list[DetectedArtifactRoot]] = {
        service: [] for service in SERVICE_NAMES
    }
    seen: set[tuple[str, str, str]] = set()

    for home in accessor.user_homes():
        for spec in SERVICE_ARTIFACT_SPECS:
            for pattern in spec.patterns_for(accessor.source.kind):
                for entry in accessor.glob(home, pattern):
                    normalized_path = entry.path.replace("\\", "/").lower()
                    if any(value.lower() in normalized_path for value in spec.exclude_contains):
                        continue
                    identity = (spec.service, spec.artifact_type, entry.path.lower())
                    if identity in seen:
                        continue
                    seen.add(identity)
                    roots_by_service[spec.service].append(
                        DetectedArtifactRoot(
                            spec.service,
                            spec.artifact_type,
                            home,
                            entry,
                            spec.include_file_patterns,
                        )
                    )

    # A previously collected TraceAgent artifacts directory uses compact file
    # names instead of the original application paths. Recover its service and
    # artifact-type mapping from the collection manifests so it can be loaded as
    # an evidence source, collected into a new case, and parsed normally.
    if accessor.source.kind == SourceKind.ARTIFACT_DIRECTORY:
        for root in _manifest_artifact_roots(accessor):
            identity = (root.service, root.artifact_type, root.entry.path.lower())
            if identity in seen:
                continue
            seen.add(identity)
            roots_by_service[root.service].append(root)

    return tuple(
        ServiceDetection(service, bool(roots_by_service[service]), tuple(roots_by_service[service]))
        for service in SERVICE_NAMES
    )


def _manifest_artifact_roots(accessor: EvidenceAccessor) -> tuple[DetectedArtifactRoot, ...]:
    source_root = accessor.source.location
    homes = accessor.user_homes()
    if not homes or not source_root.is_dir():
        return ()
    home = homes[0]
    roots: list[DetectedArtifactRoot] = []
    seen: set[tuple[str, str, Path]] = set()

    try:
        manifests = tuple(source_root.rglob("collection_manifest.jsonl"))
    except OSError:
        return ()

    for manifest in manifests:
        if not manifest.is_file() or manifest.is_symlink():
            continue
        try:
            lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                item = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict):
                continue
            service = item.get("service")
            artifact_type = item.get("artifact_type")
            collected_path = item.get("collected_path")
            if (
                service not in SERVICE_NAMES
                or not isinstance(artifact_type, str)
                or not isinstance(collected_path, str)
            ):
                continue
            relative = PurePosixPath(collected_path.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                continue
            parts = relative.parts
            service_relative = parts[1:] if parts[0].lower() == manifest.parent.name.lower() else parts
            if not service_relative:
                continue
            if artifact_type in _COMPOUND_ARTIFACT_TYPES:
                candidate = manifest.parent / service_relative[0]
            else:
                candidate = manifest.parent.joinpath(*service_relative)
            entry = _local_entry_within(candidate, source_root)
            if entry is None:
                continue
            identity = (service, artifact_type, candidate.resolve())
            if identity in seen:
                continue
            seen.add(identity)
            roots.append(
                DetectedArtifactRoot(
                    service=service,
                    artifact_type=artifact_type,
                    user=home,
                    entry=entry,
                    include_file_patterns=("**/*", "*"),
                )
            )
    return tuple(roots)


def _local_entry_within(path: Path, source_root: Path) -> EvidenceEntry | None:
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve()
        if not resolved.is_relative_to(source_root.resolve()):
            return None
        stat = resolved.stat()
        is_file = resolved.is_file()
        is_dir = resolved.is_dir()
    except OSError:
        return None
    if not (is_file or is_dir):
        return None
    return EvidenceEntry(
        path=str(resolved),
        name=resolved.name,
        is_file=is_file,
        is_dir=is_dir,
        size=stat.st_size if is_file else None,
        modified_time=stat.st_mtime,
        handle=resolved,
    )
