from __future__ import annotations

from dataclasses import dataclass

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

    return tuple(
        ServiceDetection(service, bool(roots_by_service[service]), tuple(roots_by_service[service]))
        for service in SERVICE_NAMES
    )
