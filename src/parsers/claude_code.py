from __future__ import annotations

from collections.abc import Iterable

from core.models import ArtifactRecord, EvidenceSource
from parsers.base import ArtifactParser, EventSink, ParseContext, ParserMetadata
from version import __version__


class ClaudeCodeParser(ArtifactParser):
    """Example Claude Code parser wired into TraceAgent without real parsing yet."""

    @property
    def metadata(self) -> ParserMetadata:
        return ParserMetadata(
            parser_id="claude_code.placeholder",
            name="Claude Code",
            category="service",
            version=__version__,
            services=("Claude Code",),
            description="Placeholder module for Claude Code JSONL session artifacts.",
            implementation_status="placeholder",
        )

    def probe(self, source: EvidenceSource) -> float:
        """Return zero until Claude Code artifact detection is implemented."""
        return 0.0

    def discover(self, source: EvidenceSource, context: ParseContext) -> Iterable[ArtifactRecord]:
        context.progress(100, "Claude Code discovery is not implemented yet.")
        return ()

    def parse(
        self,
        source: EvidenceSource,
        artifacts: Iterable[ArtifactRecord],
        emit: EventSink,
        context: ParseContext,
    ) -> None:
        context.progress(100, "Claude Code placeholder emitted no events.")
