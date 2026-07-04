from __future__ import annotations

from collections.abc import Iterable

from parsers.base import ArtifactParser


class ParserRegistry:
    def __init__(self, parsers: Iterable[ArtifactParser] = ()) -> None:
        self._parsers: dict[str, ArtifactParser] = {}
        for parser in parsers:
            self.register(parser)

    def register(self, parser: ArtifactParser) -> None:
        parser_id = parser.metadata.parser_id
        if parser_id in self._parsers:
            raise ValueError(f"Parser already registered: {parser_id}")
        self._parsers[parser_id] = parser

    def all(self) -> tuple[ArtifactParser, ...]:
        return tuple(sorted(self._parsers.values(), key=lambda item: item.metadata.name.lower()))

    def get(self, parser_id: str) -> ArtifactParser:
        return self._parsers[parser_id]
