from __future__ import annotations

from collections.abc import Iterable

from collection.base import Collector


class CollectorRegistry:
    def __init__(self, collectors: Iterable[Collector] = ()) -> None:
        self._collectors: dict[str, Collector] = {}
        for collector in collectors:
            self.register(collector)

    def register(self, collector: Collector) -> None:
        collector_id = collector.metadata.collector_id
        if collector_id in self._collectors:
            raise ValueError(f"Collector already registered: {collector_id}")
        self._collectors[collector_id] = collector

    def all(self) -> tuple[Collector, ...]:
        return tuple(sorted(self._collectors.values(), key=lambda item: item.metadata.name.lower()))
