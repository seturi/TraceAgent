from collection.artifact_collector import ServiceArtifactCollector
from collection.ntfs.collector import NtfsArtifactCollector
from collection.registry import CollectorRegistry


def create_default_collector_registry() -> CollectorRegistry:
    return CollectorRegistry((ServiceArtifactCollector(), NtfsArtifactCollector()))
