from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.models import EvidenceSource


@dataclass(frozen=True, slots=True)
class CasePaths:
    root: Path
    artifacts: Path
    parsed: Path


def create_case_paths(
    source: EvidenceSource,
    *,
    documents_root: Path | None = None,
    created_at: datetime | None = None,
) -> CasePaths:
    user_profile = Path(os.environ.get("USERPROFILE", Path.home()))
    documents = documents_root or (user_profile / "Documents")
    timestamp = (created_at or datetime.now()).strftime("%Y%m%d_%H%M%S")
    case_id = f"case_{timestamp}_{source.source_id[:8]}"
    root = documents / "traceagent" / case_id
    artifacts = root / "artifacts"
    parsed = root / "parsed"
    artifacts.mkdir(parents=True, exist_ok=False)
    parsed.mkdir(parents=True, exist_ok=False)
    return CasePaths(root, artifacts, parsed)
