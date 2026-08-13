from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any


_MOJIBAKE_LEADERS = frozenset("ÃÂâðìëí")


@lru_cache(maxsize=2048)
def repair_text_encoding(text: str) -> tuple[str, bool]:
    """Repair reversible UTF-8/CP949 mojibake without guessing lost bytes.

    Tool output captured on Windows occasionally contains UTF-8 or CP949 bytes
    decoded as Latin-1/Windows-1252.  Each line is considered independently so
    a correctly decoded Korean line cannot make a neighbouring broken line
    unrepairable.  A candidate is accepted only when it round-trips exactly and
    its mojibake score is materially lower.

    U+FFFD is deliberately left untouched: once a decoder emitted a replacement
    character, the original byte is no longer available for reliable recovery.
    """
    if not text or not _looks_suspicious(text):
        return text, False

    repaired_parts: list[str] = []
    changed = False
    for part in text.splitlines(keepends=True):
        ending = ""
        body = part
        if part.endswith("\r\n"):
            body, ending = part[:-2], "\r\n"
        elif part.endswith(("\r", "\n")):
            body, ending = part[:-1], part[-1]
        repaired, did_change = _repair_line(body)
        repaired_parts.append(repaired + ending)
        changed = changed or did_change

    # str.splitlines() returns no part for the empty string only, handled above.
    return "".join(repaired_parts), changed


def repair_text_tree(value: Any) -> tuple[Any, int]:
    """Return a JSON-like value with string values safely repaired."""
    if isinstance(value, str):
        repaired, changed = repair_text_encoding(value)
        return repaired, int(changed)
    if isinstance(value, Mapping):
        repaired_mapping: dict[Any, Any] = {}
        repairs = 0
        for key, item in value.items():
            repaired_item, item_repairs = repair_text_tree(item)
            repaired_mapping[key] = repaired_item
            repairs += item_repairs
        return repaired_mapping, repairs
    if isinstance(value, list):
        repaired_items: list[Any] = []
        repairs = 0
        for item in value:
            repaired_item, item_repairs = repair_text_tree(item)
            repaired_items.append(repaired_item)
            repairs += item_repairs
        return repaired_items, repairs
    if isinstance(value, tuple):
        repaired_items = []
        repairs = 0
        for item in value:
            repaired_item, item_repairs = repair_text_tree(item)
            repaired_items.append(repaired_item)
            repairs += item_repairs
        return tuple(repaired_items), repairs
    return value, 0


def _repair_line(text: str) -> tuple[str, bool]:
    if not text or not _looks_suspicious(text):
        return text, False

    original = text
    current = text
    for _ in range(2):
        candidate = _best_candidate(current)
        if candidate == current:
            break
        current = candidate
    return current, current != original


def _best_candidate(text: str) -> str:
    baseline = _mojibake_score(text)
    best = text
    best_score = baseline
    suspicious_count = _suspicious_count(text)
    original_hangul = _hangul_count(text)

    for source_encoding, target_encoding in (
        ("cp1252", "utf-8"),
        ("latin-1", "utf-8"),
        ("cp1252", "cp949"),
        ("latin-1", "cp949"),
    ):
        try:
            raw = text.encode(source_encoding)
            candidate = raw.decode(target_encoding)
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if candidate.encode(target_encoding) != raw:
            continue

        candidate_score = _mojibake_score(candidate)
        hangul_gain = _hangul_count(candidate) - original_hangul
        if target_encoding == "cp949":
            # Genuine Western-language text may be Latin-1 encodable.  Require
            # a meaningful Korean recovery before treating it as CP949 bytes.
            acceptable = suspicious_count >= 4 and hangul_gain >= 3
        else:
            acceptable = bool(_MOJIBAKE_LEADERS.intersection(text)) or hangul_gain >= 2
        if acceptable and candidate_score + 2 <= best_score:
            best = candidate
            best_score = candidate_score
    return best


def _looks_suspicious(text: str) -> bool:
    return "\ufffd" in text or _suspicious_count(text) >= 2


def _suspicious_count(text: str) -> int:
    return sum(
        1
        for char in text
        if char in _MOJIBAKE_LEADERS
        or 0x80 <= ord(char) <= 0x9F
        or 0xA0 <= ord(char) <= 0xFF
    )


def _mojibake_score(text: str) -> int:
    score = text.count("\ufffd") * 20
    score += sum(4 for char in text if char in _MOJIBAKE_LEADERS)
    score += sum(3 for char in text if 0x80 <= ord(char) <= 0x9F)
    score += sum(1 for char in text if 0xA0 <= ord(char) <= 0xFF)
    return score


def _hangul_count(text: str) -> int:
    return sum(1 for char in text if "\uac00" <= char <= "\ud7a3")
