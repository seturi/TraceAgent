from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class StructuredDataIssue:
    path: str
    location: str
    error: str


@dataclass(frozen=True, slots=True)
class JsonLineRecord:
    line_number: int
    value: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SqliteRowRecord:
    table: str
    row_number: int
    values: dict[str, Any]
    # Same row, before json_safe() summarizes BLOB columns down to a hash/hex
    # preview - callers that need to look inside a BLOB (e.g. sniffing an
    # embedded protobuf timestamp) need the actual bytes, not the summary.
    raw_values: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TimestampedLogRecord:
    line_number: int
    timestamp: datetime | None
    level: str | None
    message: str


_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}(?:T|\s)\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"\[(?P<level>[^]]+)]\s*(?P<message>.*)$"
)


def iter_json_lines(
    path: Path,
    issues: list[StructuredDataIssue] | None = None,
) -> Iterator[JsonLineRecord]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                if issues is not None:
                    issues.append(
                        StructuredDataIssue(str(path), f"line {line_number}", str(exc))
                    )
                continue
            if isinstance(value, dict):
                yield JsonLineRecord(line_number, value)
            elif issues is not None:
                issues.append(
                    StructuredDataIssue(
                        str(path),
                        f"line {line_number}",
                        f"Expected JSON object, found {type(value).__name__}",
                    )
                )


def read_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return value


def load_collection_manifest(service_root: Path) -> dict[str, dict[str, Any]]:
    manifest_path = service_root / "collection_manifest.jsonl"
    if not manifest_path.is_file():
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for record in iter_json_lines(manifest_path):
        collected_path = record.value.get("collected_path")
        if not isinstance(collected_path, str):
            continue
        relative_parts = Path(collected_path).parts
        if relative_parts and relative_parts[0] == service_root.name:
            relative_parts = relative_parts[1:]
        destination = service_root.joinpath(*relative_parts).resolve()
        entries[str(destination).lower()] = record.value
    return entries


def iter_timestamped_log(path: Path) -> Iterator[TimestampedLogRecord]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            match = _LOG_PATTERN.match(line.rstrip())
            if not match:
                continue
            yield TimestampedLogRecord(
                line_number,
                parse_timestamp(match.group("timestamp")),
                match.group("level"),
                match.group("message"),
            )


def sqlite_tables(path: Path) -> tuple[str, ...]:
    connection = _open_sqlite_read_only(path)
    try:
        return tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
    finally:
        connection.close()


def iter_sqlite_rows(
    path: Path,
    *,
    tables: tuple[str, ...] | None = None,
) -> Iterator[SqliteRowRecord]:
    connection = _open_sqlite_read_only(path)
    try:
        connection.row_factory = sqlite3.Row
        selected = tables or tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        for table in selected:
            quoted = '"' + table.replace('"', '""') + '"'
            for row_number, row in enumerate(
                connection.execute(f"SELECT * FROM {quoted}"), start=1
            ):
                yield SqliteRowRecord(
                    table,
                    row_number,
                    {key: json_safe(row[key]) for key in row.keys()},
                    {key: row[key] for key in row.keys()},
                )
    finally:
        connection.close()


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        divisor = 1000.0 if abs(numeric) >= 10_000_000_000 else 1.0
        try:
            return datetime.fromtimestamp(numeric / divisor, timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.replace(".", "", 1).isdigit():
            try:
                return parse_timestamp(float(text))
            except ValueError:
                return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


_PROTO_TIMESTAMP_MIN_SECONDS = 1_500_000_000  # 2017-07-14
_PROTO_TIMESTAMP_MAX_SECONDS = 2_500_000_000  # 2049-03-01


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _iter_proto_fields(data: bytes) -> Iterator[tuple[int, int, Any]]:
    """Best-effort walk of protobuf wire-format bytes of unknown schema."""
    pos = 0
    length = len(data)
    while pos < length:
        try:
            tag, pos = _read_varint(data, pos)
        except ValueError:
            return
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:  # varint
            try:
                value, pos = _read_varint(data, pos)
            except ValueError:
                return
            yield field_no, wire_type, value
        elif wire_type == 2:  # length-delimited (bytes/string/submessage)
            try:
                size, pos = _read_varint(data, pos)
            except ValueError:
                return
            if size < 0 or pos + size > length:
                return
            yield field_no, wire_type, data[pos : pos + size]
            pos += size
        elif wire_type == 1:  # fixed64
            if pos + 8 > length:
                return
            pos += 8
            yield field_no, wire_type, None
        elif wire_type == 5:  # fixed32
            if pos + 4 > length:
                return
            pos += 4
            yield field_no, wire_type, None
        else:  # groups (2, 3) or unknown - can't safely skip, stop here
            return


def sniff_proto_timestamp(blob: bytes, *, _depth: int = 0) -> datetime | None:
    """Recover a ``google.protobuf.Timestamp`` embedded at an unknown depth
    inside an otherwise-undocumented protobuf blob (e.g. Antigravity's SQLite
    BLOB columns, which carry per-step creation time this way instead of in a
    plain column - see parsers.antigravity._parse_database).

    Schema-agnostic: walks the wire format looking for a length-delimited
    submessage shaped *exactly* like ``{1: seconds (varint), 2: nanos
    (varint)}`` with a seconds value in a plausible calendar-date range. That
    exact shape plus range check makes an accidental match on unrelated bytes
    very unlikely, but this is still a heuristic, not a schema - callers
    should treat a ``None`` result as "no timestamp found", not "no timestamp
    exists".
    """
    if _depth > 6:
        return None
    fields = list(_iter_proto_fields(blob))
    if len(fields) == 2:
        (field1, wire1, value1), (field2, wire2, value2) = fields
        if (
            field1 == 1
            and wire1 == 0
            and field2 == 2
            and wire2 == 0
            and isinstance(value1, int)
            and isinstance(value2, int)
            and _PROTO_TIMESTAMP_MIN_SECONDS <= value1 <= _PROTO_TIMESTAMP_MAX_SECONDS
            and 0 <= value2 < 1_000_000_000
        ):
            try:
                return datetime.fromtimestamp(value1, timezone.utc)
            except (OSError, OverflowError, ValueError):
                pass
    for _, wire_type, value in fields:
        if wire_type == 2 and isinstance(value, (bytes, bytearray)):
            found = sniff_proto_timestamp(value, _depth=_depth + 1)
            if found is not None:
                return found
    return None


def file_timestamp(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {
            "encoding": "binary_summary",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "hex_preview": value[:128].hex(),
        }
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return str(value)


def _open_sqlite_read_only(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)
