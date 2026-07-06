"""Carve ``$FILE_NAME`` attributes out of raw NTFS metadata (``$LogFile``).

``dissect`` does not parse ``$LogFile``, and a full LFS transaction decoder is
large and fragile.  However, the redo/undo data of the index-entry log records
embeds complete ``$FILE_NAME`` attributes, whose binary layout is stable.  We
therefore *carve* those structures directly — the same technique NTFS journal
recovery tools use — which reliably recovers file names, parent references and
the four ``$FILE_NAME`` timestamps, and survives records that are otherwise
purged.  This module is dependency-free so the carver can be unit-tested.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# $FILE_NAME attribute field offsets (relative to the attribute content start).
_OFF_PARENT = 0x00
_OFF_CTIME = 0x08
_OFF_MTIME = 0x10
_OFF_MFT_TIME = 0x18
_OFF_ATIME = 0x20
_OFF_FLAGS = 0x38
_OFF_NAME_LEN = 0x40
_OFF_NAMESPACE = 0x41
_OFF_NAME = 0x42

# Namespace codes: 0=POSIX, 1=Win32, 2=DOS (8.3), 3=Win32&DOS.
_DOS_NAMESPACE = 2
# Maximum spread of a record's four $FILE_NAME timestamps for it to be credible.
_MAX_TIME_SPAN = timedelta(days=365 * 30)

# Unicode ranges that legitimately appear in file names (ASCII, accented Latin,
# Hangul, Kana, CJK, full/half-width forms).  Random bytes that decode as UTF-16
# scatter across unrelated scripts (combining marks, rare alphabets), so a name
# with too many out-of-range characters is a carving false positive.
_NAME_RANGES = (
    (0x20, 0x7E),
    (0x00A1, 0x017F),
    (0x1100, 0x11FF),
    (0x3000, 0x30FF),
    (0x3130, 0x318F),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFF00, 0xFFEF),
)


def _plausible_name(name: str) -> bool:
    odd = sum(
        0 if any(lo <= ord(ch) <= hi for lo, hi in _NAME_RANGES) else 1 for ch in name
    )
    return odd / len(name) <= 0.25


@dataclass(frozen=True, slots=True)
class CarvedFileName:
    offset: int
    parent_reference: int
    namespace: int
    name: str
    created: datetime | None
    modified: datetime | None
    mft_modified: datetime | None
    accessed: datetime | None
    flags: int


def _filetime(value: int) -> datetime | None:
    if value <= 0:
        return None
    try:
        return _EPOCH + timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return None


def _plausible(dt: datetime | None) -> bool:
    return dt is not None and 1980 <= dt.year <= 2100


def carve_file_names(
    buf: bytes,
    *,
    include_dos: bool = False,
) -> list[CarvedFileName]:
    """Recover ``$FILE_NAME`` structures embedded in ``buf``.

    A candidate is accepted when the name length/namespace bytes are valid, the
    name decodes as printable UTF-16LE, and the creation/modification stamps are
    plausible FILETIMEs — which together make false positives vanishingly rare.
    """
    results: list[CarvedFileName] = []
    n = len(buf)
    # The creation FILETIME's most-significant byte is 0x01 for any date between
    # ~1996 and ~2036, and sits at FN+0x0F.  Jumping to those bytes with the
    # C-level ``bytes.find`` skips ~all non-candidate offsets (a byte-by-byte
    # Python scan of a 64 MiB $LogFile is otherwise ~20x slower).
    ctime_msb = _OFF_CTIME + 7
    pos = 0
    while True:
        idx = buf.find(b"\x01", pos)
        if idx < 0:
            break
        pos = idx + 1
        offset = idx - ctime_msb
        if offset < 0 or offset + _OFF_NAME > n:
            continue
        name_len = buf[offset + _OFF_NAME_LEN]
        namespace = buf[offset + _OFF_NAMESPACE]
        end = offset + _OFF_NAME + 2 * name_len
        if not (1 <= name_len <= 255 and namespace <= 3 and end <= n):
            continue
        created = _filetime(struct.unpack_from("<Q", buf, offset + _OFF_CTIME)[0])
        modified = _filetime(struct.unpack_from("<Q", buf, offset + _OFF_MTIME)[0])
        mft_changed = _filetime(struct.unpack_from("<Q", buf, offset + _OFF_MFT_TIME)[0])
        accessed = _filetime(struct.unpack_from("<Q", buf, offset + _OFF_ATIME)[0])
        stamps = (created, modified, mft_changed, accessed)
        # A real $FILE_NAME has four valid, clustered timestamps; random bytes
        # rarely produce four plausible FILETIMEs within the same era.
        if not all(_plausible(stamp) for stamp in stamps):
            continue
        if (max(stamps) - min(stamps)) > _MAX_TIME_SPAN:
            continue
        try:
            name = buf[offset + _OFF_NAME : end].decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if len(name) < 2 or "\x00" in name or any(ord(ch) < 32 and ch != "\t" for ch in name):
            continue
        if not _plausible_name(name):
            continue  # random bytes that happened to decode as mixed-script text
        if namespace == _DOS_NAMESPACE and not include_dos:
            continue
        results.append(
            CarvedFileName(
                offset=offset,
                parent_reference=struct.unpack_from("<Q", buf, offset + _OFF_PARENT)[0]
                & ((1 << 48) - 1),
                namespace=namespace,
                name=name,
                created=created,
                modified=modified,
                mft_modified=mft_changed,
                accessed=accessed,
                flags=struct.unpack_from("<I", buf, offset + _OFF_FLAGS)[0],
            )
        )
    return results


_INDEX_ENTRY_HDR = 0x10  # INDEX_ENTRY header before the embedded $FILE_NAME
# NTFS LFS redo/undo operation codes whose data carries a $FILE_NAME index entry,
# mapped to the file operation they represent.  Borrowing this mechanism (the
# opcode structurally identifies a real name and its operation) lets us reject
# carving false positives and recover create/delete/rename semantics from
# $LogFile — without a full, version-fragile LFS transaction decoder.
INDEX_ENTRY_OPS = {
    0x0C: "created",  # AddIndexEntryRoot
    0x0D: "deleted",  # DeleteIndexEntryRoot
    0x0E: "created",  # AddIndexEntryAllocation
    0x0F: "deleted",  # DeleteIndexEntryAllocation
    0x13: "modified",  # UpdateFileNameRoot
    0x14: "modified",  # UpdateFileNameAllocation
}


def anchor_operation(buf: bytes, fn_offset: int) -> str | None:
    """The file operation for a carved $FILE_NAME, from the log record before it.

    A real ``$FILE_NAME`` sits at ``opcode_offset + redo/undo_offset + 0x10``
    inside an index-entry log record; scanning back for that opcode both proves
    the name is genuine and yields the operation.
    """
    for pos in range(fn_offset - 0x14, max(-1, fn_offset - 0x70), -2):
        if pos < 0 or pos + 10 > len(buf):
            continue
        op = struct.unpack_from("<H", buf, pos)[0]
        if op not in INDEX_ENTRY_OPS:
            continue
        redo_off = struct.unpack_from("<H", buf, pos + 4)[0]
        undo_off = struct.unpack_from("<H", buf, pos + 8)[0]
        if fn_offset in (pos + redo_off + _INDEX_ENTRY_HDR, pos + undo_off + _INDEX_ENTRY_HDR):
            return INDEX_ENTRY_OPS[op]
    return None


def carve_index_operations(
    buf: bytes, *, include_dos: bool = False
) -> list[tuple[CarvedFileName, str]]:
    """Carve only $FILE_NAMEs backed by an index-entry log record, with operation."""
    results: list[tuple[CarvedFileName, str]] = []
    for item in carve_file_names(buf, include_dos=include_dos):
        operation = anchor_operation(buf, item.offset)
        if operation is not None:
            results.append((item, operation))
    return results


def dedupe(carved: list[CarvedFileName]) -> list[CarvedFileName]:
    """Collapse repeated carves (redo+undo copies) by name/parent/mtime."""
    seen: set[tuple[int, str, str]] = set()
    unique: list[CarvedFileName] = []
    for item in carved:
        key = (item.parent_reference, item.name, item.modified.isoformat() if item.modified else "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
