"""NTFS event-flow signatures for human vs AI-agent discrimination.

This is the *primary* discrimination layer from the research paper (Tables 5-7).
A reconstructed :class:`FileOperation` (an ordered flow of USN reasons for one
logical file action) is matched against known signatures to decide whether a
human or an AI agent performed it, and — where the flow is distinctive — which
agent family.  Local-artifact cross-analysis (see :mod:`analysis.ntfs.attribution`)
then confirms or refines the guess.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime

from core.models import ActorClass

# Actor keys used for service hints from NTFS flow alone.
CLAUDE_COWORK = "Claude Cowork"
CLAUDE_CODE = "Claude Code"
CODEX = "Codex"
ANTIGRAVITY = "Antigravity"

_TMP_RENAME_FAMILY = (CLAUDE_COWORK, CLAUDE_CODE, ANTIGRAVITY)
_DIRECT_WRITE_FAMILY = (CODEX,)

# Application temp-file patterns that only appear when a *human* edits a file in
# an interactive desktop application.
_WORD_TEMP = re.compile(r"^~wr[dl]\d+\.tmp$", re.IGNORECASE)
_OFFICE_LOCK = re.compile(r"^~\$.+\.(docx?|xlsx?|pptx?)$", re.IGNORECASE)
_RECYCLE_META = re.compile(r"^\$[ir][0-9a-z]{4,}", re.IGNORECASE)
# In-progress download markers written by browsers and messenger clients, which
# rename to the final name once the transfer completes.  Only a person driving a
# download UI produces these — an agent writing a file through a file API never
# does — so inside a user download/document tree they are a positive human
# signal, covering the most common real user activity (browser downloads,
# KakaoTalk/Telegram file receipts) that Office/Recycle Bin signatures miss.
_DOWNLOAD_TEMP = re.compile(r"\.(crdownload|part|partial|download|opdownload)$", re.IGNORECASE)
_RECYCLE_RENAME = re.compile(r"^\$r[0-9a-z]+\.", re.IGNORECASE)

# Paths that indicate OS / application background activity rather than a person
# or an agent deliberately operating on a document.  Browsers, WebView2, Office,
# LevelDB and the like constantly perform atomic tmp->rename writes that would
# otherwise be mistaken for AI agent activity, so anything under these roots is
# treated as background unless it also sits under a user document location.
# Roots that hold OS and application storage.  A user document never lives under
# any of these, so they are background *unconditionally* — the user-document
# escape below must not apply to them.  It matters: "/onedrive/" is a user
# document hint (C:\Users\x\OneDrive\Documents), but it also matches the OneDrive
# *application* directory under AppData, which would otherwise let every OneDrive
# cache write escape the background filter and be read as agent activity.
_APPLICATION_STORAGE_HINTS = (
    "/windows/",
    "/program files/",
    "/program files (x86)/",
    "/programdata/",
    "/system volume information/",
    "/$extend/",
    "/appdata/",
)
# Background only when the operation is not also under a user document tree: a
# deleted user document does sit in the Recycle Bin, and that is user activity.
_BACKGROUND_PATH_HINTS = ("/$recycle.bin/",)
# Background even when nominally under a user document tree (app cache churn).
_BACKGROUND_ANYWHERE_HINTS = (
    "/ebwebview/",
    "/leveldb/",
    "/gpucache/",
    "/code cache/",
    "/service worker/",
    "/webcache/",
    "/indexeddb/",
    "/blob_storage/",
    "/cache_data/",
    "/accountpictures/",
)
# OS / application-owned files: registry hives and their transaction logs, shell
# metadata, icon and thumbnail caches, error reports, LevelDB internals, and
# GUID-named temp files.  These are background churn *wherever* they sit — a
# "copy" of desktop.ini into Documents is the shell materialising a folder, not
# a person or an agent handling a document — so they are matched by name, ahead
# of any path-based reasoning, and are recognised even when the record's parent
# reference could not be resolved to a path.
_BACKGROUND_FILENAMES = re.compile(
    r"""^(?:
        log | log\.old | local\ state | current | lock | manifest-\d+
      | desktop\.ini | thumbs\.db
      | pagefile\.sys | swapfile\.sys | hiberfil\.sys
      | ntuser\.(?:dat|ini)[^\\/]* | usrclass\.dat[^\\/]*
      | iconcache[^\\/]*\.db | thumbcache[^\\/]*\.db
      | report\.wer(?:\.tmp)?
      | [^\\/]*\.(?:ldb|log\d*|regtrans-ms|blf|etl|evtx|pf)
      | \{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?\.tmp
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Paths a person typically operates on interactively.
_USER_DOC_HINTS = (
    "/desktop/",
    "/documents/",
    "/downloads/",
    "/pictures/",
    "/onedrive/",
    "/바탕 화면/",
    "/바탕화면/",
    "/문서/",
)


def normalize_path(path: str | None) -> str | None:
    """Canonicalise a path so $MFT, USN and agent session-log paths compare equal.

    Handles Windows/`\\?\\`/UNC forms, ``file://`` URIs with ``%20`` encoding
    (agent logs), WSL ``/mnt/c`` mounts and drive letters, always yielding a
    lower-case, forward-slash, leading-slash path.
    """
    if not path:
        return None
    value = path.strip()
    if "%" in value:
        try:
            value = urllib.parse.unquote(value)
        except (ValueError, TypeError):
            pass
    value = value.replace("\\", "/")
    value = re.sub(r"^file:/*", "/", value, flags=re.IGNORECASE)  # file:// scheme
    value = re.sub(r"^//[?.]/", "/", value)  # \\?\ / \\.\ prefixes
    value = re.sub(r"^/*[a-zA-Z]:", "/", value)  # drive letter (any leading slashes) -> root
    value = re.sub(r"^/mnt/[a-zA-Z]/", "/", value)  # WSL drive mount -> root
    while "//" in value:
        value = value.replace("//", "/")
    if not value.startswith("/"):
        value = "/" + value  # a consistent leading slash so $MFT and log paths align
    return value.lower()


def basename_of(path: str | None) -> str | None:
    normalized = normalize_path(path)
    if not normalized:
        return None
    return normalized.rstrip("/").rsplit("/", 1)[-1] or None


# Each AI agent's own local-artifact storage (see collection.service_catalog's
# ServiceArtifactSpec.user_patterns) is under continuous read/write churn just
# from the agent app running - housekeeping saves, WAL/SHM files, atomic
# tmp-then-rename state writes. NTFS/USN scanning is volume-wide and has no
# notion of "this directory belongs to an already-parsed local artifact
# source", so without this filter that churn floods File/Folder Activity
# looking like the agent editing user files, when it never touched anything
# outside its own app-data directory.
_SERVICE_OWNED_PATH_MARKERS = (
    "/.gemini/antigravity/",
    "/.claude/projects/",
    "/local-agent-mode-sessions/",
    "/claude/claude-code-sessions/",
    "/claude/logs/",
    "/claude-cli-nodejs/cache/",
    "/.codex/",
)


def is_service_owned_path(path: str | None) -> bool:
    """Whether ``path`` sits inside an AI agent's own local-artifact storage."""
    normalized = normalize_path(path)
    if not normalized:
        return False
    return any(marker in normalized for marker in _SERVICE_OWNED_PATH_MARKERS)


@dataclass(frozen=True, slots=True)
class FileOperation:
    """One logical file/folder action reconstructed from USN records."""

    target_path: str | None
    normalized_path: str | None
    basename: str | None
    filenames: tuple[str, ...]
    reason_flow: tuple[str, ...]  # friendly names, ordered
    paths: tuple[str, ...]  # normalized (lowercased) full paths involved
    start: datetime
    end: datetime
    file_references: tuple[int, ...]
    event_ids: tuple[str, ...]
    # FILE_ATTRIBUTE_DIRECTORY was set on the USN records for this operation.
    is_directory: bool = False

    @property
    def reasons(self) -> frozenset[str]:
        return frozenset(self.reason_flow)


@dataclass(frozen=True, slots=True)
class ActorSignal:
    """Layer-1 (signature) discrimination result for one operation."""

    actor_class: ActorClass
    behavior: str
    confidence: float
    service_hints: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    forbidden_services: tuple[str, ...] = ()  # services that could NOT do this
    metadata: dict[str, object] = field(default_factory=dict)


def _any_filename(op: FileOperation, predicate) -> bool:
    return any(predicate(name) for name in op.filenames if name)


def has_app_temp(op: FileOperation) -> str | None:
    """Return the interactive application name if a human app-temp trace exists."""
    if _any_filename(op, lambda n: bool(_WORD_TEMP.match(n))):
        return "Microsoft Word"
    if _any_filename(op, lambda n: bool(_OFFICE_LOCK.match(n))):
        return "Microsoft Office"
    for path in op.paths:
        if "/tabstate/" in path and path.endswith((".bin.tmp", ".bin")):
            return "Windows Notepad"
    return None


def has_download_temp(op: FileOperation) -> bool:
    """Whether a browser/messenger in-progress download marker is present."""
    return _any_filename(op, lambda n: bool(_DOWNLOAD_TEMP.search(n)))


def has_recycle_bin(op: FileOperation) -> bool:
    if any("/$recycle.bin/" in path for path in op.paths):
        return True
    return _any_filename(
        op, lambda n: bool(_RECYCLE_META.match(n) or _RECYCLE_RENAME.match(n))
    )


def _looks_like_tmp(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.lower()
    if _WORD_TEMP.match(lowered) or _OFFICE_LOCK.match(lowered):
        return False  # app temp, not an agent atomic-write temp
    return lowered.endswith(".tmp") or lowered.endswith(".pbtxt")


def has_tmp_rename(op: FileOperation) -> bool:
    renamed = {"File_Renamed_Old", "File_Renamed_New"} & op.reasons
    return bool(renamed) and _any_filename(op, _looks_like_tmp)


def is_user_doc_path(op: FileOperation) -> bool:
    return any(hint in path for path in op.paths for hint in _USER_DOC_HINTS)


def is_background_path(op: FileOperation) -> bool:
    """Whether the operation targets OS / application background storage.

    App-cache locations (``_BACKGROUND_ANYWHERE_HINTS``), OS/application storage
    roots (``_APPLICATION_STORAGE_HINTS``) and OS-owned file names count as
    background unconditionally; the Recycle Bin only counts when the operation is
    not also under a user document tree.
    """
    if any(hint in path for path in op.paths for hint in _BACKGROUND_ANYWHERE_HINTS):
        return True
    if any(hint in path for path in op.paths for hint in _APPLICATION_STORAGE_HINTS):
        return True
    if _any_filename(op, lambda n: bool(_BACKGROUND_FILENAMES.match(n))):
        return True
    if is_user_doc_path(op):
        return False
    return any(hint in path for path in op.paths for hint in _BACKGROUND_PATH_HINTS)


def classify_behavior(op: FileOperation) -> str:
    reasons = op.reasons
    # Recycle-bin move is a rename into $Recycle.Bin (no File_Deleted reason).
    if has_recycle_bin(op) and reasons & {"File_Renamed_Old", "File_Renamed_New"}:
        return "delete_recycle"
    if "File_Deleted" in reasons:
        return "delete_permanent"
    if {"File_Renamed_Old", "File_Renamed_New"} <= reasons:
        # Directory change => move, otherwise a plain rename.
        dirs = {path.rsplit("/", 1)[0] for path in op.paths if "/" in path}
        return "move" if len(dirs) > 1 else "rename"
    if "File_Created" in reasons:
        if {"Data_Overwritten", "Basic_Info_Changed"} <= reasons:
            return "copy"
        return "create"
    if reasons & {"Data_Added", "Data_Overwritten", "Data_Truncated", "Object_ID_Changed"}:
        return "modify"
    return "metadata_change"


def evaluate(op: FileOperation) -> ActorSignal:
    """Score an operation from its NTFS flow alone (paper Tables 5-7)."""
    behavior = classify_behavior(op)
    app = has_app_temp(op)
    recycle = has_recycle_bin(op)

    # --- Strong human signals -------------------------------------------------
    if app is not None:
        return ActorSignal(
            ActorClass.HUMAN,
            behavior,
            0.85,
            reasons=(f"interactive_app_temp:{app}",),
            metadata={"application": app},
        )

    if has_download_temp(op) and is_user_doc_path(op):
        return ActorSignal(
            ActorClass.HUMAN,
            behavior,
            0.7,
            reasons=("browser_or_messenger_download",),
        )

    if behavior == "delete_recycle":
        # Recycle-bin move: a person via Explorer, or any non-Cowork agent.
        # Claude Cowork runs in a Linux sandbox and *cannot* use the recycle bin.
        return ActorSignal(
            ActorClass.HUMAN,
            behavior,
            0.55,
            service_hints=_DIRECT_WRITE_FAMILY + (CLAUDE_CODE, ANTIGRAVITY),
            reasons=("recycle_bin_move",),
            forbidden_services=(CLAUDE_COWORK,),
        )

    # --- OS / application background churn ------------------------------------
    # Browsers, WebView2, Office and LevelDB perform constant atomic tmp->rename
    # writes; classify them as system so they do not masquerade as AI activity.
    # A genuine agent operation on such a path is still recoverable via Layer-2
    # session-log correlation, which overrides this verdict.
    if is_background_path(op):
        return ActorSignal(
            ActorClass.SYSTEM,
            behavior,
            0.6,
            reasons=("os_or_app_background_path",),
        )

    # --- Directories ----------------------------------------------------------
    # Every signature below reads the shape of a *file content* write.  A
    # directory produces the same reason bits from index churn (shell folder
    # creation, temp directories, cache buckets) without the same meaning, so
    # claiming an actor from them is unfounded; leave it to session-log
    # correlation, which can still confirm a genuine agent folder operation.
    if op.is_directory:
        return ActorSignal(
            ActorClass.UNKNOWN, behavior, 0.15, reasons=("directory_operation",)
        )

    # --- Unresolved location --------------------------------------------------
    # Without a path there is no way to tell whether this sits in a user document
    # tree or in OS/application storage, and the write-shape signatures below are
    # only meaningful once background churn has been excluded — on real evidence
    # they fire almost exclusively on Windows internals whose parent reference the
    # $MFT copy could not resolve.  Session-log correlation (Layer 2) matches on
    # file name and command text, so a genuine agent operation is still
    # recoverable here.
    if not op.paths:
        return ActorSignal(
            ActorClass.UNKNOWN, behavior, 0.15, reasons=("unresolved_path",)
        )

    # --- AI atomic-write signatures ------------------------------------------
    if has_tmp_rename(op):
        return ActorSignal(
            ActorClass.AI_AGENT,
            behavior,
            0.75,
            service_hints=_TMP_RENAME_FAMILY,
            reasons=("atomic_tmp_rename_write",),
            forbidden_services=_DIRECT_WRITE_FAMILY,
        )

    if behavior == "modify" and {"Data_Truncated", "Data_Added", "Data_Overwritten"} <= op.reasons:
        # docx/xlsx rewrite flow shared by Cowork/Code/Antigravity.
        return ActorSignal(
            ActorClass.AI_AGENT,
            behavior,
            0.6,
            service_hints=_TMP_RENAME_FAMILY,
            reasons=("data_truncate_add_overwrite",),
        )

    if behavior == "modify" and "Object_ID_Changed" in op.reasons:
        # A Codex content edit begins with an object-id change.
        return ActorSignal(
            ActorClass.AI_AGENT,
            behavior,
            0.55,
            service_hints=_DIRECT_WRITE_FAMILY,
            reasons=("object_id_then_data",),
        )

    # --- Weak / ambiguous -----------------------------------------------------
    if behavior == "copy":
        # A copy preserves the source's timestamps whoever performs it, so
        # Explorer's Ctrl+C/Ctrl+V, an installer and an agent's copy call are
        # indistinguishable from the flow alone — the same argument this module
        # already makes for permanent deletes.  Asserting AI here is what floods
        # the view: on real evidence a single `npm install` contributed 1,491
        # "AI agent" copies under node_modules.  The service hints are kept so
        # session-log correlation can still resolve it.
        return ActorSignal(
            ActorClass.UNKNOWN,
            behavior,
            0.25,
            service_hints=(CLAUDE_CODE, ANTIGRAVITY, CODEX),
            reasons=("copy_ambiguous",),
        )

    if behavior == "delete_permanent":
        # rm (agent) vs Shift+Delete (human) are indistinguishable from NTFS
        # alone; leave it to cross-analysis to decide.
        return ActorSignal(
            ActorClass.UNKNOWN,
            behavior,
            0.2,
            reasons=("permanent_delete_ambiguous",),
        )

    if behavior in {"create", "rename", "move"} and is_user_doc_path(op):
        return ActorSignal(
            ActorClass.UNKNOWN,
            behavior,
            0.25,
            reasons=("direct_operation_ambiguous",),
        )

    return ActorSignal(ActorClass.UNKNOWN, behavior, 0.1, reasons=("no_strong_signature",))
