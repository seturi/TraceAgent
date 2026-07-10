from __future__ import annotations

import csv
import html as html_lib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from core.models import ActorClass, NormalizedEvent
from version import __version__


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


# Internal behavior/reason codes (see analysis.ntfs.signatures / analysis.ntfs.attribution)
# translated into phrases an investigator can read without knowing the codebase.
_BEHAVIOR_LABELS = {
    "create": "Created",
    "modify": "Modified",
    "rename": "Renamed",
    "move": "Moved",
    "copy": "Copied",
    "delete_permanent": "Permanently deleted",
    "delete_recycle": "Moved to Recycle Bin",
    "metadata_change": "Metadata changed",
    "logfile_recovered": "Recovered from $LogFile",
}

_REASON_LABELS = {
    "interactive_app_temp": "interactive application temp file",
    "recycle_bin_move": "Recycle Bin move",
    "os_or_app_background_path": "OS/application background activity",
    "atomic_tmp_rename_write": "atomic temp-file-then-rename write (AI-agent pattern)",
    "data_truncate_add_overwrite": "truncate-then-rewrite pattern",
    "object_id_then_data": "object-ID change followed by data write",
    "copy_with_basic_info_change": "copy with attribute change",
    "permanent_delete_ambiguous": "permanent delete, actor not determinable from filesystem alone",
    "direct_operation_ambiguous": "direct operation, actor not determinable from filesystem alone",
    "no_strong_signature": "no strong signature",
    "session_log_path_match": "session-log path match",
    "session_log_basename_match": "session-log filename match",
    "session_log_command_match": "session-log command match",
    "tool": "tool",
    "signature_service_conflict": "conflicts with the filesystem signature",
}


def _behavior_label(code: str) -> str:
    return _BEHAVIOR_LABELS.get(code, code)


def _reason_label(code: str) -> str:
    base, _, detail = code.partition(":")
    label = _REASON_LABELS.get(base, base.replace("_", " "))
    return f"{label} ({detail})" if detail else label


def _activity_summary(behaviors: tuple[str, ...]) -> str:
    if not behaviors:
        return "—"
    return " → ".join(_behavior_label(code) for code in behaviors)


def _evidence_summary(reasons: tuple[str, ...], limit: int = 3) -> str:
    if not reasons:
        return "—"
    shown = [_reason_label(code) for code in reasons[:limit]]
    remaining = len(reasons) - limit
    if remaining > 0:
        shown.append(f"+{remaining} more")
    return "; ".join(shown)


@dataclass(frozen=True, slots=True)
class FileAttributionRow:
    """One file/folder's reconstructed activity and human/AI-agent verdict.

    Mirrors the Analyze > NTFS events view: ``behaviors`` is the ordered flow of
    reconstructed operations (e.g. create -> modify -> rename) and ``reasons``
    is the evidence backing the actor verdict, both still using the internal
    codes from :mod:`analysis.ntfs.signatures` — renderers translate them to
    plain language via :func:`_activity_summary` / :func:`_evidence_summary`.
    """

    filename: str
    path: str
    actor_class: ActorClass
    service: str | None
    confidence: float
    behaviors: tuple[str, ...]
    reasons: tuple[str, ...]
    first_activity: datetime | None
    last_activity: datetime | None


@dataclass(frozen=True, slots=True)
class SessionSummaryRow:
    """One local-artifact session, as shown in the Analyze > Local artifacts view."""

    service: str
    session_id: str
    event_count: int
    first: datetime
    last: datetime


@dataclass(frozen=True, slots=True)
class CaseReport:
    source_label: str
    generated_at: datetime
    events: tuple[NormalizedEvent, ...]
    file_rows: tuple[FileAttributionRow, ...]
    session_rows: tuple[SessionSummaryRow, ...]


def _actor_label(actor_class: ActorClass, service: str | None) -> str:
    if actor_class == ActorClass.AI_AGENT:
        return f"AI agent · {service}" if service else "AI agent"
    return {
        ActorClass.HUMAN: "Human",
        ActorClass.SYSTEM: "System",
    }.get(actor_class, "Unknown")


def _fmt_time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "—"


_CSV_FIELDS = (
    "filename",
    "path",
    "actor",
    "confidence",
    "activity",
    "evidence",
    "first_activity",
    "last_activity",
)


_SESSION_CSV_FIELDS = ("service", "session_id", "event_count", "first_activity", "last_activity")


def export_activity_csv(report: CaseReport, destination: Path) -> None:
    """Human-readable activity report: file/folder attribution, then local
    artifact sessions, as two labeled sections in one CSV — so a case with
    only service artifacts (no NTFS) still exports something, and vice versa.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow(["# File / Folder Activity"])
        writer.writerow(_CSV_FIELDS)
        for row in report.file_rows:
            writer.writerow(
                (
                    row.filename,
                    row.path,
                    _actor_label(row.actor_class, row.service),
                    f"{row.confidence:.2f}",
                    _activity_summary(row.behaviors),
                    _evidence_summary(row.reasons, limit=len(row.reasons) or 1),
                    _fmt_time(row.first_activity),
                    _fmt_time(row.last_activity),
                )
            )
        writer.writerow([])
        writer.writerow(["# Local Artifact Sessions"])
        writer.writerow(_SESSION_CSV_FIELDS)
        for row in report.session_rows:
            writer.writerow(
                (row.service, row.session_id, row.event_count, _fmt_time(row.first), _fmt_time(row.last))
            )


def export_case_report_json(report: CaseReport, destination: Path) -> None:
    """Same content as the HTML/PDF report, structured for scripts instead of eyes."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source_label": report.source_label,
        "generated_at": report.generated_at.isoformat(),
        "summary": {
            "total_events": len(report.events),
            "files_analyzed": len(report.file_rows),
            "sessions": len(report.session_rows),
            "by_actor": dict(Counter(row.actor_class.value for row in report.file_rows)),
        },
        "file_activity": [
            {
                "filename": row.filename,
                "path": row.path,
                "actor_class": row.actor_class.value,
                "service": row.service,
                "confidence": round(row.confidence, 3),
                "activity": _activity_summary(row.behaviors),
                "evidence": _evidence_summary(row.reasons, limit=len(row.reasons) or 1),
                "first_activity": row.first_activity.isoformat() if row.first_activity else None,
                "last_activity": row.last_activity.isoformat() if row.last_activity else None,
            }
            for row in report.file_rows
        ],
        "sessions": [
            {
                "service": row.service,
                "session_id": row.session_id,
                "event_count": row.event_count,
                "first": row.first.isoformat(),
                "last": row.last.isoformat(),
            }
            for row in report.session_rows
        ],
    }
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _esc(value: object) -> str:
    return html_lib.escape(str(value)) if value is not None else ""


def render_html_report(report: CaseReport) -> str:
    """Render a self-contained HTML report.

    Markup is deliberately limited to tags/inline styles that both a browser
    and Qt's ``QTextDocument`` rich-text renderer support, since the same HTML
    is reused to print the PDF report.
    """
    actor_counts = Counter(row.actor_class for row in report.file_rows)
    service_counts = Counter(row.service for row in report.session_rows)

    file_rows_html = "".join(
        f'<tr style="background-color:{"#f7f7f7" if index % 2 else "#ffffff"};">'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(row.filename)}'
        f'<br/><span style="color:#868d92;font-size:10px;font-family:Consolas,monospace;">{_esc(row.path)}</span></td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(_actor_label(row.actor_class, row.service))}'
        f'<br/><span style="color:#868d92;font-size:10px;">confidence {row.confidence:.2f}</span></td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(_activity_summary(row.behaviors))}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;font-size:11px;">{_esc(_evidence_summary(row.reasons))}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(_fmt_time(row.last_activity))}</td>'
        f"</tr>"
        for index, row in enumerate(report.file_rows)
    )
    session_rows_html = "".join(
        f'<tr style="background-color:{"#f7f7f7" if index % 2 else "#ffffff"};">'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(row.service)}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;font-family:Consolas,monospace;font-size:11px;">{_esc(row.session_id)}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;text-align:right;">{row.event_count}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(_fmt_time(row.first))}</td>'
        f'<td style="padding:6px 10px;border:1px solid #ccc;">{_esc(_fmt_time(row.last))}</td>'
        f"</tr>"
        for index, row in enumerate(report.session_rows)
    )
    actor_summary = "".join(
        f'<li>{_esc(_actor_label(actor, None))}: {count}</li>'
        for actor, count in sorted(actor_counts.items(), key=lambda item: item[0].value)
    )
    service_summary = "".join(
        f"<li>{_esc(service or 'Unknown')}: {count} session(s)</li>"
        for service, count in sorted(service_counts.items(), key=lambda item: item[0] or "")
    )

    return f"""<html><body style="font-family:Segoe UI,Arial,sans-serif;color:#1b1d22;">
<h1 style="font-size:20px;margin-bottom:0;">TraceAgent Forensic Report</h1>
<p style="color:#5b6268;margin-top:4px;">
Evidence source: {_esc(report.source_label)}<br/>
Generated: {_esc(report.generated_at.strftime('%Y-%m-%d %H:%M:%S %Z'))}<br/>
TraceAgent version: {_esc(__version__)}
</p>

<h2 style="font-size:15px;border-bottom:1px solid #ccc;padding-bottom:4px;">Summary</h2>
<p>Total normalized events: {len(report.events)}<br/>
File/folder entries analyzed: {len(report.file_rows)}<br/>
Local artifact sessions: {len(report.session_rows)}</p>
<p><b>By actor</b></p>
<ul>{actor_summary or "<li>No file/folder attribution results.</li>"}</ul>
<p><b>By service</b></p>
<ul>{service_summary or "<li>No local artifact sessions.</li>"}</ul>

<h2 style="font-size:15px;border-bottom:1px solid #ccc;padding-bottom:4px;">File / Folder Activity</h2>
<p style="color:#5b6268;font-size:11px;">
What happened to each file, who most likely did it, and the evidence behind that call.
</p>
<table style="border-collapse:collapse;width:100%;font-size:12px;">
<tr style="background-color:#eef0f0;">
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">File</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Actor</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Activity</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Evidence</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Last activity</th>
</tr>
{file_rows_html or '<tr><td style="padding:6px 10px;border:1px solid #ccc;" colspan="5">No NTFS attribution results.</td></tr>'}
</table>

<h2 style="font-size:15px;border-bottom:1px solid #ccc;padding-bottom:4px;">Local Artifact Sessions</h2>
<table style="border-collapse:collapse;width:100%;font-size:12px;">
<tr style="background-color:#eef0f0;">
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Service</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Session</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Events</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">First seen</th>
<th style="padding:6px 10px;border:1px solid #ccc;text-align:left;">Last seen</th>
</tr>
{session_rows_html or '<tr><td style="padding:6px 10px;border:1px solid #ccc;" colspan="5">No local artifact sessions.</td></tr>'}
</table>

<p style="color:#868d92;font-size:11px;margin-top:18px;">
Generated by TraceAgent {_esc(__version__)}. All evidence sources were accessed read-only;
collected artifacts are hashed with SHA-256 at collection time for post-hoc integrity verification.
</p>
</body></html>"""


def export_html_report(report: CaseReport, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html_report(report), encoding="utf-8")
