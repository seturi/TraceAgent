from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QRect, QSize, QSizeF
from PySide6.QtGui import QAction, QColor, QFont, QFontMetrics, QIcon, QPainter, QPen, QPixmap, QTextDocument
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analysis.ntfs.attribution import OperationVerdict, attribute_ntfs_events, build_agent_index
from analysis.ntfs.narrative import Narrative, summarize_file
from analysis.ntfs.signatures import basename_of, normalize_path
from analysis.session_narrative import describe_event, event_kind, summarize_session
from collection.artifact_collector import ServiceArtifactCollector
from collection.base import CollectionContext
from collection.ntfs.collector import ExtractedNtfsArtifacts, NtfsArtifactCollector
from collection.service_catalog import ServiceDetection
from core.models import (
    ActorClass,
    AgentAttribution,
    ArtifactRecord,
    EvidenceSource,
    NormalizedEvent,
    SourceKind,
)
from parsers.base import ParseContext
from parsers.codex import expand_codex_embedded_transcript
from parsers.registry import ParserRegistry
from reporting.exporters import (
    CaseReport,
    FileAttributionRow,
    SessionSummaryRow,
    build_agent_sections,
    build_prompt_title_rows,
    export_activity_csv,
    export_case_report_json,
    export_html_report,
    render_html_report,
)
from reporting.parsed_writer import write_parsed_events
from utils.case_loader import CaseLoadError, load_case
from utils.case_paths import CasePaths, create_case_paths
from utils.evidence_access import SourceAccessError, open_evidence_accessor
from version import __version__


SERVICES = ("All services", "Claude Cowork", "Claude Code", "Antigravity", "Codex")
LOCAL_SERVICES = ("Claude Cowork", "Claude Code", "Antigravity", "Codex")
SERVICE_ICON_FILES = {
    "Claude Cowork": "claude.svg",
    "Claude Code": "claude.svg",
    "Antigravity": "antigravity.png",
    "Codex": "codex.svg",
}
SERVICE_ICON_DIR = Path(__file__).resolve().parent / "assets"
NTFS_ACTORS = ("All actors", "AI agent", "Human", "System", "Unknown")
NTFS_ITEM_TYPES = ("Files and folders", "Files only", "Folders only")
NTFS_BEHAVIORS = (
    "All behaviors",
    "create",
    "modify",
    "rename",
    "move",
    "copy",
    "delete_permanent",
    "delete_recycle",
    "metadata_change",
    "logfile_recovered",
)
_ATTRIBUTION_LABELS = {
    "Confirmed": "confirmed",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Not attributed": "none",
}
# A parsed NTFS journal easily yields hundreds of thousands of events; rendering
# them all into a QTableWidget freezes the UI.  Cap what is drawn and tell the
# user to narrow with filters — the full set stays available for filtering.
MAX_DISPLAY_ROWS = 5000
IMAGE_FILTER = "Disk images (*.E01 *.e01 *.raw *.dd *.img *.vhd *.vhdx);;All files (*.*)"
SESSION_KEY_ROLE = Qt.UserRole + 2
EVENT_ID_ROLE = Qt.UserRole + 3
EVENT_COLOR_ROLE = Qt.UserRole + 4
SESSION_SERVICE_ROLE = Qt.UserRole + 5
SESSION_STARTED_ROLE = Qt.UserRole + 6
SESSION_EVENTS_ROLE = Qt.UserRole + 7
EVENT_TYPE_ROLE = Qt.UserRole + 8
EVENT_SUMMARY_ROLE = Qt.UserRole + 9
EVENT_TIME_ROLE = Qt.UserRole + 10
PARSE_NAME_ROLE = Qt.UserRole + 20
PARSE_ARTIFACTS_ROLE = Qt.UserRole + 21
PARSE_RECORDS_ROLE = Qt.UserRole + 22
PARSE_ERRORS_ROLE = Qt.UserRole + 23
PARSE_STATUS_ROLE = Qt.UserRole + 24
PARSE_PROGRESS_ROLE = Qt.UserRole + 25


def _mono_icon(kind: str) -> QIcon:
    pixmap = QPixmap(16, 16)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(QColor("#78716C"), 1.4))
    painter.setBrush(Qt.NoBrush)
    if kind == "folder":
        painter.drawRoundedRect(2, 5, 12, 8, 1, 1)
        painter.drawLine(3, 5, 6, 5)
        painter.drawLine(3, 4, 7, 4)
    elif kind == "drive":
        painter.drawRoundedRect(2, 3, 12, 10, 2, 2)
        painter.drawLine(3, 9, 13, 9)
        painter.drawEllipse(11, 10, 1, 1)
    elif kind == "computer":
        painter.drawRoundedRect(2, 2, 12, 9, 1, 1)
        painter.drawLine(6, 13, 10, 13)
        painter.drawLine(8, 11, 8, 13)
    else:
        painter.drawRoundedRect(3, 2, 10, 12, 1, 1)
        painter.drawLine(5, 6, 11, 6)
        painter.drawLine(5, 9, 11, 9)
    painter.end()
    return QIcon(pixmap)


class ForensicTableWidget(QTableWidget):
    """Keep column guides visible through an empty forensic ledger."""

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt API naming
        super().paintEvent(event)
        if self.rowCount():
            return
        painter = QPainter(self.viewport())
        painter.setPen(QColor("#d1d6da"))
        header = self.horizontalHeader()
        for column in range(self.columnCount() - 1):
            x = header.sectionViewportPosition(column) + header.sectionSize(column) - 1
            painter.drawLine(x, 0, x, self.viewport().height())


class MiddleElideDelegate(QStyledItemDelegate):
    """Preserve both the root and filename when a path column is narrow."""

    def paint(self, painter, option, index) -> None:  # noqa: N802 - Qt API naming
        display = QStyleOptionViewItem(option)
        self.initStyleOption(display, index)
        display.text = display.fontMetrics.elidedText(
            display.text,
            Qt.ElideMiddle,
            max(0, display.rect.width() - 10),
        )
        style = display.widget.style() if display.widget is not None else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, display, painter, display.widget)


class ParserOption(QFrame):
    """Compact parser selector used by the parse-plan matrix."""

    def __init__(
        self,
        name: str,
        parser_id: str | None,
        state: str,
        *,
        locked: bool = False,
        icon_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, objectName="ParserOption")
        self.parser_id = parser_id
        self.setProperty("selected", False)
        self.setProperty("available", parser_id is not None)
        self.setMinimumHeight(48)
        if parser_id is not None:
            self.setCursor(Qt.PointingHandCursor)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(8)

        if locked:
            control: QCheckBox | QRadioButton = QRadioButton()
            control.setAutoExclusive(False)
            control.setChecked(True)
            control.setEnabled(False)
        else:
            control = QCheckBox()
            control.setEnabled(parser_id is not None)
        control.setAccessibleName(f"Select {name} parser")
        layout.addWidget(control, 0, Qt.AlignTop)
        self.control = control

        self.icon_label = QLabel(objectName="ParserServiceIcon")
        self.icon_label.setFixedSize(24, 24)
        self.icon_label.setAlignment(Qt.AlignCenter)
        if icon_path is not None and icon_path.is_file():
            self.icon_label.setPixmap(QIcon(str(icon_path)).pixmap(QSize(20, 20)))
            self.icon_label.setAccessibleName(f"{name} service icon")
            layout.addWidget(self.icon_label, 0, Qt.AlignVCenter)
        else:
            self.icon_label.hide()

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)
        self.name_label = QLabel(name, objectName="ParserOptionName")
        self.state_label = QLabel(state, objectName="ParserOptionState")
        text_layout.addWidget(self.name_label)
        text_layout.addWidget(self.state_label)
        layout.addLayout(text_layout, 1)
        self.selected_badge = QLabel("SELECTED", objectName="ParserSelectedBadge")
        self.selected_badge.setAlignment(Qt.AlignCenter)
        self.selected_badge.setVisible(False)
        layout.addWidget(self.selected_badge, 0, Qt.AlignVCenter)
        control.toggled.connect(self._sync_selected_style)
        self._sync_selected_style(control.isChecked())

    def isChecked(self) -> bool:  # noqa: N802 - mirrors Qt controls
        return self.control.isChecked()

    def setChecked(self, checked: bool) -> None:  # noqa: N802
        self.control.setChecked(checked)

    def set_state(self, state: str, *, available: bool | None = None) -> None:
        self.state_label.setText(state)
        if available is not None:
            self.setProperty("available", available)
            if isinstance(self.control, QCheckBox):
                self.control.setEnabled(available)
            self.setCursor(Qt.PointingHandCursor if available else Qt.ArrowCursor)
        self._refresh_style()

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt API naming
        if self.control.isEnabled():
            self.control.toggle()
            event.accept()
            return
        super().mousePressEvent(event)

    def _sync_selected_style(self, checked: bool) -> None:
        self.setProperty("selected", checked)
        self.selected_badge.setVisible(checked)
        self._refresh_style()

    def _refresh_style(self) -> None:
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()


class ParseTimelineDelegate(QStyledItemDelegate):
    """Paint parse jobs as a connected execution rail instead of table rows."""

    def sizeHint(self, option, index) -> QSize:  # noqa: N802 - Qt API naming
        return QSize(option.rect.width(), 62)

    def paint(self, painter, option, index) -> None:  # noqa: N802 - Qt API naming
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = option.rect.adjusted(0, 0, -1, -1)
        if option.state & QStyle.State_Selected:
            painter.fillRect(rect, QColor("#EEF2FF"))

        status = str(index.data(PARSE_STATUS_ROLE) or "Waiting")
        progress = int(index.data(PARSE_PROGRESS_ROLE) or 0)
        errors = int(index.data(PARSE_ERRORS_ROLE) or 0)
        marker_x = rect.left() + 18
        center_y = rect.top() + 18
        line_color = QColor("#E7E5E4")
        painter.setPen(QPen(line_color, 1))
        if index.row() > 0:
            painter.drawLine(marker_x, rect.top(), marker_x, center_y - 6)
        if index.row() + 1 < index.model().rowCount():
            painter.drawLine(marker_x, center_y + 6, marker_x, rect.bottom())

        if status in ("Failed",):
            marker = QColor("#B91C1C")
        elif errors or "warning" in status.casefold():
            marker = QColor("#B45309")
        elif status in ("Completed", "Loaded"):
            marker = QColor("#4F46E5")
        elif status == "Running":
            marker = QColor("#4F46E5")
        else:
            marker = QColor("#A8A29E")
        painter.setPen(QPen(marker, 2))
        painter.setBrush(marker if status in ("Completed", "Loaded", "Running") else QColor("#FFFFFF"))
        painter.drawEllipse(QRect(marker_x - 5, center_y - 5, 10, 10))

        content_left = marker_x + 18
        content_right = rect.right() - 12
        name_font = QFont(option.font)
        name_font.setWeight(QFont.DemiBold)
        painter.setFont(name_font)
        painter.setPen(QColor("#1C1917"))
        painter.drawText(
            QRect(content_left, rect.top() + 8, content_right - content_left - 110, 20),
            Qt.AlignVCenter | Qt.AlignLeft,
            str(index.data(PARSE_NAME_ROLE) or "Unknown parser"),
        )
        status_font = QFont(option.font)
        status_font.setPointSizeF(max(8.0, option.font.pointSizeF() - 1))
        status_font.setWeight(QFont.DemiBold)
        painter.setFont(status_font)
        painter.setPen(marker)
        status_text = f"{status}{f'  {progress}%' if status == 'Running' else ''}"
        status_width = max(105, painter.fontMetrics().horizontalAdvance(status_text) + 14)
        painter.drawText(
            QRect(content_right - status_width, rect.top() + 8, status_width, 20),
            Qt.AlignVCenter | Qt.AlignRight,
            status_text,
        )

        artifacts = int(index.data(PARSE_ARTIFACTS_ROLE) or 0)
        records = int(index.data(PARSE_RECORDS_ROLE) or 0)
        diagnostic_label = "warnings" if "warning" in status.casefold() else "errors"
        meta = (
            f"{artifacts:,} artifacts  ·  {records:,} records  ·  "
            f"{errors:,} {diagnostic_label}"
        )
        painter.setFont(status_font)
        painter.setPen(QColor("#78716C"))
        painter.drawText(
            QRect(content_left, rect.top() + 31, content_right - content_left, 18),
            Qt.AlignVCenter | Qt.AlignLeft,
            meta,
        )
        if status == "Running":
            bar = QRect(content_left, rect.bottom() - 7, max(0, content_right - content_left), 3)
            painter.fillRect(bar, QColor("#E7E5E4"))
            filled = QRect(bar.left(), bar.top(), round(bar.width() * progress / 100), bar.height())
            painter.fillRect(filled, QColor("#4F46E5"))
        painter.restore()


class SessionListDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index) -> None:  # noqa: N802
        painter.save()
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        rect = option.rect.adjusted(0, 0, 0, -6)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#EEF2FF" if selected else "#F5F5F4" if hovered else "#FFFFFF"))
        painter.drawRoundedRect(rect, 6, 6)
        if selected:
            painter.fillRect(rect.left(), rect.top() + 4, 3, rect.height() - 8, QColor("#4F46E5"))

        session_id = str(index.data(Qt.DisplayRole) or "")
        service = str(index.data(SESSION_SERVICE_ROLE) or "")
        started = str(index.data(SESSION_STARTED_ROLE) or "")
        events = int(index.data(SESSION_EVENTS_ROLE) or 0)
        content = rect.adjusted(12, 7, -12, -5)

        painter.setPen(QColor("#1C1917"))
        painter.setFont(QFont("Consolas", 10, QFont.DemiBold))
        painter.drawText(content, Qt.AlignLeft | Qt.AlignTop, session_id)

        painter.setPen(QColor("#78716C"))
        painter.setFont(QFont("Segoe UI", 8))
        meta_y = content.top() + 24
        painter.drawText(content.left(), meta_y, f"{service}  ·  {started}")
        event_text = f"{events:,} events"
        event_width = painter.fontMetrics().horizontalAdvance(event_text)
        painter.drawText(content.right() - event_width, meta_y, event_text)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        return QSize(option.rect.width(), 58)


class ConversationDelegate(QStyledItemDelegate):
    """Render evidence events as a readable conversation with quiet activity rows."""

    _KIND_COLORS = {
        "USER": "#3F6F72", "AGENT": "#57534E", "TOOL": "#6D5D8C",
        "OUT": "#4F7459", "THINK": "#806F3E", "LOG": "#78716C", "EVENT": "#57534E",
    }
    _MESSAGE_KINDS = {"USER", "AGENT"}

    @staticmethod
    def _viewport_width(option, parent) -> int:
        width = parent.viewport().width() if parent is not None else option.rect.width()
        return max(360, width)

    def _message_geometry(self, option, index) -> tuple[int, int, int]:
        parent = self.parent()
        width = self._viewport_width(option, parent)
        text = str(index.data(EVENT_SUMMARY_ROLE) or "")
        body_font = QFont("Segoe UI", 9)
        metrics = QFontMetrics(body_font)
        max_bubble = max(260, int(width * 0.72))
        longest_line = max((metrics.horizontalAdvance(line) for line in text.splitlines()), default=0)
        bubble_width = min(max_bubble, max(210, longest_line + 30))
        text_width = max(160, bubble_width - 24)
        bounds = metrics.boundingRect(
            QRect(0, 0, text_width, 100000),
            Qt.TextWordWrap | Qt.AlignLeft | Qt.AlignTop,
            text,
        )
        body_height = max(metrics.height(), bounds.height())
        bubble_height = 12 + 18 + body_height + 18 + 10
        return bubble_width, bubble_height, body_height

    def _activity_height(self, option, index) -> int:
        width = self._viewport_width(option, self.parent())
        text = str(index.data(EVENT_SUMMARY_ROLE) or "")
        metrics = QFontMetrics(QFont("Segoe UI", 8))
        bounds = metrics.boundingRect(
            QRect(0, 0, max(180, width - 170), 100000),
            Qt.TextWordWrap | Qt.AlignLeft | Qt.AlignTop,
            text,
        )
        return max(36, bounds.height() + 18)

    def paint(self, painter, option, index) -> None:  # noqa: N802 - Qt API naming
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = option.rect.adjusted(8, 4, -8, -6)
        selected = bool(option.state & QStyle.State_Selected)
        kind = str(index.data(EVENT_TYPE_ROLE) or "EVENT")
        summary = str(index.data(EVENT_SUMMARY_ROLE) or "")
        stamp = str(index.data(EVENT_TIME_ROLE) or "")
        if kind in self._MESSAGE_KINDS:
            bubble_width, bubble_height, body_height = self._message_geometry(option, index)
            is_user = kind == "USER"
            x = rect.right() - bubble_width if is_user else rect.left()
            bubble = QRect(x, rect.top(), bubble_width, bubble_height)
            background = QColor("#EEF2FF" if is_user else "#FFFFFF")
            border = QColor("#4F46E5" if selected else "#C7D2FE" if is_user else "#E7E5E4")
            painter.setPen(QPen(border, 1.5 if selected else 1))
            painter.setBrush(background)
            painter.drawRoundedRect(bubble, 6, 6)

            content = bubble.adjusted(12, 9, -12, -8)
            painter.setFont(QFont("Segoe UI", 8, QFont.DemiBold))
            painter.setPen(QColor("#4F46E5" if is_user else "#57534E"))
            painter.drawText(
                QRect(content.left(), content.top(), content.width(), 16),
                Qt.AlignRight if is_user else Qt.AlignLeft,
                "USER" if is_user else "AGENT",
            )
            painter.setFont(QFont("Segoe UI", 9))
            painter.setPen(QColor("#1C1917"))
            painter.drawText(
                QRect(content.left(), content.top() + 21, content.width(), body_height),
                Qt.TextWordWrap | Qt.AlignLeft | Qt.AlignTop,
                summary,
            )
            painter.setFont(QFont("Consolas", 8))
            painter.setPen(QColor("#78716C"))
            painter.drawText(
                QRect(content.left(), bubble.bottom() - 22, content.width(), 14),
                Qt.AlignRight,
                stamp,
            )
        else:
            if selected:
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor("#EEF2FF"))
                painter.drawRoundedRect(rect, 5, 5)
            badge_width = 58
            badge = QRect(rect.left() + 12, rect.top() + 7, badge_width, 20)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#F5F5F4"))
            painter.drawRoundedRect(badge, 4, 4)
            painter.setPen(QColor(self._KIND_COLORS.get(kind, "#57534E")))
            painter.setFont(QFont("Segoe UI", 8, QFont.DemiBold))
            painter.drawText(badge, Qt.AlignCenter, kind)
            painter.setFont(QFont("Segoe UI", 8))
            painter.setPen(QColor("#57534E"))
            painter.drawText(
                QRect(badge.right() + 10, rect.top() + 8, rect.width() - badge_width - 116, rect.height() - 10),
                Qt.TextWordWrap | Qt.AlignLeft | Qt.AlignTop,
                summary,
            )
            painter.setFont(QFont("Consolas", 8))
            painter.setPen(QColor("#A8A29E"))
            painter.drawText(
                QRect(rect.right() - 64, rect.top() + 8, 54, 14),
                Qt.AlignRight,
                stamp,
            )
        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        kind = str(index.data(EVENT_TYPE_ROLE) or "EVENT")
        if kind in self._MESSAGE_KINDS:
            return QSize(option.rect.width(), self._message_geometry(option, index)[1] + 12)
        return QSize(option.rect.width(), self._activity_height(option, index) + 8)


class EventDetailsDialog(QDialog):
    """Reusable modeless inspector for one conversation event."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("EventDetailsDialog")
        self.setWindowTitle("Event Details")
        self.setModal(False)
        self.setMinimumSize(620, 480)
        self.resize(760, 640)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        self.heading = QLabel("Event details", objectName="SectionTitle")
        layout.addWidget(self.heading)
        self.content = QTextBrowser(objectName="StructuredDetails")
        self.content.setOpenExternalLinks(False)
        self.content.setAccessibleName("Selected conversation event details")
        layout.addWidget(self.content, 1)

        actions = QHBoxLayout()
        actions.addStretch()
        copy_button = QPushButton("Copy")
        copy_button.setAccessibleName("Copy event details")
        copy_button.clicked.connect(
            lambda: QApplication.clipboard().setText(self.content.toPlainText())
        )
        actions.addWidget(copy_button)
        close_button = QPushButton("Close")
        close_button.setAccessibleName("Close event details")
        close_button.clicked.connect(self.close)
        actions.addWidget(close_button)
        layout.addLayout(actions)

    def set_event(self, event: NormalizedEvent) -> None:
        marker, kind = _event_kind(event)
        summary = _event_summary(event, kind) or event.event_type
        self.setWindowTitle(f"Event Details — {event.service or 'Unknown'}")
        self.heading.setText(f"{marker}  {_truncate(_oneline(summary), 120)}")
        self.content.setHtml(_event_detail_html(event))
        self.content.verticalScrollBar().setValue(0)


class MainWindow(QMainWindow):
    def __init__(
        self,
        parser_registry: ParserRegistry | None = None,
        artifact_collector: ServiceArtifactCollector | None = None,
    ) -> None:
        super().__init__()
        self.parser_registry = parser_registry or ParserRegistry()
        self.artifact_collector = artifact_collector or ServiceArtifactCollector()
        self.ntfs_collector = NtfsArtifactCollector()
        self.ntfs_verdicts: tuple[OperationVerdict, ...] = ()
        self._ntfs_status = ""
        self.ntfs_folder_artifacts: tuple[ExtractedNtfsArtifacts, ...] = ()
        self.current_source: EvidenceSource | None = None
        self.service_detections: tuple[ServiceDetection, ...] = ()
        self.collected_artifacts: tuple[ArtifactRecord, ...] = ()
        self.collection_root: Path | None = None
        self.parsed_events: tuple[NormalizedEvent, ...] = ()
        self.case_paths: CasePaths | None = None
        self.service_parser_options: dict[str, ParserOption] = {}
        self.parser_options: dict[str, ParserOption] = {}
        self.service_parsers = {
            service: parser
            for parser in self.parser_registry.all()
            for service in parser.metadata.services
        }
        self.setWindowTitle("TraceAgent")
        self.resize(1440, 900)
        self.setMinimumSize(1120, 720)
        self._build_menu()
        self._build_toolbar()
        self.setCentralWidget(self._build_content())
        self.statusBar().showMessage("Ready — no evidence source loaded")
        self.evidence_mode_label = QLabel("READ-ONLY", objectName="EvidenceModeStatus")
        self.statusBar().addPermanentWidget(self.evidence_mode_label)
        self.version_label = QLabel(f"VERSION  {__version__}", objectName="VersionLabel")
        self.version_label.setToolTip(f"TraceAgent {__version__}")
        self.statusBar().addPermanentWidget(self.version_label)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")
        self.open_case_action = QAction("Open Case…", self)
        self.open_case_action.setShortcut("Ctrl+O")
        self.open_case_action.triggered.connect(self._browse_case)
        file_menu.addAction(self.open_case_action)
        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        export_menu = self.menuBar().addMenu("Export")
        self.export_actions: dict[str, QAction] = {}
        export_specs = (
            ("csv", "CSV…", self._export_csv),
            ("json", "JSON…", self._export_json),
            ("html", "HTML Report…", self._export_html_report),
            ("pdf", "PDF Report…", self._export_pdf_report),
        )
        for key, label, handler in export_specs:
            action = QAction(label, self)
            action.setEnabled(False)
            action.triggered.connect(handler)
            export_menu.addAction(action)
            self.export_actions[key] = action

        edit_menu = self.menuBar().addMenu("Edit")
        self.copy_action = QAction("Copy", self)
        self.copy_action.setShortcut("Ctrl+C")
        self.copy_action.triggered.connect(self._copy_selection)
        edit_menu.addAction(self.copy_action)

        view_menu = self.menuBar().addMenu("View")
        for index, (label, shortcut) in enumerate(
            (("Collection", "Alt+1"), ("Parsing", "Alt+2"), ("Analysis", "Alt+3"))
        ):
            action = QAction(label, self)
            action.setShortcut(shortcut)
            action.triggered.connect(lambda _checked=False, tab=index: self.tabs.setCurrentIndex(tab))
            view_menu.addAction(action)

        tools_menu = self.menuBar().addMenu("Tools")
        self.hash_action = QAction("Calculate SHA-256", self)
        self.hash_action.setCheckable(True)
        self.hash_action.setChecked(True)
        self.hash_action.toggled.connect(
            lambda checked: self.hash_check.setChecked(checked) if hasattr(self, "hash_check") else None
        )
        tools_menu.addAction(self.hash_action)
        filter_action = QAction("Focus Filter", self)
        filter_action.setShortcut("Ctrl+F")
        filter_action.triggered.connect(self._focus_filter)
        tools_menu.addAction(filter_action)
        self.filter_action = filter_action

        help_menu = self.menuBar().addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        self.menuBar().removeAction(export_menu.menuAction())
        self.menuBar().insertMenu(help_menu.menuAction(), export_menu)

    def _build_toolbar(self) -> None:
        self.open_case_action.setIcon(self.style().standardIcon(QStyle.SP_DirIcon))
        self.open_case_action.setToolTip("Open a saved TraceAgent case read-only")
        self.load_source_action = QAction(
            self.style().standardIcon(QStyle.SP_BrowserReload), "Load selected source", self
        )
        self.load_source_action.setToolTip("Load selected source read-only")
        self.load_source_action.triggered.connect(
            lambda: self._load_source() if hasattr(self, "load_button") else None
        )
        self.collect_action = QAction(
            self.style().standardIcon(QStyle.SP_DriveHDIcon), "Collect artifacts", self
        )
        self.collect_action.setToolTip("Collect artifacts")
        self.collect_action.setEnabled(False)
        self.collect_action.triggered.connect(
            lambda: self._collect_artifacts() if hasattr(self, "collect_button") else None
        )
        self.parse_action = QAction(
            self.style().standardIcon(QStyle.SP_ArrowForward), "Run parsers", self
        )
        self.parse_action.setToolTip("Run selected parsers")
        self.parse_action.setEnabled(False)
        self.parse_action.triggered.connect(
            lambda: self._run_selected_parsers() if hasattr(self, "parse_button") else None
        )
        self.export_actions["csv"].setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.export_actions["csv"].setToolTip("Export activity as CSV")
        self.export_actions["json"].setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.export_actions["json"].setToolTip("Export case data as JSON")
        self.export_actions["html"].setIcon(self.style().standardIcon(QStyle.SP_FileDialogInfoView))
        self.export_actions["html"].setToolTip("Export HTML report")
        self.export_actions["pdf"].setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.export_actions["pdf"].setToolTip("Export PDF report")
        self.filter_action.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.filter_action.setToolTip("Focus the active analysis filter")
        self.filter_action.setEnabled(False)
        self.source_info_action = QAction(
            self.style().standardIcon(QStyle.SP_MessageBoxInformation), "Source information", self
        )
        self.source_info_action.setToolTip("Evidence source information")
        self.source_info_action.setEnabled(False)
        self.source_info_action.triggered.connect(self._show_source_info)
        toolbar = QToolBar("Main", self)
        toolbar.setObjectName("MainToolBar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for action, label in (
            (self.open_case_action, "Open Case"), (self.load_source_action, "Load"),
            (self.collect_action, "Collect"), (self.parse_action, "Parse"),
            (self.export_actions["csv"], "CSV"), (self.export_actions["json"], "JSON"),
            (self.export_actions["html"], "HTML"), (self.export_actions["pdf"], "PDF"),
            (self.filter_action, "Filter"), (self.source_info_action, "Source info"),
        ):
            action.setIconText(label)
        toolbar.addAction(self.open_case_action)
        toolbar.addAction(self.load_source_action)
        toolbar.addSeparator()
        toolbar.addAction(self.collect_action)
        toolbar.addAction(self.parse_action)
        toolbar.addSeparator()
        toolbar.addAction(self.export_actions["csv"])
        toolbar.addAction(self.export_actions["json"])
        toolbar.addAction(self.export_actions["html"])
        toolbar.addAction(self.export_actions["pdf"])
        toolbar.addSeparator()
        toolbar.addAction(self.filter_action)
        toolbar.addAction(self.source_info_action)
        self.addToolBar(toolbar)

    def _copy_selection(self) -> None:
        widget = QApplication.focusWidget()
        if isinstance(widget, (QLineEdit, QTextEdit, QTextBrowser)):
            widget.copy()
            return
        if isinstance(widget, QTableWidget):
            ranges = widget.selectedRanges()
            if not ranges:
                return
            selected = ranges[0]
            lines = []
            for row in range(selected.topRow(), selected.bottomRow() + 1):
                values = []
                for column in range(selected.leftColumn(), selected.rightColumn() + 1):
                    item = widget.item(row, column)
                    values.append(item.text() if item else "")
                lines.append("\t".join(values))
            QApplication.clipboard().setText("\n".join(lines))
        elif isinstance(widget, QTreeWidget) and widget.currentItem() is not None:
            item = widget.currentItem()
            QApplication.clipboard().setText(
                "\t".join(item.text(column) for column in range(widget.columnCount()))
            )

    def _focus_filter(self) -> None:
        if not hasattr(self, "tabs"):
            return
        if self.tabs.currentIndex() == 2 and hasattr(self, "analyze_tabs"):
            target = self.la_search if self.analyze_tabs.currentIndex() == 0 else self.ntfs_search
            target.setFocus()
            target.selectAll()

    def _show_source_info(self) -> None:
        if self.current_source is None:
            return
        source = self.current_source
        QMessageBox.information(
            self,
            "Evidence Source",
            "\n".join(
                (
                    f"Type: {source.kind.value}",
                    f"Label: {source.label}",
                    f"Location: {source.location}",
                    f"Access: {'Read-only' if source.read_only else 'Read/write'}",
                )
            ),
        )

    def _build_content(self) -> QWidget:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(4, 4, 4, 4)
        root_layout.setSpacing(0)
        workspace = QSplitter(Qt.Horizontal)
        workspace.setObjectName("WorkspaceSplitter")

        main = QWidget()
        layout = QVBoxLayout(main)
        layout.setContentsMargins(4, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self._build_source_bar())
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.tabs.tabBar().setDrawBase(True)
        self.tabs.addTab(self._build_collect_tab(), "Collection")
        self.tabs.addTab(self._build_parse_tab(), "Parsing")
        self.tabs.addTab(self._build_analyze_tab(), "Analysis")
        layout.addWidget(self.tabs, 1)
        workspace.addWidget(self._build_workspace_panel())
        workspace.addWidget(main)
        workspace.setStretchFactor(0, 0)
        workspace.setStretchFactor(1, 1)
        workspace.setHandleWidth(8)
        workspace.setSizes((260, 1160))
        grip_layout = QVBoxLayout(workspace.handle(1))
        grip_layout.setContentsMargins(0, 0, 0, 0)
        grip_layout.addStretch()
        grip_layout.addWidget(QLabel("⋮", objectName="SplitterGrip"))
        grip_layout.addStretch()
        root_layout.addWidget(workspace, 1)
        return root

    def _build_workspace_panel(self) -> QFrame:
        panel = QFrame(objectName="WorkspacePanel")
        panel.setMinimumWidth(180)
        panel.setMaximumWidth(420)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)
        layout.addWidget(QLabel("CASE EXPLORER", objectName="PaneTitle"))
        self.workspace_tree = QTreeWidget()
        self.workspace_tree.setObjectName("WorkspaceTree")
        self.workspace_tree.setIconSize(QSize(16, 16))
        self.workspace_tree.setHeaderHidden(True)
        self.workspace_tree.setIndentation(18)
        self.workspace_tree.setRootIsDecorated(True)
        self.workspace_tree.setItemsExpandable(True)
        self.case_item = QTreeWidgetItem(("Untitled case",))
        self.case_item.setIcon(0, _mono_icon("folder"))
        self.source_group_item = QTreeWidgetItem(("Evidence Sources",))
        self.source_group_item.setIcon(0, _mono_icon("drive"))
        self.source_value_item = QTreeWidgetItem(("No source",))
        self.source_value_item.setIcon(0, _mono_icon("computer"))
        self.source_value_item.setData(0, Qt.UserRole, "collection")
        self.source_group_item.addChild(self.source_value_item)
        self.artifacts_item = QTreeWidgetItem(("Artifacts",))
        self.artifacts_item.setIcon(0, _mono_icon("folder"))
        self.artifacts_item.setData(0, Qt.UserRole, "collection")
        self.parsers_item = QTreeWidgetItem(("Parser Output",))
        self.parsers_item.setIcon(0, _mono_icon("document"))
        self.parsers_item.setData(0, Qt.UserRole, "parsing")
        self.results_item = QTreeWidgetItem(("Analysis Results",))
        self.results_item.setIcon(0, _mono_icon("document"))
        self.results_item.setData(0, Qt.UserRole, "analysis")
        for item in (self.source_group_item, self.artifacts_item, self.parsers_item, self.results_item):
            self.case_item.addChild(item)
        self.workspace_tree.addTopLevelItem(self.case_item)
        self.case_item.setExpanded(True)
        self.source_group_item.setExpanded(True)
        self.workspace_tree.itemSelectionChanged.connect(self._workspace_nav_changed)
        layout.addWidget(self.workspace_tree, 1)
        return panel

    def _workspace_nav_changed(self) -> None:
        item = self.workspace_tree.currentItem()
        target = item.data(0, Qt.UserRole) if item is not None else None
        index = {"collection": 0, "parsing": 1, "analysis": 2}.get(target)
        if index is not None:
            self.tabs.setCurrentIndex(index)

    def _build_source_bar(self) -> QFrame:
        frame = QFrame(objectName="SourceBar")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(6)
        layout.addWidget(QLabel("Source:", objectName="FieldLabel"))
        self.source_kind = QComboBox()
        self.source_kind.addItem("Current PC", "live_system")
        self.source_kind.addItem("Disk image", "disk_image")
        self.source_kind.addItem("Extracted artifact folder", "artifact_directory")
        self.source_kind.currentIndexChanged.connect(self._source_kind_changed)
        self.source_kind.setAccessibleName("Evidence source type")
        layout.addWidget(self.source_kind)
        self.source_path = QLineEdit()
        self.source_path.setPlaceholderText("Local computer (live collection)")
        self.source_path.setReadOnly(True)
        self.source_path.setAccessibleName("Evidence source path")
        self.source_path.textChanged.connect(self._update_source_controls)
        layout.addWidget(self.source_path, 1)
        self.browse_button = QPushButton("Browse…")
        self.browse_button.setAccessibleName("Browse for evidence source")
        self.browse_button.clicked.connect(self._browse_source)
        self.browse_button.setEnabled(False)
        layout.addWidget(self.browse_button)
        self.load_button = QPushButton("Load Source", objectName="AccentButton")
        self.load_button.setAccessibleName("Load evidence source read-only")
        self.load_button.setDefault(True)
        self.load_button.setAutoDefault(True)
        self.load_button.clicked.connect(self._load_source)
        layout.addWidget(self.load_button)
        return frame

    def _build_collect_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)
        controls = QFrame(objectName="Panel")
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(4, 2, 4, 2)
        controls_layout.addWidget(QLabel("Artifacts", objectName="SectionTitle"))
        controls_layout.addStretch()
        self.hash_check = QCheckBox("Calculate SHA-256")
        self.hash_check.setChecked(True)
        self.hash_check.toggled.connect(self.hash_action.setChecked)
        controls_layout.addWidget(self.hash_check)
        self.collect_button = QPushButton("Start Collection")
        self.collect_button.setAccessibleName("Start read-only evidence collection")
        self.collect_button.setEnabled(False)
        self.collect_button.clicked.connect(self._collect_artifacts)
        controls_layout.addWidget(self.collect_button)
        layout.addWidget(controls)
        filter_bar = QFrame(objectName="FilterBar")
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(4, 2, 4, 2)
        filter_layout.setSpacing(5)
        filter_layout.addWidget(QLabel("Filter:", objectName="FieldLabel"))
        self.collection_filter = QLineEdit()
        self.collection_filter.setClearButtonEnabled(True)
        self.collection_filter.setPlaceholderText("Artifact, path, hash, user, status")
        self.collection_filter.textChanged.connect(self._filter_collection_rows)
        filter_layout.addWidget(self.collection_filter, 1)
        filter_layout.addWidget(QLabel("Source:", objectName="FieldLabel"))
        self.collection_source_filter = QComboBox()
        self.collection_source_filter.setMinimumWidth(170)
        self.collection_source_filter.addItem("All sources (0)", "")
        self.collection_source_filter.setAccessibleName("Filter collection results by source")
        self.collection_source_filter.currentIndexChanged.connect(self._filter_collection_rows)
        filter_layout.addWidget(self.collection_source_filter)
        layout.addWidget(filter_bar)
        self.collection_progress = QProgressBar()
        self.collection_progress.setTextVisible(False)
        self.collection_progress.setVisible(False)
        layout.addWidget(self.collection_progress)
        self.collection_table = self._table(
            ("Source", "Artifact", "Path", "Size", "SHA-256", "Status", "User", "Modified", "Original path"),
            2,
        )
        self.collection_table.setColumnWidth(8, 180)
        self.collection_table.horizontalHeader().setSortIndicator(2, Qt.AscendingOrder)
        self.collection_table.horizontalHeader().setSortIndicatorShown(True)
        layout.addWidget(self.collection_table, 1)
        return page

    def _build_parse_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        plan_panel = QFrame(objectName="ParsePlanPanel")
        plan_layout = QVBoxLayout(plan_panel)
        plan_layout.setContentsMargins(12, 10, 12, 12)
        plan_layout.setSpacing(8)
        plan_header = QHBoxLayout()
        plan_header.setContentsMargins(0, 0, 0, 0)
        plan_header.addWidget(QLabel("Parse plan", objectName="SectionTitle"))
        plan_header.addStretch()
        self.parse_plan_summary = QLabel("No parsers selected", objectName="ParsePlanSummary")
        plan_header.addWidget(self.parse_plan_summary)
        self.parse_button = QPushButton("Run Parsers", objectName="AccentButton")
        self.parse_button.setAccessibleName("Run selected parser modules")
        self.parse_button.setEnabled(False)
        self.parse_button.clicked.connect(self._run_selected_parsers)
        plan_header.addWidget(self.parse_button)
        plan_layout.addLayout(plan_header)

        matrix = QGridLayout()
        self.parse_option_grid = matrix
        matrix.setContentsMargins(0, 0, 0, 0)
        matrix.setHorizontalSpacing(6)
        matrix.setVerticalSpacing(6)
        self.parser_options.clear()
        self.service_parser_options.clear()
        self.ntfs_radios: list[tuple[QRadioButton, str]] = []
        row = 0
        for group, children in (
            ("Service artifact parsers", ("Claude Cowork", "Claude Code", "Antigravity", "Codex")),
            ("Filesystem parsers", ("NTFS $MFT", "NTFS $UsnJrnl", "NTFS $LogFile")),
        ):
            columns = 2 if group == "Service artifact parsers" else 3
            column_span = 3 if columns == 2 else 2
            group_label = QLabel(group.upper(), objectName="ParserGroupLabel")
            matrix.addWidget(group_label, row, 0, 1, 6)
            row += 1
            for index, child in enumerate(children):
                parser = self.service_parsers.get(child)
                if parser is None:
                    state = "Parser unavailable"
                elif parser.metadata.implementation_status == "placeholder":
                    state = "Pending implementation"
                else:
                    state = "Ready"
                parser_id = parser.metadata.parser_id if parser is not None else None
                locked = bool(parser and parser.metadata.category == "ntfs")
                icon_file = SERVICE_ICON_FILES.get(child)
                option = ParserOption(
                    child,
                    parser_id,
                    state,
                    locked=locked,
                    icon_path=SERVICE_ICON_DIR / icon_file if icon_file else None,
                )
                option.set_state(
                    state,
                    available=bool(
                        parser
                        and parser.metadata.implementation_status != "placeholder"
                    ),
                )
                if group == "Service artifact parsers":
                    self.service_parser_options[child] = option
                if parser is not None:
                    option.setToolTip(parser.metadata.description)
                    self.parser_options[parser.metadata.parser_id] = option
                    option.control.toggled.connect(self._update_parse_plan_summary)
                    if locked:
                        self.ntfs_radios.append((option.control, parser.metadata.parser_id))
                matrix.addWidget(
                    option,
                    row + index // columns,
                    (index % columns) * column_span,
                    1,
                    column_span,
                )
            row += (len(children) + columns - 1) // columns
        for column in range(6):
            matrix.setColumnStretch(column, 1)
        plan_layout.addLayout(matrix)
        layout.addWidget(plan_panel)

        run_panel = QFrame(objectName="ParseRunPanel")
        run_layout = QVBoxLayout(run_panel)
        run_layout.setContentsMargins(12, 10, 12, 10)
        run_layout.setSpacing(6)
        queue_header = QHBoxLayout()
        queue_header.setContentsMargins(0, 0, 0, 0)
        self.parse_run_title = QLabel("Execution", objectName="SectionTitle")
        queue_header.addWidget(self.parse_run_title)
        self.parse_run_summary = QLabel("No parse run", objectName="Muted")
        queue_header.addWidget(self.parse_run_summary)
        queue_header.addStretch()
        run_layout.addLayout(queue_header)
        self.parse_progress = QProgressBar()
        self.parse_progress.setTextVisible(False)
        self.parse_progress.setVisible(False)
        run_layout.addWidget(self.parse_progress)
        self.parse_timeline = QListWidget(objectName="ParseTimeline")
        self.parse_timeline.setSelectionMode(QAbstractItemView.SingleSelection)
        self.parse_timeline.setItemDelegate(ParseTimelineDelegate(self.parse_timeline))
        self.parse_timeline.setAccessibleName("Parser execution timeline")
        self.parse_timeline.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.parse_timeline.setVisible(False)
        run_layout.addWidget(self.parse_timeline, 1)
        self.parse_empty_state = QLabel(
            "Select detected parsers above, then run the parse plan.",
            objectName="ParseEmptyState",
        )
        self.parse_empty_state.setAlignment(Qt.AlignCenter)
        run_layout.addWidget(self.parse_empty_state, 1)

        activity_header = QHBoxLayout()
        activity_header.setContentsMargins(0, 2, 0, 0)
        self.parse_log_toggle = QPushButton("▸  Activity log", objectName="ActivityToggle")
        self.parse_log_toggle.setCheckable(True)
        self.parse_log_toggle.toggled.connect(self._toggle_parse_log)
        activity_header.addWidget(self.parse_log_toggle)
        activity_header.addStretch()
        self.parse_log_copy = QPushButton("Copy", objectName="QuietButton")
        self.parse_log_copy.clicked.connect(
            lambda: QApplication.clipboard().setText(self.parse_log.toPlainText())
        )
        activity_header.addWidget(self.parse_log_copy)
        run_layout.addLayout(activity_header)
        self.parse_log = QTextEdit()
        self.parse_log.setReadOnly(True)
        self.parse_log.setPlaceholderText("Parser diagnostics and audit messages")
        if self.parser_registry.all():
            self.parse_log.setPlainText(
                "Connected parser modules:\n"
                + "\n".join(
                    f"- {parser.metadata.name} "
                    f"({'pending' if parser.metadata.implementation_status == 'placeholder' else 'ready'})"
                    for parser in self.parser_registry.all()
                )
            )
        self.parse_log.setMaximumHeight(120)
        self.parse_log.setVisible(False)
        run_layout.addWidget(self.parse_log)
        layout.addWidget(run_panel, 1)
        self._update_parse_plan_summary()
        return page

    def _build_analyze_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        self.analyze_tabs = QTabWidget()
        self.analyze_tabs.setDocumentMode(True)
        self.analyze_tabs.addTab(self._build_local_artifacts_view(), "Local artifacts")
        self.analyze_tabs.addTab(self._build_ntfs_events_view(), "NTFS events")
        layout.addWidget(self.analyze_tabs, 1)
        return page

    def _detail_panel(self, title: str, placeholder: str) -> tuple[QFrame, QTextEdit]:
        panel = QFrame(objectName="DetailPanel")
        panel.setMinimumWidth(330)
        detail_layout = QVBoxLayout(panel)
        detail_layout.addWidget(QLabel(title, objectName="SectionTitle"))
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlaceholderText(placeholder)
        detail_layout.addWidget(box, 1)
        return panel, box

    def _build_local_artifacts_view(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 8, 0, 0)
        bar = QFrame(objectName="Panel")
        filters = QHBoxLayout(bar)
        self.la_search = QLineEdit()
        self.la_search.setPlaceholderText("Search session ID, prompt, tool, command, or path")
        self.la_search.setAccessibleName("Search local artifact sessions")
        self.la_search.textChanged.connect(self._refresh_local_tree)
        filters.addWidget(self.la_search, 2)
        filters.addWidget(QLabel("Service:", objectName="FieldLabel"))
        self.la_service_filter = QComboBox()
        self.la_service_filter.setMinimumWidth(160)
        self.la_service_filter.setAccessibleName("Filter sessions by service")
        self.la_service_filter.currentIndexChanged.connect(self._local_service_filter_changed)
        filters.addWidget(self.la_service_filter)
        filters.addWidget(QLabel("Event:", objectName="FieldLabel"))
        self.la_type = QComboBox()
        self.la_type.addItems(
            ("All events", "Prompt", "Thinking", "Tool call", "Result", "Message", "Log")
        )
        self.la_type.currentIndexChanged.connect(self._refresh_local_timeline)
        filters.addWidget(self.la_type)
        self.la_show_low_importance = QCheckBox("Show low-importance events")
        self.la_show_low_importance.setToolTip(
            "Include internal bookkeeping (telemetry, streaming deltas, raw log/session "
            "metadata) that parsers flag as low-signal and hide by default."
        )
        self.la_show_low_importance.toggled.connect(self._local_importance_changed)
        filters.addWidget(self.la_show_low_importance)
        outer.addWidget(bar)

        self._selected_local_service = ""

        splitter = QSplitter(Qt.Horizontal)

        # Left: compact session cards with an explicit sort control.  The
        # minimum leaves room for a full session UUID while still letting the
        # conversation and the interpretation pane have a usable width on a
        # minimum-size window.
        nav = QFrame(objectName="Panel")
        nav.setMinimumWidth(340)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(8, 8, 8, 8)
        session_header_row = QHBoxLayout()
        session_header_row.addWidget(QLabel("Sessions", objectName="SectionTitle"))
        session_header_row.addStretch()
        self.la_session_sort = QComboBox(objectName="CompactSort")
        self.la_session_sort.addItems(("Started ↓", "Started ↑", "Service A–Z", "Events ↓"))
        self.la_session_sort.currentIndexChanged.connect(self._refresh_local_tree)
        session_header_row.addWidget(self.la_session_sort)
        nav_layout.addLayout(session_header_row)
        self.la_count = QLabel("", objectName="Muted")
        nav_layout.addWidget(self.la_count)
        self.la_session_list = QListWidget(objectName="SessionList")
        self.la_session_list.setSpacing(0)
        self.la_session_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.la_session_list.setMouseTracking(True)
        self.la_session_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.la_session_list.setItemDelegate(SessionListDelegate(self.la_session_list))
        self.la_session_list.currentItemChanged.connect(self._on_session_selected)
        nav_layout.addWidget(self.la_session_list, 1)
        splitter.addWidget(nav)

        # Center: conversation/activity timeline for the selected session
        center = QFrame(objectName="Panel")
        center_layout = QVBoxLayout(center)
        center_layout.addWidget(QLabel("Conversation", objectName="SectionTitle"))
        self.la_session_label = QLabel("", objectName="Muted")
        self.la_session_label.setWordWrap(True)
        center_layout.addWidget(self.la_session_label)
        self.la_timeline_list = QListWidget(objectName="TimelineList")
        self.la_timeline_list.setMouseTracking(True)
        self.la_timeline_list.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.la_timeline_list.verticalScrollBar().setSingleStep(18)
        self.la_timeline_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.la_timeline_list.setAccessibleName("Conversation events for the selected session")
        self.la_timeline_list.setItemDelegate(ConversationDelegate(self.la_timeline_list))
        self.la_timeline_list.currentItemChanged.connect(self._on_timeline_selected)
        self.la_timeline_list.itemClicked.connect(self._on_timeline_selected)
        self.la_timeline_list.itemActivated.connect(self._on_timeline_selected)
        center_layout.addWidget(self.la_timeline_list, 1)
        splitter.addWidget(center)

        # Right: what the reconstructed session actually means, in English then
        # Korean — the counterpart of the NTFS view's interpretation panel.  It
        # takes a lower minimum than the NTFS detail panel and stays collapsible
        # so the conversation never loses its readable width on a small screen.
        panel, self.la_interpretation = self._detail_panel("Interpretation / 해석", "")
        panel.setMinimumWidth(240)
        splitter.addWidget(panel)
        splitter.setCollapsible(2, True)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 7)
        splitter.setStretchFactor(2, 4)
        splitter.setSizes((420, 620, 400))
        outer.addWidget(splitter, 1)
        return page

    def _build_ntfs_events_view(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 8, 0, 0)
        bar = QFrame(objectName="Panel")
        filters = QHBoxLayout(bar)
        self.ntfs_search = QLineEdit()
        self.ntfs_search.setPlaceholderText("Search file/folder path or evidence")
        self.ntfs_search.setAccessibleName("Search NTFS file and folder evidence")
        self.ntfs_search.textChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_search, 2)
        self.ntfs_actor = QComboBox()
        self.ntfs_actor.addItems(NTFS_ACTORS)
        self.ntfs_actor.currentIndexChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_actor)
        self.ntfs_item_type = QComboBox()
        self.ntfs_item_type.addItems(NTFS_ITEM_TYPES)
        self.ntfs_item_type.setToolTip(
            "Directories get USN records too (shell folder creation, cache buckets),\n"
            "and on a busy volume they outnumber file activity."
        )
        self.ntfs_item_type.currentIndexChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_item_type)
        self.ntfs_behavior = QComboBox()
        self.ntfs_behavior.addItems(NTFS_BEHAVIORS)
        self.ntfs_behavior.currentIndexChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_behavior)
        self.ntfs_hide_system = QCheckBox("Hide system/background")
        self.ntfs_hide_system.setChecked(True)
        self.ntfs_hide_system.setToolTip(
            "Hide OS/application churn (browser & app temp files with GUID names, caches)."
        )
        self.ntfs_hide_system.stateChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_hide_system)
        outer.addWidget(bar)

        splitter = QSplitter(Qt.Horizontal)
        left = QFrame(objectName="Panel")
        left_layout = QVBoxLayout(left)
        self.ntfs_count = QLabel("", objectName="Muted")
        left_layout.addWidget(self.ntfs_count)
        self.ntfs_table = self._table(
            (
                "Filename",
                "Type",
                "Path",
                "Actor",
                "해석 / Interpretation",
                "Service",
                "Operations",
                "Last activity",
            ),
            4,
        )
        # Interpretation is the column worth the space, so it takes the stretch.
        # Paths would otherwise size to their longest entry and push it off-screen,
        # so give Path a fixed starting width the user can drag.
        self.ntfs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.ntfs_table.setColumnWidth(2, 300)
        self.ntfs_table.setSortingEnabled(True)
        self.ntfs_table.itemSelectionChanged.connect(self._show_ntfs_detail)
        left_layout.addWidget(self.ntfs_table, 1)
        splitter.addWidget(left)
        panel, self.ntfs_detail = self._detail_panel("File activity", "")
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        outer.addWidget(splitter, 1)
        return page

    @staticmethod
    def _table(headers: tuple[str, ...], stretch_column: int) -> QTableWidget:
        table = ForensicTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setFocusPolicy(Qt.StrongFocus)
        table.setShowGrid(True)
        table.verticalHeader().setDefaultSectionSize(24)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionsClickable(True)
        table.horizontalHeader().setSectionsMovable(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for column in range(len(headers)):
            table.setColumnWidth(column, 110)
            if headers[column].casefold().endswith("path"):
                table.setItemDelegateForColumn(column, MiddleElideDelegate(table))
        table.horizontalHeader().setSectionResizeMode(stretch_column, QHeaderView.Stretch)
        return table

    def _source_kind_changed(self) -> None:
        live = self.source_kind.currentData() == "live_system"
        extracted = self.source_kind.currentData() == "artifact_directory"
        self.browse_button.setEnabled(not live)
        self.collect_button.setText("Use Artifact Folder" if extracted else "Start Collection")
        self.source_path.clear()
        self.source_path.setPlaceholderText("Local computer (live collection)" if live else "Select a source path")
        self._update_source_controls()

    def _update_source_controls(self) -> None:
        if not hasattr(self, "load_button"):
            return
        ready = self.source_kind.currentData() == "live_system" or bool(
            self.source_path.text().strip()
        )
        self.load_button.setEnabled(ready)
        self.load_source_action.setEnabled(ready)

    def _filter_collection_rows(self, _value=None) -> None:
        needle = self.collection_filter.text().strip().casefold()
        selected_source = str(self.collection_source_filter.currentData() or "")
        for row in range(self.collection_table.rowCount()):
            source_item = self.collection_table.item(row, 0)
            source = source_item.text() if source_item is not None else ""
            haystack = " ".join(
                self.collection_table.item(row, column).text()
                if self.collection_table.item(row, column) is not None
                else ""
                for column in range(self.collection_table.columnCount())
            ).casefold()
            hidden = (bool(selected_source) and source != selected_source) or (
                bool(needle) and needle not in haystack
            )
            self.collection_table.setRowHidden(row, hidden)

    def _refresh_collection_source_filter(self) -> None:
        current = str(self.collection_source_filter.currentData() or "")
        counts = Counter(
            self.collection_table.item(row, 0).text()
            for row in range(self.collection_table.rowCount())
            if self.collection_table.item(row, 0) is not None
        )
        self.collection_source_filter.blockSignals(True)
        self.collection_source_filter.clear()
        self.collection_source_filter.addItem(
            f"All sources ({sum(counts.values()):,})", ""
        )
        selected_index = 0
        ordered = [source for source in SERVICES[1:] if source in counts]
        ordered += sorted(set(counts) - set(ordered))
        for source in ordered:
            self.collection_source_filter.addItem(f"{source} ({counts[source]:,})", source)
            if source == current:
                selected_index = self.collection_source_filter.count() - 1
        self.collection_source_filter.setCurrentIndex(selected_index)
        self.collection_source_filter.blockSignals(False)
        self._filter_collection_rows()

    def _clear_collection_rows(self) -> None:
        self.collection_table.setRowCount(0)
        self._refresh_collection_source_filter()

    def _browse_case(self) -> None:
        default_root = Path.home() / "Documents" / "traceagent"
        path = QFileDialog.getExistingDirectory(
            self,
            "Open TraceAgent Case",
            str(default_root if default_root.is_dir() else Path.home()),
        )
        if path:
            self._open_case_folder(Path(path))

    def _open_case_folder(self, case_root: Path) -> bool:
        self.open_case_action.setEnabled(False)
        self.statusBar().showMessage(f"Opening saved case read-only: {case_root}")
        QApplication.processEvents()
        try:
            loaded = load_case(case_root)
        except (CaseLoadError, OSError) as exc:
            QMessageBox.critical(self, "Open Case", str(exc))
            self.statusBar().showMessage("Failed to open saved case")
            return False
        finally:
            self.open_case_action.setEnabled(True)

        if any(event.parser_id.startswith("ntfs.") for event in loaded.events):
            outcome = attribute_ntfs_events(loaded.events)
            self.ntfs_verdicts = outcome.verdicts
            self.parsed_events = tuple(sorted(outcome.events, key=lambda event: event.timestamp))
        else:
            self.ntfs_verdicts = ()
            self.parsed_events = loaded.events

        self.current_source = loaded.source
        self.case_paths = loaded.paths
        self.collection_root = loaded.paths.artifacts
        self.collected_artifacts = loaded.artifacts
        self.service_detections = ()
        self.ntfs_folder_artifacts = ()
        self._ntfs_status = ""
        self.setWindowTitle(f"TraceAgent - {loaded.paths.root.name}")

        artifact_index = self.source_kind.findData("artifact_directory")
        self.source_kind.blockSignals(True)
        self.source_kind.setCurrentIndex(artifact_index)
        self.source_kind.blockSignals(False)
        self.source_path.setText(str(loaded.paths.root))
        self.source_path.setPlaceholderText("Saved TraceAgent case")
        self.collect_button.setText("Start Collection")

        self.case_item.setText(0, loaded.paths.root.name)
        self.source_value_item.setText(0, "Saved case (read-only)")
        self.source_value_item.setIcon(0, _mono_icon("folder"))
        self.source_value_item.setToolTip(0, str(loaded.paths.root))
        self.artifacts_item.setText(0, f"Artifacts ({len(loaded.artifacts):,})")
        self.parsers_item.setText(0, f"Parser Output ({len(loaded.events):,})")

        self._clear_collection_rows()
        for record in loaded.artifacts:
            self._append_collection_row(
                (
                    record.service or "Unknown",
                    record.artifact_type,
                    record.path,
                    _format_size(record.size),
                    record.sha256 or "Not calculated",
                    "Loaded",
                    str(record.metadata.get("user") or ""),
                    str(record.metadata.get("modified_time") or ""),
                    record.original_path or "",
                )
            )
        self._refresh_collection_source_filter()
        self._populate_loaded_parse_table()
        self._sync_service_parser_checks()
        self._update_parse_service_states()
        self._populate_analyze_views()

        has_events = bool(self.parsed_events)
        for action in self.export_actions.values():
            action.setEnabled(has_events)
        self.filter_action.setEnabled(has_events)
        self.source_info_action.setEnabled(True)
        self.collect_button.setEnabled(False)
        self.collect_action.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.parse_action.setEnabled(False)
        self.load_button.setEnabled(False)
        self.load_source_action.setEnabled(False)
        self.parse_log.setPlainText(
            f"Loaded {len(loaded.events):,} parsed event(s) from {loaded.paths.parsed}."
            + (
                f"\n{len(loaded.issues):,} malformed or missing record(s) were skipped."
                if loaded.issues
                else ""
            )
        )
        self.parse_progress.setValue(0)
        self.parse_progress.setVisible(False)
        self.tabs.setCurrentIndex(2 if has_events else 0)
        if has_events:
            self.analyze_tabs.setCurrentIndex(
                1
                if all(event.parser_id.startswith("ntfs.") for event in self.parsed_events)
                else 0
            )
        self.statusBar().showMessage(
            f"Loaded case read-only: {loaded.paths.root.name}; "
            f"{len(loaded.artifacts):,} artifacts, {len(loaded.events):,} parsed events"
            + (f", {len(loaded.issues):,} warning(s)" if loaded.issues else "")
        )
        return True

    def _populate_loaded_parse_table(self) -> None:
        self._reset_parse_runs("Previous run")
        event_counts = Counter(event.parser_id for event in self.parsed_events)
        artifact_counts = Counter(record.service for record in self.collected_artifacts)
        for parser_id, event_count in sorted(event_counts.items()):
            try:
                parser = self.parser_registry.get(parser_id)
            except KeyError:
                parser = None
            name = parser.metadata.name if parser is not None else parser_id
            artifact_count = (
                sum(artifact_counts.get(service, 0) for service in parser.metadata.services)
                if parser is not None
                else 0
            )
            self._append_parse_run(
                parser_id,
                name,
                artifacts=artifact_count,
                records=event_count,
                errors=0,
                status="Loaded",
            )
        self.parse_run_summary.setText(
            f"{len(event_counts):,} parsers · {len(self.parsed_events):,} records"
        )

    def _reset_parse_runs(self, title: str = "Execution") -> None:
        self.parse_run_title.setText(title)
        self.parse_timeline.clear()
        self._parse_run_items: dict[str, QListWidgetItem] = {}
        self.parse_timeline.setVisible(False)
        self.parse_empty_state.setVisible(True)
        self.parse_run_summary.setText("No parse run")

    def _append_parse_run(
        self,
        parser_id: str,
        name: str,
        *,
        artifacts: int = 0,
        records: int = 0,
        errors: int = 0,
        status: str = "Waiting",
        progress: int = 0,
    ) -> QListWidgetItem:
        item = QListWidgetItem()
        item.setData(PARSE_NAME_ROLE, name)
        item.setData(PARSE_ARTIFACTS_ROLE, artifacts)
        item.setData(PARSE_RECORDS_ROLE, records)
        item.setData(PARSE_ERRORS_ROLE, errors)
        item.setData(PARSE_STATUS_ROLE, status)
        item.setData(PARSE_PROGRESS_ROLE, progress)
        item.setText(f"{name}: {status}, {artifacts:,} artifacts, {records:,} records")
        item.setSizeHint(QSize(0, 62))
        self.parse_timeline.addItem(item)
        self._parse_run_items[parser_id] = item
        self.parse_empty_state.setVisible(False)
        self.parse_timeline.setVisible(True)
        return item

    def _update_parse_run(
        self,
        parser_id: str,
        *,
        artifacts: int | None = None,
        records: int | None = None,
        errors: int | None = None,
        status: str | None = None,
        progress: int | None = None,
    ) -> None:
        item = self._parse_run_items.get(parser_id)
        if item is None:
            return
        for role, value in (
            (PARSE_ARTIFACTS_ROLE, artifacts),
            (PARSE_RECORDS_ROLE, records),
            (PARSE_ERRORS_ROLE, errors),
            (PARSE_STATUS_ROLE, status),
            (PARSE_PROGRESS_ROLE, progress),
        ):
            if value is not None:
                item.setData(role, value)
        item.setText(
            f"{item.data(PARSE_NAME_ROLE)}: {item.data(PARSE_STATUS_ROLE)}, "
            f"{int(item.data(PARSE_ARTIFACTS_ROLE) or 0):,} artifacts, "
            f"{int(item.data(PARSE_RECORDS_ROLE) or 0):,} records"
        )
        self.parse_timeline.viewport().update()

    def _toggle_parse_log(self, expanded: bool) -> None:
        self.parse_log.setVisible(expanded)
        self.parse_log_toggle.setText(
            ("▾" if expanded else "▸") + "  Activity log"
        )

    def _update_parse_plan_summary(self, *_args) -> None:
        if not hasattr(self, "parse_plan_summary"):
            return
        selected_ids = self._checked_parser_ids()
        selected_services: set[str] = set()
        includes_ntfs = False
        for parser_id in selected_ids:
            try:
                parser = self.parser_registry.get(parser_id)
            except KeyError:
                continue
            selected_services.update(parser.metadata.services)
            includes_ntfs = includes_ntfs or parser.metadata.category == "ntfs"
        artifact_count = sum(
            1
            for artifact in self.collected_artifacts
            if artifact.service in selected_services
            or (includes_ntfs and artifact.service == "NTFS")
        )
        if selected_ids:
            suffix = f" · {artifact_count:,} artifacts" if artifact_count else ""
            self.parse_plan_summary.setText(f"{len(selected_ids)} selected{suffix}")
        else:
            self.parse_plan_summary.setText("No parsers selected")

    def _browse_source(self) -> None:
        kind = self.source_kind.currentData()
        if kind == "disk_image":
            path, _ = QFileDialog.getOpenFileName(self, "Select Disk Image", "", IMAGE_FILTER)
        elif kind == "artifact_directory":
            path = QFileDialog.getExistingDirectory(self, "Select Extracted Artifact Folder")
        else:
            path = ""
        if path:
            self.source_path.setText(path)

    def _load_source(self) -> None:
        kind = self.source_kind.currentData()
        if kind != "live_system" and not self.source_path.text().strip():
            QMessageBox.warning(self, "Evidence Source", "Select an evidence source first.")
            return
        location = Path.home() if kind == "live_system" else Path(self.source_path.text().strip())
        label = "Current PC" if kind == "live_system" else str(location)
        source = EvidenceSource(SourceKind(kind), location, label=label, read_only=True)
        self.setWindowTitle("TraceAgent")

        self.load_button.setEnabled(False)
        self.load_source_action.setEnabled(False)
        self.collect_button.setEnabled(False)
        self.collect_action.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.parse_action.setEnabled(False)
        self.source_info_action.setEnabled(False)
        self.filter_action.setEnabled(False)
        for action in self.export_actions.values():
            action.setEnabled(False)
        self.statusBar().showMessage(f"Opening source read-only: {label}")
        QApplication.processEvents()
        try:
            with open_evidence_accessor(source) as accessor:
                info = accessor.info()
                detections = self.artifact_collector.scan(source, accessor)
            ntfs_folder_artifacts = self.ntfs_collector.scan(source)
        except (SourceAccessError, OSError, ValueError) as exc:
            self.current_source = None
            self.source_info_action.setEnabled(False)
            self.service_detections = ()
            self.ntfs_folder_artifacts = ()
            self._clear_collection_rows()
            self.source_value_item.setText(0, "Source error")
            self._update_parse_service_states()
            QMessageBox.critical(self, "Evidence Source", str(exc))
            self.statusBar().showMessage("Failed to open evidence source")
            return
        finally:
            self._update_source_controls()

        self.current_source = source
        source_name = "Current PC" if source.kind == SourceKind.LIVE_SYSTEM else source.location.name
        self.source_value_item.setText(0, source_name or str(source.location))
        self.source_value_item.setIcon(
            0,
            _mono_icon("computer" if source.kind == SourceKind.LIVE_SYSTEM else "drive"),
        )
        self.source_value_item.setToolTip(0, label)
        self.artifacts_item.setText(0, "Artifacts")
        self.parsers_item.setText(0, "Parser Output")
        self.results_item.setText(0, "Analysis Results")
        self.service_detections = detections
        self.ntfs_folder_artifacts = ntfs_folder_artifacts
        self._update_ntfs_lock(source.kind)
        self.collected_artifacts = ()
        self.collection_root = None
        self.parsed_events = ()
        self.case_paths = None
        self._ntfs_status = ""
        self._show_service_detections(detections)
        self._show_ntfs_folder_detection(ntfs_folder_artifacts)
        self._refresh_collection_source_filter()
        self._sync_service_parser_checks()
        self._update_parse_service_states()
        present_count = sum(detection.present for detection in detections)
        fs_text = f", {info.filesystems} filesystem(s)" if info.filesystems is not None else ""

        needs_admin = source.kind == SourceKind.LIVE_SYSTEM and not _is_admin()
        if needs_admin:
            self._ntfs_status = (
                "NTFS events are unavailable on this live system: reading $MFT/$UsnJrnl "
                "requires running TraceAgent as Administrator. Analyse a disk image, or "
                "relaunch elevated. (Service artifacts are still collected without admin.)"
            )
            QMessageBox.warning(self, "NTFS requires Administrator", self._ntfs_status)
        self.statusBar().showMessage(
            f"Source opened read-only: {info.user_homes} user profile(s){fs_text}; "
            f"{present_count} supported service(s) found"
            + (" — NTFS needs Administrator" if needs_admin else "")
        )
        can_collect = (
            present_count > 0
            or source.kind in {SourceKind.LIVE_SYSTEM, SourceKind.DISK_IMAGE}
            or bool(ntfs_folder_artifacts)
        )
        self.collect_button.setEnabled(can_collect)
        self.collect_action.setEnabled(can_collect)
        self.source_info_action.setEnabled(True)
        self.tabs.setCurrentIndex(0)

    def _show_service_detections(self, detections: tuple[ServiceDetection, ...]) -> None:
        self._clear_collection_rows()
        for detection in detections:
            roots = [root.entry.path for root in detection.roots]
            path = roots[0] if len(roots) == 1 else f"{roots[0]} (+{len(roots) - 1} more)" if roots else "—"
            status = f"Found ({len(roots)})" if detection.present else "Not found"
            self._append_collection_row(
                (detection.service, "Service detection", path, "", "", status)
            )

    def _show_ntfs_folder_detection(
        self, artifacts: tuple[ExtractedNtfsArtifacts, ...]
    ) -> None:
        for item in artifacts:
            names = ", ".join(path.name for _kind, _name, path in item.files)
            self._append_collection_row(
                (
                    "NTFS",
                    "Extracted filesystem artifacts",
                    str(item.directory),
                    "",
                    "",
                    f"Found ({names})",
                )
            )

    def _update_parse_service_states(self) -> None:
        detections = {item.service: item for item in self.service_detections}
        collected_counts = Counter(
            artifact.service for artifact in self.collected_artifacts if artifact.service
        )

        for service, option in self.service_parser_options.items():
            parser = self.service_parsers.get(service)
            detection = detections.get(service)
            found = bool(detection and detection.present)
            collected = collected_counts.get(service, 0)
            available = True

            if self.current_source is None:
                if parser is None:
                    state, available = "Parser unavailable", False
                elif parser.metadata.implementation_status == "placeholder":
                    state, available = "Pending implementation", False
                else:
                    state = "Ready"
            elif collected:
                state = f"{collected:,} artifacts · ready"
            elif not found:
                state, available = "Not detected", False
            elif parser is None:
                state, available = "No parser available", False
            elif parser.metadata.implementation_status == "placeholder":
                state, available = "Detected · parser pending", False
            else:
                state = "Detected · ready"

            option.set_state(state, available=available)
            if not available:
                option.setChecked(False)
        self._update_parse_plan_summary()

    def _sync_service_parser_checks(self) -> None:
        """Select only service parsers backed by evidence in the current source."""
        detected_services = {
            detection.service for detection in self.service_detections if detection.present
        }
        detected_services.update(
            artifact.service
            for artifact in self.collected_artifacts
            if artifact.service in self.service_parser_options
        )
        for service, option in self.service_parser_options.items():
            option.setChecked(service in detected_services and option.control.isEnabled())
        self._update_parse_plan_summary()

    def _collect_artifacts(self) -> None:
        if self.current_source is None:
            QMessageBox.warning(self, "Collection", "Load an evidence source first.")
            return

        self.collect_button.setEnabled(False)
        self.collect_action.setEnabled(False)
        self.load_button.setEnabled(False)
        self.load_source_action.setEnabled(False)
        self._clear_collection_rows()
        self.collection_progress.setVisible(True)
        self.collection_progress.setValue(0)
        if self.case_paths is None:
            try:
                self.case_paths = create_case_paths(self.current_source)
            except OSError as exc:
                QMessageBox.critical(self, "Collection", f"Unable to create case folder: {exc}")
                self._update_source_controls()
                self.collect_button.setEnabled(True)
                self.collect_action.setEnabled(True)
                self.collection_progress.setVisible(False)
                return
        context = CollectionContext(
            workspace=self.case_paths.root,
            calculate_sha256=self.hash_check.isChecked(),
            progress=self._collection_progress,
        )
        try:
            records: list[ArtifactRecord] = []
            # Collect NTFS journals first so they are available even if the
            # (potentially large) service-artifact copy is slow or interrupted.
            if self.current_source.kind in self.ntfs_collector.metadata.source_kinds:
                ntfs_context = CollectionContext(
                    workspace=self.case_paths.root,
                    calculate_sha256=self.hash_check.isChecked(),
                    progress=self._collection_progress,
                )
                records.extend(self.ntfs_collector.collect(self.current_source, ntfs_context))
                context.options["ntfs_collection_errors"] = ntfs_context.options.get(
                    "ntfs_collection_errors", []
                )
            if self.current_source.kind == SourceKind.ARTIFACT_DIRECTORY:
                records.extend(self.artifact_collector.inventory(self.current_source, context))
            else:
                records.extend(self.artifact_collector.collect(self.current_source, context))
            records = tuple(records)
        except (SourceAccessError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Collection", str(exc))
            self.statusBar().showMessage("Artifact collection failed")
            return
        finally:
            self._update_source_controls()
            can_collect = (
                any(item.present for item in self.service_detections)
                or self.current_source.kind in {SourceKind.LIVE_SYSTEM, SourceKind.DISK_IMAGE}
                or bool(self.ntfs_folder_artifacts)
            )
            self.collect_button.setEnabled(can_collect)
            self.collect_action.setEnabled(can_collect)
            self.collection_progress.setVisible(False)

        self.collected_artifacts = records
        self.artifacts_item.setText(0, f"Artifacts ({len(records):,})")
        if self.case_paths is not None:
            self.case_item.setText(0, self.case_paths.root.name)
        self.collection_root = (
            self.current_source.location
            if self.current_source.kind == SourceKind.ARTIFACT_DIRECTORY
            else self.case_paths.artifacts
        )
        self._update_parse_service_states()
        for record in records:
            self._append_collection_row(
                (
                    record.service or "Unknown",
                    record.artifact_type,
                    record.path,
                    _format_size(record.size),
                    record.sha256 or "Not calculated",
                    (
                        "Referenced"
                        if self.current_source.kind == SourceKind.ARTIFACT_DIRECTORY
                        else "Collected"
                    ),
                    str(record.metadata.get("user") or ""),
                    str(record.metadata.get("modified_time") or ""),
                    record.original_path or "",
                )
            )
        errors = context.options.get("collection_errors", [])
        self._record_ntfs_collection_status(records, context)
        self._refresh_collection_source_filter()
        self.collection_progress.setValue(100)
        self.collection_progress.setVisible(False)
        can_parse = bool(records) and bool(self.parser_registry.all())
        self.parse_button.setEnabled(can_parse)
        self.parse_action.setEnabled(can_parse)
        action = (
            "Registered"
            if self.current_source.kind == SourceKind.ARTIFACT_DIRECTORY
            else "Collected"
        )
        self.statusBar().showMessage(
            f"{action} {len(records)} artifact file(s); {len(errors)} error(s) — "
            f"{self.case_paths.root}"
        )
        self.tabs.setCurrentIndex(1)

    def _record_ntfs_collection_status(
        self, records: tuple[ArtifactRecord, ...], context: CollectionContext
    ) -> None:
        """Make NTFS collection outcome visible so an empty NTFS view is explained."""
        ntfs_collected = sum(1 for record in records if record.service == "NTFS")
        ntfs_errors = context.options.get("ntfs_collection_errors", []) or []
        if self.current_source is None:
            return
        if (
            self.current_source.kind == SourceKind.ARTIFACT_DIRECTORY
            and not self.ntfs_folder_artifacts
        ):
            self._ntfs_status = (
                "No $J/$LogFile artifacts were detected in the selected artifact folder."
            )
        elif ntfs_collected == 0:
            reason = str(ntfs_errors[0].get("error")) if ntfs_errors else "no NTFS volume was found"
            hint = (
                " (a live system must be opened with Administrator privileges)"
                if self.current_source.kind == SourceKind.LIVE_SYSTEM
                else ""
            )
            self._ntfs_status = f"NTFS journals were not collected: {reason}{hint}"
            self._append_collection_row(
                ("NTFS", "filesystem journals", "—", "", "", f"Not collected — {reason}")
            )
        else:
            self._ntfs_status = ""

    def _collection_progress(self, percent: int, message: str) -> None:
        self.collection_progress.setValue(percent)
        self.statusBar().showMessage(message)
        QApplication.processEvents()

    def _append_collection_row(self, values: tuple[str, ...]) -> None:
        row = self.collection_table.rowCount()
        self.collection_table.insertRow(row)
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column in (2, 8) and value and value != "—":
                item.setToolTip(value)
            self.collection_table.setItem(row, column, item)

    def _update_ntfs_lock(self, source_kind: SourceKind) -> None:
        """Lock the NTFS radios on (default) or off (live systems need Admin)."""
        on = source_kind != SourceKind.LIVE_SYSTEM
        for radio, _parser_id in getattr(self, "ntfs_radios", []):
            radio.setChecked(on)
            radio.setEnabled(False)  # locked either way
        self._update_parse_plan_summary()

    def _checked_parser_ids(self) -> set[str]:
        return {
            parser_id
            for parser_id, option in getattr(self, "parser_options", {}).items()
            if option.isChecked()
        }

    def _run_selected_parsers(self) -> None:
        if self.current_source is None or self.collection_root is None or self.case_paths is None:
            QMessageBox.warning(self, "Parsing", "Collect service artifacts first.")
            return

        self.parse_log.clear()
        all_parsers = self.parser_registry.all()
        parsers = _select_parsers(all_parsers, self._checked_parser_ids())
        if not parsers:
            QMessageBox.information(self, "Parsing", "Check at least one parser module to run.")
            self.parse_button.setEnabled(True)
            return
        self._reset_parse_runs("Execution")
        for parser in parsers:
            services = set(parser.metadata.services)
            artifact_estimate = sum(
                1
                for artifact in self.collected_artifacts
                if artifact.service in services
                or (parser.metadata.category == "ntfs" and artifact.service == "NTFS")
            )
            self._append_parse_run(
                parser.metadata.parser_id,
                parser.metadata.name,
                artifacts=artifact_estimate,
            )
        self.parse_run_summary.setText(f"0 of {len(parsers)} completed")
        parse_source = EvidenceSource(
            SourceKind.ARTIFACT_DIRECTORY,
            self.collection_root,
            label=f"Collected artifacts from {self.current_source.label}",
            read_only=True,
            source_id=self.current_source.source_id,
        )
        all_events: list[NormalizedEvent] = []

        self.parse_button.setEnabled(False)
        self.parse_action.setEnabled(False)
        self.parse_progress.setValue(0)
        self.parse_progress.setVisible(True)
        for parser_index, parser in enumerate(parsers, start=1):
            parser_id = parser.metadata.parser_id
            self._active_parse_id = parser_id
            self._update_parse_run(parser_id, status="Running", progress=0)
            artifact_count = 0
            record_count = 0
            error_count = 0
            status = "Completed"
            if parser.metadata.implementation_status == "placeholder":
                status = "Pending"
            else:
                context = ParseContext(
                    workspace=self.collection_root,
                    progress=lambda percent, message, name=parser.metadata.name: self._parse_progress(
                        name, message, percent
                    ),
                )
                parser_events: list[NormalizedEvent] = []
                try:
                    artifacts = tuple(parser.discover(parse_source, context))
                    artifact_count = len(artifacts)
                    if artifacts:
                        parser.parse(parse_source, artifacts, parser_events.append, context)
                        record_count = len(parser_events)
                        all_events.extend(parser_events)
                        outputs = write_parsed_events(
                            self.case_paths.parsed,
                            parser.metadata.parser_id,
                            parser_events,
                        )
                        for output in outputs:
                            self.parse_log.append(f"[{parser.metadata.name}] Saved: {output}")
                    else:
                        status = "No artifacts"
                    error_count = _diagnostic_count(context.options)
                    if status == "Completed" and error_count:
                        status = "Completed with warnings"
                        self.parse_log.append(
                            f"[{parser.metadata.name}] {error_count:,} recoverable warning(s); "
                            "some source records could not be decoded."
                        )
                        for diagnostic in _diagnostic_messages(context.options)[:5]:
                            self.parse_log.append(f"  - {diagnostic}")
                except Exception as exc:
                    status = "Failed"
                    error_count += 1
                    self.parse_log.append(f"[{parser.metadata.name}] ERROR: {exc}")

            self._update_parse_run(
                parser_id,
                artifacts=artifact_count,
                records=record_count,
                errors=error_count,
                status=status,
                progress=100,
            )
            self.parse_progress.setValue(round(parser_index / max(len(parsers), 1) * 100))
            self.parse_run_summary.setText(
                f"{parser_index} of {len(parsers)} completed"
            )
            QApplication.processEvents()
        self._active_parse_id = None

        outcome = attribute_ntfs_events(all_events)
        self.ntfs_verdicts = outcome.verdicts
        self.parsed_events = tuple(sorted(outcome.events, key=lambda event: event.timestamp))
        self._populate_analyze_views()
        for action in self.export_actions.values():
            action.setEnabled(bool(self.parsed_events))
        self.filter_action.setEnabled(bool(self.parsed_events))
        if self.ntfs_verdicts:
            self.parse_log.append(
                f"[NTFS attribution] {len(self.ntfs_verdicts)} file operation(s) classified: "
                + _verdict_summary(self.ntfs_verdicts)
            )
        if not self.parse_log.toPlainText():
            self.parse_log.setPlainText(
                f"Parsed {len(self.parsed_events)} normalized event(s) from "
                f"{len(parsers)} selected parser module(s)."
            )
        self.parse_progress.setValue(100 if parsers else 0)
        self.parse_progress.setVisible(False)
        self.parse_run_title.setText("Previous run")
        self.parse_run_summary.setText(
            f"{len(parsers)} parsers · {len(self.parsed_events):,} records"
        )
        self.parsers_item.setText(0, f"Parser Output ({len(self.parsed_events):,})")
        can_parse = bool(self.collected_artifacts) and bool(all_parsers)
        self.parse_button.setEnabled(can_parse)
        self.parse_action.setEnabled(can_parse)
        self.statusBar().showMessage(
            f"Parsing complete: {len(self.parsed_events)} normalized event(s) — "
            f"{self.case_paths.parsed}"
        )
        has_local_events = any(
            not event.parser_id.startswith("ntfs.") for event in self.parsed_events
        )
        has_ntfs_events = any(
            event.parser_id.startswith("ntfs.") for event in self.parsed_events
        )
        if (has_ntfs_events and not has_local_events) or (
            not self.parsed_events and bool(self.ntfs_folder_artifacts)
        ):
            self.analyze_tabs.setCurrentIndex(1)
        else:
            self.analyze_tabs.setCurrentIndex(0)
        self.tabs.setCurrentIndex(2)

    def _parse_progress(self, parser_name: str, message: str, percent: int = 0) -> None:
        active_id = getattr(self, "_active_parse_id", None)
        if active_id:
            self._update_parse_run(active_id, status="Running", progress=percent)
        self.statusBar().showMessage(f"{parser_name}: {message}")
        QApplication.processEvents()

    def _populate_analyze_views(self) -> None:
        self._event_by_id = {event.event_id: event for event in self.parsed_events}
        self._local_events = tuple(
            event for event in self.parsed_events if not event.parser_id.startswith("ntfs.")
        )
        self._local_service_counts = Counter(
            (event.service or "unknown") for event in self._local_events
        )
        self._logfile_events = tuple(
            event for event in self.parsed_events if event.parser_id == "ntfs.logfile"
        )
        self._mft_events = tuple(
            event for event in self.parsed_events if event.parser_id == "ntfs.mft"
        )
        self._verdict_by_op = {verdict.operation_id: verdict for verdict in self.ntfs_verdicts}
        ai_attributions = sum(verdict.actor_class == ActorClass.AI_AGENT for verdict in self.ntfs_verdicts)
        self.results_item.setText(
            0, f"Analysis Results ({len(self.parsed_events):,} / AI {ai_attributions:,})"
        )
        self._build_file_entries()
        self._build_local_sessions()
        self._refresh_ntfs_events()

    def _build_file_entries(self) -> None:
        """Group NTFS operations, $MFT files and $LogFile recoveries per file/folder."""
        entries: dict[str, dict] = {}

        def entry_for(path, event_id):
            key = normalize_path(path) or event_id
            entry = entries.setdefault(
                key, {"path": path, "ops": [], "logs": [], "mft": [], "key": key}
            )
            if not entry["path"]:
                entry["path"] = path
            return entry

        for verdict in self.ntfs_verdicts:
            entry_for(verdict.target_path, verdict.operation_id)["ops"].append(verdict)
        for event in getattr(self, "_logfile_events", ()):
            entry_for(event.path, event.event_id)["logs"].append(event)
        for event in getattr(self, "_mft_events", ()):
            entry_for(event.path, event.event_id)["mft"].append(event)

        # Cross-analysis: files that only survive in $MFT/$LogFile (their USN was
        # purged) are attributed by matching their path to agent session logs.
        agent_index = build_agent_index(getattr(self, "_local_events", ()))
        priority = {
            ActorClass.AI_AGENT: 3,
            ActorClass.HUMAN: 2,
            ActorClass.SYSTEM: 1,
            ActorClass.UNKNOWN: 0,
        }
        for key, entry in entries.items():
            ops = sorted(entry["ops"], key=lambda v: v.start)
            entry["ops"] = ops
            entry["matched"] = None
            if ops:
                best = max(ops, key=lambda v: (priority[v.actor_class], v.confidence))
                entry["actor"] = best.actor_class
                entry["service"] = best.service
                entry["confidence"] = best.confidence
            else:
                match = agent_index.by_path.get(key)
                confidence = 0.7
                if not match:
                    # fall back to a filename match, but only when it points to a
                    # single service (avoids mis-crediting common file names).
                    named = agent_index.by_name.get(basename_of(entry["path"]))
                    if named and len({a.service for a in named}) == 1:
                        match = named
                        confidence = 0.5
                if match:
                    entry["actor"] = ActorClass.AI_AGENT
                    entry["service"] = match[0].service
                    entry["confidence"] = confidence
                    entry["matched"] = match[0]
                else:
                    entry["actor"] = ActorClass.UNKNOWN
                    entry["service"] = None
                    entry["confidence"] = 0.0
            times = (
                [v.start for v in ops]
                + [e.timestamp for e in entry["logs"]]
                + [e.timestamp for e in entry["mft"]]
            )
            entry["first"] = min(times) if times else None
            entry["last"] = max(times) if times else None
            # When the path is unresolved, fall back to the recovered file name
            # (from $LogFile/$MFT/USN records) rather than the internal event id.
            recovered = self._entry_recovered_name(entry)
            entry["path"] = entry["path"] or recovered or key
            entry["filename"] = basename_of(entry["path"]) or recovered or entry["path"]
            entry["key"] = key
            # Directory-ness comes from FILE_ATTRIBUTE_DIRECTORY on the USN
            # records, or $MFT's $FILE_NAME flags — never guessed from the name.
            entry["is_dir"] = any(verdict.is_directory for verdict in ops) or any(
                event.metadata.get("is_dir") is True for event in entry.get("mft", [])
            )
            entry["narrative"] = _entry_narrative(entry)

        self._file_by_key = entries
        self._file_entries = sorted(
            entries.values(),
            key=lambda e: e["last"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    def _entry_recovered_name(self, entry: dict) -> str | None:
        """The real file name recorded in $LogFile/$MFT/USN records for an entry."""
        for event in entry["logs"] + entry.get("mft", []):
            name = event.metadata.get("filename")
            if name:
                return str(name)
        for verdict in entry["ops"]:
            for event_id in verdict.event_ids:
                event = self._event_by_id.get(event_id)
                if event is not None and event.metadata.get("filename"):
                    return str(event.metadata["filename"])
        return None

    # -- Local artifacts view ------------------------------------------------
    def _build_local_sessions(self) -> None:
        """Group local-artifact events into per-service sessions (conversations)."""
        source_events = tuple(getattr(self, "_local_events", ()))
        # Older derived cases predate ``artifact_session_id``. Recover each
        # rollout's stable session id from its first session_meta record before
        # deciding whether an embedded guardian transcript is only a duplicate.
        codex_artifact_sessions: dict[str, str] = {}
        for event in source_events:
            if event.parser_id != "codex.desktop" or event.event_type != "codex_session_meta":
                continue
            session_id = event.metadata.get("artifact_session_id") or event.metadata.get("id")
            reference = _raw_artifact_reference(event.raw_reference)
            if reference and isinstance(session_id, str) and session_id:
                codex_artifact_sessions.setdefault(reference, session_id)

        expanded_events: tuple[NormalizedEvent, ...] = tuple(
            expanded_event
            for event in source_events
            for expanded_event in (
                expand_codex_embedded_transcript(event)
                if event.parser_id == "codex.desktop"
                else (event,)
            )
        )
        canonical_codex_sessions = {
            str(
                event.metadata.get("artifact_session_id")
                or codex_artifact_sessions.get(_raw_artifact_reference(event.raw_reference))
                or event.session_id
            )
            for event in expanded_events
            if event.parser_id == "codex.desktop"
            and (
                event.metadata.get("artifact_session_id")
                or codex_artifact_sessions.get(_raw_artifact_reference(event.raw_reference))
                or event.session_id
            )
            and not event.metadata.get("embedded_transcript")
            and not event.metadata.get("embedded_transcript_expanded")
            and event.event_type.startswith(("codex_event_msg.", "codex_response_item."))
        }
        local_event_list: list[NormalizedEvent] = []
        embedded_seen: set[tuple[str, str]] = set()
        for event in expanded_events:
            if not event.metadata.get("embedded_transcript"):
                local_event_list.append(event)
                continue
            target_session = (
                event.metadata.get("reviewed_session_id")
                or event.metadata.get("parent_session_id")
                or event.session_id
            )
            if not isinstance(target_session, str) or not target_session:
                target_session = event.session_id
            if target_session in canonical_codex_sessions:
                continue
            fingerprint = event.metadata.get("embedded_transcript_fingerprint")
            if not isinstance(fingerprint, str):
                fingerprint = "\0".join(
                    (
                        event.event_type,
                        event.actor or "",
                        event.tool_name or "",
                        event.command or "",
                        event.result or "",
                    )
                )
            identity = (target_session or "", fingerprint)
            if identity in embedded_seen:
                continue
            embedded_seen.add(identity)
            local_event_list.append(
                event if event.session_id == target_session else replace(event, session_id=target_session)
            )
        local_events = tuple(local_event_list)
        for event in local_events:
            self._event_by_id.setdefault(event.event_id, event)
        # Older Codex parsed files used payload.session_id (the parent task) and
        # even changed it when a copied session_meta appeared inside a rollout.
        # Recover the stable rollout/thread id from the first meta record sharing
        # the same raw artifact reference so existing cases display correctly
        # without rewriting their derived JSONL evidence.
        sessions: dict[str, dict] = {}
        for event in local_events:
            service = event.service or "Unknown"
            recovered_session_id = None
            if event.parser_id == "codex.desktop" and not event.metadata.get("embedded_transcript"):
                recovered_session_id = codex_artifact_sessions.get(
                    _raw_artifact_reference(event.raw_reference)
                )
            session_id = recovered_session_id or event.session_id or "(session-less)"
            key = f"{service} {session_id}"
            entry = sessions.setdefault(
                key,
                {
                    "service": service,
                    "session_id": session_id,
                    "events": [],
                    "is_guardian": False,
                },
            )
            entry["events"].append(event)
            if event.parser_id == "codex.desktop" and _is_codex_guardian_event(event):
                entry["is_guardian"] = True
        for entry in sessions.values():
            entry["events"].sort(key=lambda e: e.timestamp)
            entry["first"] = entry["events"][0].timestamp
            entry["last"] = entry["events"][-1].timestamp
        self._sessions = sessions
        self._current_session_key = None
        self._timeline_events: tuple[NormalizedEvent, ...] = ()
        service_counts = Counter(
            entry["service"]
            for entry in sessions.values()
            if self._local_session_is_visible(entry)
        )
        self._populate_local_service_filter(service_counts)
        self.la_timeline_list.clear()
        self.la_session_label.clear()
        self.la_interpretation.clear()
        self._close_event_details()
        self._refresh_local_tree()

    def _populate_local_service_filter(self, service_counts: Counter) -> None:
        selected = self._selected_local_service
        if selected and selected not in service_counts:
            selected = ""
            self._selected_local_service = ""
        self.la_service_filter.blockSignals(True)
        self.la_service_filter.clear()
        entries = [("", "All services", sum(service_counts.values()))]
        known_services = [service for service in SERVICES[1:] if service in service_counts]
        other_services = sorted(set(service_counts) - set(known_services))
        entries.extend(
            (service, service, service_counts[service])
            for service in (*known_services, *other_services)
        )
        for service, label, count in entries:
            self.la_service_filter.addItem(f"{label} ({count})", service)
            if service == selected:
                self.la_service_filter.setCurrentIndex(self.la_service_filter.count() - 1)
        self.la_service_filter.blockSignals(False)

    def _local_service_filter_changed(self) -> None:
        self._selected_local_service = str(self.la_service_filter.currentData() or "")
        self._current_session_key = None
        self._timeline_events = ()
        self.la_timeline_list.clear()
        self.la_session_label.clear()
        self.la_interpretation.clear()
        self._close_event_details()
        self._refresh_local_tree()

    def _local_importance_changed(self) -> None:
        """Apply the low-signal policy to both sessions and their timelines."""
        sessions = getattr(self, "_sessions", {})
        service_counts = Counter(
            entry["service"]
            for entry in sessions.values()
            if self._local_session_is_visible(entry)
        )
        self._populate_local_service_filter(service_counts)
        self._current_session_key = None
        self._timeline_events = ()
        self.la_timeline_list.clear()
        self.la_session_label.clear()
        self.la_interpretation.clear()
        self._close_event_details()
        self._refresh_local_tree()

    def _local_session_is_visible(self, entry: dict) -> bool:
        if self.la_show_low_importance.isChecked():
            return True
        if entry.get("is_guardian"):
            return False
        return any(not _is_low_importance_event(event) for event in entry["events"])

    def _refresh_local_tree(self) -> None:
        session_list = self.la_session_list
        session_list.blockSignals(True)
        session_list.clear()
        needle = self.la_search.text().strip().lower()
        selected_service = self._selected_local_service
        sessions = getattr(self, "_sessions", {})
        visible_sessions: list[tuple[str, dict]] = []
        for key, entry in sessions.items():
            if not self._local_session_is_visible(entry):
                continue
            if selected_service and entry["service"] != selected_service:
                continue
            if needle and not _session_matches(entry, needle):
                continue
            visible_sessions.append((key, entry))

        sort_mode = self.la_session_sort.currentIndex()
        if sort_mode == 0:
            visible_sessions.sort(key=lambda item: item[1]["first"], reverse=True)
        elif sort_mode == 1:
            visible_sessions.sort(key=lambda item: item[1]["first"])
        elif sort_mode == 2:
            visible_sessions.sort(key=lambda item: (item[1]["service"].casefold(), item[1]["first"]))
        else:
            visible_sessions.sort(key=lambda item: len(item[1]["events"]), reverse=True)
        for key, entry in visible_sessions:
            item = QListWidgetItem(entry["session_id"])
            item.setData(SESSION_KEY_ROLE, key)
            item.setData(SESSION_SERVICE_ROLE, entry["service"])
            item.setData(SESSION_STARTED_ROLE, _format_local_datetime(entry["first"], "%m-%d %H:%M"))
            item.setData(SESSION_EVENTS_ROLE, len(entry["events"]))
            item.setToolTip(entry["session_id"])
            item.setSizeHint(QSize(480, 58))
            session_list.addItem(item)
        session_list.blockSignals(False)

        total_sessions = len(sessions)
        if total_sessions == 0:
            self.la_count.clear()
            return
        shown_events = sum(len(entry["events"]) for _, entry in visible_sessions)
        self.la_count.setText(
            f"{len(visible_sessions)} of {total_sessions} sessions  ·  {shown_events:,} events"
        )

    def _on_session_selected(
        self, current: QListWidgetItem | None = None,
        _previous: QListWidgetItem | None = None,
    ) -> None:
        item = current or self.la_session_list.currentItem()
        if item is None:
            return
        key = item.data(SESSION_KEY_ROLE)
        if not key:
            return
        self._current_session_key = key
        self._refresh_local_timeline()

    def _refresh_local_timeline(self) -> None:
        key = getattr(self, "_current_session_key", None)
        entry = getattr(self, "_sessions", {}).get(key) if key else None
        if entry is None:
            self.la_timeline_list.clear()
            self.la_interpretation.clear()
            self._timeline_events = ()
            return
        kind_filter = _TYPE_FILTER.get(self.la_type.currentText())
        show_low_importance = self.la_show_low_importance.isChecked()
        shown: list[NormalizedEvent] = []
        previous_fingerprint = None
        seen_reasoning: set[str] = set()
        duplicate_count = 0
        for event in entry["events"]:
            if not show_low_importance and _is_low_importance_event(event):
                continue
            _, kind = _event_kind(event)
            if kind_filter and kind != kind_filter:
                continue
            if kind == "thinking":
                reasoning_fingerprint = _oneline(event.result or event.command).casefold()
                if reasoning_fingerprint and reasoning_fingerprint in seen_reasoning:
                    duplicate_count += 1
                    continue
                if reasoning_fingerprint:
                    seen_reasoning.add(reasoning_fingerprint)
            fingerprint = _local_event_fingerprint(event)
            if fingerprint == previous_fingerprint:
                duplicate_count += 1
                continue
            shown.append(event)
            previous_fingerprint = fingerprint
            if len(shown) >= MAX_DISPLAY_ROWS:
                break
        self._timeline_events = tuple(shown)
        timeline = self.la_timeline_list
        timeline.blockSignals(True)
        timeline.clear()
        previous_stamp = None
        for event in shown:
            marker, kind = _event_kind(event)
            summary = _conversation_event_text(event, kind)
            stamp = _format_local_datetime(event.timestamp, "%H:%M:%S")
            item = QListWidgetItem(summary)
            item.setData(EVENT_ID_ROLE, event.event_id)
            item.setData(EVENT_TYPE_ROLE, marker)
            item.setData(EVENT_SUMMARY_ROLE, summary)
            item.setData(EVENT_TIME_ROLE, stamp if stamp != previous_stamp else "")
            item.setToolTip(f"{stamp}  {summary}")
            timeline.addItem(item)
            previous_stamp = stamp
        timeline.blockSignals(False)
        self.la_session_label.setText(
            f"Session {entry['session_id']}  ·  {entry['service']}  ·  "
            f"{_format_local_datetime(entry['first'], '%Y-%m-%d %H:%M')}–"
            f"{_format_local_datetime(entry['last'], '%H:%M:%S')}  ·  "
            f"{len(shown)}/{len(entry['events'])} shown"
            + (f"  ·  {duplicate_count} duplicate(s) hidden" if duplicate_count else "")
        )
        self._render_session_interpretation(entry, tuple(shown))

    def _render_session_interpretation(
        self, entry: dict, shown: tuple[NormalizedEvent, ...]
    ) -> None:
        """Explain the selected session — who did what — in English, then Korean.

        Interprets exactly the events on screen, and says how many records the
        filters held back, so the narrative can never claim more coverage than
        the reviewer is actually looking at.
        """
        narrative = summarize_session(
            service=entry["service"],
            events=shown,
            hidden_count=max(0, len(entry["events"]) - len(shown)),
        )
        lines = [
            f"Session  : {entry['session_id']}",
            f"Service  : {entry['service']}",
            f"Period   : {_format_local_datetime(entry['first'])} – "
            f"{_format_local_datetime(entry['last'], '%H:%M:%S')}",
            f"Events   : {len(shown):,} shown / {len(entry['events']):,} total",
            "",
            "══ Interpretation / 해석 ══",
            "",
            "[English]",
            f"  {narrative.headline_en}",
        ]
        lines += [f"    {line}" for line in narrative.detail_en]
        lines += ["", "[한국어]", f"  {narrative.headline_ko}"]
        lines += [f"    {line}" for line in narrative.detail_ko]
        self.la_interpretation.setPlainText("\n".join(lines))

    def _on_timeline_selected(
        self, current: QListWidgetItem | None,
        _previous: QListWidgetItem | None = None,
    ) -> None:
        item = current or self.la_timeline_list.currentItem()
        event = self._event_by_id.get(item.data(EVENT_ID_ROLE)) if item is not None else None
        if event is not None:
            self._render_event_detail(event)

    def _render_event_detail(self, event: NormalizedEvent) -> None:
        dialog = getattr(self, "event_details_dialog", None)
        if dialog is None:
            dialog = EventDetailsDialog(self)
            dialog.finished.connect(self._restore_timeline_focus)
            self.event_details_dialog = dialog
        dialog.set_event(event)
        if not dialog.isVisible():
            dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _close_event_details(self) -> None:
        dialog = getattr(self, "event_details_dialog", None)
        if dialog is not None and dialog.isVisible():
            dialog.close()

    def _restore_timeline_focus(self, _result: int = 0) -> None:
        if hasattr(self, "la_timeline_list"):
            self.la_timeline_list.setFocus(Qt.OtherFocusReason)

    # -- NTFS events view (per file/folder) ----------------------------------
    def _refresh_ntfs_events(self) -> None:
        table = self.ntfs_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        needle = self.ntfs_search.text().strip().lower()
        actor = self.ntfs_actor.currentText()
        item_type = self.ntfs_item_type.currentText()
        behavior = self.ntfs_behavior.currentText()
        hide_system = self.ntfs_hide_system.isChecked()
        entries = getattr(self, "_file_entries", ())
        matched = 0
        for entry in entries:
            if hide_system and entry["actor"] == ActorClass.SYSTEM:
                continue
            if item_type == "Files only" and entry.get("is_dir"):
                continue
            if item_type == "Folders only" and not entry.get("is_dir"):
                continue
            if actor != "All actors" and _actor_class_name(entry["actor"]) != actor:
                continue
            if behavior != "All behaviors" and not _entry_has_behavior(entry, behavior):
                continue
            if needle and needle not in _entry_haystack(entry):
                continue
            matched += 1
            if table.rowCount() < MAX_DISPLAY_ROWS:
                self._add_ntfs_file_row(entry)
        table.setSortingEnabled(True)
        total = len(entries)
        if total == 0:
            self.ntfs_count.setText(
                self._ntfs_status
                or "No NTFS events parsed yet — collect and parse a live-system or disk-image source."
            )
        else:
            self.ntfs_count.setText(_count_text(table.rowCount(), matched, total, "file/folder"))

    def _add_ntfs_file_row(self, entry: dict) -> None:
        table = self.ntfs_table
        row = table.rowCount()
        table.insertRow(row)
        last = entry["last"]
        narrative = entry.get("narrative")
        values = (
            entry["filename"] or "—",
            "Folder" if entry.get("is_dir") else "File",
            entry["path"] or "—",
            _actor_class_label(entry["actor"], entry["service"]),
            _truncate(narrative.headline_ko, 110) if narrative else "—",
            entry["service"] or "—",
            str(len(entry["ops"]) + len(entry["logs"]) + len(entry.get("mft", []))),
            _format_local_datetime(last, "%Y-%m-%d %H:%M:%S") if last else "—",
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setData(Qt.UserRole, f"file:{entry['key']}")
            if narrative is not None:
                # The cell holds the Korean headline (elided); the tooltip carries
                # both languages in full so nothing is lost to truncation, English
                # first to match the local-artifact interpretation panel.
                item.setToolTip(narrative.bilingual(english_first=True))
            table.setItem(row, column, item)

    def _show_ntfs_detail(self) -> None:
        items = self.ntfs_table.selectedItems()
        if not items:
            return
        key = items[0].data(Qt.UserRole) or ""
        if key.startswith("file:"):
            self._show_ntfs_file(key[5:])

    def _show_ntfs_file(self, key: str) -> None:
        entry = getattr(self, "_file_by_key", {}).get(key)
        if entry is None:
            return
        ops = entry["ops"]
        logs = entry["logs"]
        mft = entry.get("mft", [])
        lines = [
            f"File / folder : {entry['path']}",
            f"Verdict       : {_actor_class_label(entry['actor'], entry['service'])}"
            f"   (confidence {entry['confidence']:.2f})",
            f"Activity      : {len(ops)} operation(s), {len(mft)} $MFT, {len(logs)} $LogFile record(s)",
        ]
        narrative = entry.get("narrative")
        if narrative is not None:
            lines += ["", "══ Interpretation / 해석 ══", ""]
            lines += ["[English]", f"  {narrative.headline_en}"]
            lines += [f"    {line}" for line in narrative.detail_en]
            lines += ["", "[한국어]", f"  {narrative.headline_ko}"]
            lines += [f"    {line}" for line in narrative.detail_ko]
        lines += ["", "── Activity timeline ──"]
        if not ops:
            recovered = ", ".join(s for s, present in (("$MFT", mft), ("$LogFile", logs)) if present)
            lines.append(f"  (no USN operations — recovered from {recovered or 'other artifacts'})")
        for verdict in ops:
            lines.append(
                f"{_format_local_datetime(verdict.start, '%Y-%m-%d %H:%M:%S')}  "
                f"[{_actor_class_label(verdict.actor_class, verdict.service)}]  {verdict.behavior}"
            )
            if verdict.narrative is not None:
                lines.append(f"    ▸ {verdict.narrative.headline_en}")
                lines.append(f"    ▸ {verdict.narrative.headline_ko}")
                for line in verdict.narrative.detail_en:
                    lines.append(f"      {line}")
                for line in verdict.narrative.detail_ko:
                    lines.append(f"      {line}")
            flow = self._operation_flow(verdict)
            if flow:
                lines.append(f"    raw USN flow: {flow}")
            if verdict.matched_event_id:
                matched = self._event_by_id.get(verdict.matched_event_id)
                if matched is not None:
                    lines.append(
                        f"    session match: {matched.service} / "
                        f"{matched.tool_name or '-'} / {matched.session_id or '-'}"
                    )
        if mft:
            lines += ["", "── Present in $MFT (file inventory) ──"]
            for event in mft[:5]:
                meta = event.metadata
                lines.append(f"  {meta.get('full_path') or meta.get('filename', '?')}")
                lines.append(
                    f"    created={meta.get('fn_created', '—')}  modified={meta.get('fn_modified', '—')}"
                    f"  accessed={meta.get('fn_accessed', '—')}"
                )
        if entry.get("matched") is not None:
            activity = entry["matched"]
            lines += [
                "",
                "── Cross-analysis (agent session-log path match) ──",
                f"  service : {activity.service}",
                f"  tool    : {activity.tool_name or '-'}",
                f"  session : {activity.session_id or '-'}",
                f"  time    : {_format_local_datetime(activity.timestamp)}",
            ]
        if logs:
            lines += ["", "── Recovered from $LogFile (index-entry operations) ──"]
            for event in logs:
                meta = event.metadata
                op = meta.get("operation", "recovered")
                lines.append(
                    f"  [{op}] {meta.get('filename', '?')}   "
                    f"modified={meta.get('fn_modified', '—')}  created={meta.get('fn_created', '—')}"
                )
        self.ntfs_detail.setPlainText("\n".join(lines))

    def _operation_flow(self, verdict: OperationVerdict) -> str:
        flow: list[str] = []
        for event_id in verdict.event_ids:
            event = self._event_by_id.get(event_id)
            if event is not None:
                flow.extend(str(reason) for reason in event.metadata.get("ntfs_reasons", []))
        return " → ".join(flow)

    def _selected_event(self, table: QTableWidget) -> NormalizedEvent | None:
        items = table.selectedItems()
        if not items:
            return None
        return self._event_by_id.get(items[0].data(Qt.UserRole))

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About TraceAgent",
            f"TraceAgent {__version__}\n\nCollection, parser orchestration, NTFS timeline analysis, and AI-agent attribution.",
        )

    # -- Export ----------------------------------------------------------------
    def _build_case_report(self) -> CaseReport:
        file_rows = tuple(
            FileAttributionRow(
                filename=entry["filename"] or "—",
                path=entry["path"] or "—",
                actor_class=entry["actor"],
                service=entry["service"],
                confidence=entry["confidence"],
                behaviors=(
                    tuple(verdict.behavior for verdict in entry["ops"])
                    if entry["ops"]
                    else (("logfile_recovered",) if entry["logs"] else ())
                ),
                reasons=tuple(
                    dict.fromkeys(reason for verdict in entry["ops"] for reason in verdict.reasons)
                ),
                first_activity=entry["first"],
                last_activity=entry["last"],
                interpretation_ko=entry["narrative"].headline_ko if entry.get("narrative") else "",
                interpretation_en=entry["narrative"].headline_en if entry.get("narrative") else "",
            )
            for entry in getattr(self, "_file_entries", ())
        )
        session_rows = tuple(
            SessionSummaryRow(
                service=entry["service"],
                session_id=entry["session_id"],
                event_count=len(entry["events"]),
                first=entry["first"],
                last=entry["last"],
            )
            for entry in getattr(self, "_sessions", {}).values()
        )
        prompt_rows = build_prompt_title_rows(self.parsed_events)
        return CaseReport(
            source_label=self.current_source.label if self.current_source else "Unknown source",
            generated_at=datetime.now(timezone.utc),
            events=self.parsed_events,
            file_rows=file_rows,
            session_rows=session_rows,
            prompt_rows=prompt_rows,
            agent_sections=build_agent_sections(self.parsed_events, prompt_rows),
        )

    @staticmethod
    def _ensure_suffix(path: str, suffix: str) -> Path:
        candidate = Path(path)
        return candidate if candidate.suffix.lower() == suffix else candidate.with_suffix(suffix)

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV files (*.csv)")
        if not path:
            return
        destination = self._ensure_suffix(path, ".csv")
        report = self._build_case_report()
        try:
            export_activity_csv(report, destination)
        except OSError as exc:
            QMessageBox.critical(self, "Export", f"Unable to write CSV: {exc}")
            return
        self.statusBar().showMessage(
            f"Exported {len(report.file_rows)} file activity + {len(report.session_rows)} session row(s) to {destination}"
        )

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "", "JSON files (*.json)")
        if not path:
            return
        destination = self._ensure_suffix(path, ".json")
        report = self._build_case_report()
        try:
            export_case_report_json(report, destination)
        except OSError as exc:
            QMessageBox.critical(self, "Export", f"Unable to write JSON: {exc}")
            return
        self.statusBar().showMessage(f"Exported {len(report.file_rows)} file activity row(s) to {destination}")

    def _export_html_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML Report", "", "HTML files (*.html)")
        if not path:
            return
        destination = self._ensure_suffix(path, ".html")
        try:
            export_html_report(self._build_case_report(), destination)
        except OSError as exc:
            QMessageBox.critical(self, "Export", f"Unable to write HTML report: {exc}")
            return
        self.statusBar().showMessage(f"Exported HTML report to {destination}")

    def _export_pdf_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF Report", "", "PDF files (*.pdf)")
        if not path:
            return
        destination = self._ensure_suffix(path, ".pdf")
        document = QTextDocument()
        document.setHtml(render_html_report(self._build_case_report()))
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(str(destination))
        # Without an explicit page size, QTextDocument lays out at its default
        # ~271pt width instead of the printer's actual page width, so at
        # QPrinter.HighResolution's DPI everything (especially table text)
        # renders squeezed into a tiny corner and reads as illegible smudges,
        # even though the underlying text is intact (selects/copies fine).
        document.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size()))
        try:
            document.print_(printer)
        except OSError as exc:
            QMessageBox.critical(self, "Export", f"Unable to write PDF report: {exc}")
            return
        self.statusBar().showMessage(f"Exported PDF report to {destination}")


def _is_admin() -> bool:
    """Whether the process has Administrator rights (needed for live NTFS reads)."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - non-Windows or restricted environments
        return False


def _actor_class_name(actor_class: ActorClass) -> str:
    return {
        ActorClass.AI_AGENT: "AI agent",
        ActorClass.HUMAN: "Human",
        ActorClass.SYSTEM: "System",
    }.get(actor_class, "Unknown")


def _actor_class_label(actor_class: ActorClass, service: str | None = None) -> str:
    if actor_class == ActorClass.AI_AGENT:
        return f"AI · {service}" if service else "AI agent"
    return _actor_class_name(actor_class)


_TYPE_FILTER = {
    "Prompt": "prompt",
    "Thinking": "thinking",
    "Tool call": "tool",
    "Result": "result",
    "Message": "message",
    "Log": "log",
}

_FORENSIC_MARKERS = (
    ("MCP automated tool call (contains_mcp_source)", "contains_mcp_source"),
    ("High-risk action flagged (danger_level)", "danger_level"),
    ("Sandbox permission request", "sandbox_permissions"),
    ("Action justification recorded", "justification"),
    ("User approval prompt (confirm_action)", "confirm_action"),
    ("Encrypted reasoning content", "encrypted_content"),
)


def _oneline(text: object) -> str:
    if not text:
        return ""
    return " ".join(str(text).split())


# Display kind -> the marker drawn on a conversation row.  The classification
# itself lives in analysis.session_narrative so the row marker and the sentence
# written about that row can never disagree about what the event is.
_KIND_MARKERS = {
    "log": "LOG",
    "result": "OUT",
    "tool": "TOOL",
    "thinking": "THINK",
    "prompt": "USER",
    "message": "AGENT",
    "event": "EVENT",
}


def _event_kind(event: NormalizedEvent) -> tuple[str, str]:
    """Classify a local-artifact event into a display kind + stable text marker."""
    kind = event_kind(event)
    return (_KIND_MARKERS.get(kind, "EVENT"), kind)


def _event_summary(event: NormalizedEvent, kind: str) -> str:
    if kind == "tool":
        name = event.tool_name or "tool"
        extra = event.command or event.path
        return f"{name}   {_oneline(extra)}".strip() if extra else name
    text = event.result or event.command or event.path or event.event_type
    return _truncate(_oneline(text), 400)


def _event_detail_html(event: NormalizedEvent) -> str:
    marker, kind = _event_kind(event)
    summary = _event_summary(event, kind) or event.event_type
    # What this one record means, before the raw fields it was derived from.
    interpretation = describe_event(event)
    interpretation_html = (
        '<div class="block-label">INTERPRETATION / 해석</div>'
        '<div class="interp"><div>{}</div><div class="interp-ko">{}</div></div>'.format(
            html.escape(interpretation.headline_en),
            html.escape(interpretation.headline_ko),
        )
    )
    fields = (
        ("Timestamp", _format_local_datetime(event.timestamp)),
        ("Service", event.service),
        ("Session", event.session_id),
        ("Actor", event.actor),
        ("Event type", event.event_type),
        ("Tool", event.tool_name),
        ("Path", event.path),
    )
    field_html = "".join(
        '<div class="pair"><div class="label">{}</div><div class="value">{}</div></div>'.format(
            html.escape(label.upper()), html.escape(str(value))
        )
        for label, value in fields
        if value
    )
    blocks = ""
    for label, value in (
        ("Command", event.command),
        ("Result / content", event.result),
        ("Raw source", event.raw_reference),
    ):
        if value:
            blocks += (
                f'<div class="block-label">{html.escape(label.upper())}</div>'
                f'<div class="block">{html.escape(_truncate(str(value), 12000))}</div>'
            )
    return f"""
    <html><head><style>
    body {{ background:#FFFFFF; color:#1C1917; font-family:'Segoe UI',sans-serif; margin:4px; }}
    .head {{ margin-bottom:18px; }}
    .badge {{ display:inline-block; background:#F5F5F4; color:#57534E; padding:3px 7px; font-size:10px; font-weight:600; }}
    .title {{ font-size:15px; font-weight:600; margin-top:8px; line-height:1.4; }}
    .pair {{ margin-bottom:12px; }}
    .label,.block-label {{ color:#A8A29E; font-size:10px; font-weight:600; letter-spacing:0.03em; margin-bottom:3px; }}
    .value {{ color:#1C1917; font-size:13px; }}
    .block-label {{ margin-top:14px; }}
    .block {{ background:#FAFAF9; color:#292524; font-family:Consolas,monospace; font-size:12px; padding:10px; white-space:pre-wrap; }}
    .interp {{ background:#FAFAF9; color:#1C1917; font-size:13px; line-height:1.5; padding:10px; margin-bottom:14px; }}
    .interp-ko {{ color:#57534E; margin-top:4px; }}
    </style></head><body><div class="head"><span class="badge">{html.escape(marker)}</span>
    <div class="title">{html.escape(summary)}</div></div>
    {interpretation_html}{field_html}{blocks}</body></html>
    """


def _conversation_event_text(event: NormalizedEvent, kind: str) -> str:
    """Keep conversation text readable while rendering activity compactly."""
    if kind in {"prompt", "message"}:
        text = event.result or event.command or event.path or event.event_type
        return _truncate(str(text), 6000)
    if event.event_type == "codex_response_item.custom_tool_call":
        name = event.metadata.get("name") or event.tool_name or "tool"
        tool_input = event.metadata.get("input") or event.command or event.result
        return _truncate(f"{name}  {_oneline(tool_input)}".strip(), 1200)
    if event.event_type == "codex_response_item.custom_tool_call_output":
        return _truncate(_oneline(event.metadata.get("output") or event.result), 1200)
    return _event_summary(event, kind)


def _local_event_fingerprint(event: NormalizedEvent) -> tuple[object, ...]:
    """Identify exact semantic duplicates while ignoring generated record IDs."""
    return (
        event.parser_id,
        event.service or "",
        event.session_id or "",
        event.timestamp,
        event.event_type,
        event.actor or "",
        event.tool_name or "",
        normalize_path(event.path or ""),
        _oneline(event.command),
        _oneline(event.result),
    )


def _is_low_importance_event(event: NormalizedEvent) -> bool:
    """Recognize low-signal records, including cases parsed by older builds."""
    if event.event_type in {
        "codex_response_item.custom_tool_call",
        "codex_response_item.custom_tool_call_output",
    }:
        return False
    if event.event_type in {"codex_response_item.message", "codex_response_item.reasoning"}:
        return True
    if event.event_type == "codex_threads_record":
        return True
    if event.event_type in {
        "claude_file-history-snapshot",
        "claude_file-history-delta",
        "claude_fork-context-ref",
    }:
        return True
    if event.metadata.get("importance") == "low":
        return True
    return event.event_type in {"claude_application_log", "cowork_application_log"}


def _is_codex_guardian_event(event: NormalizedEvent) -> bool:
    if event.metadata.get("session_role") == "guardian":
        return True
    source = event.metadata.get("source")
    if not isinstance(source, dict):
        return False
    subagent = source.get("subagent")
    return isinstance(subagent, dict) and subagent.get("other") == "guardian"


def _raw_artifact_reference(reference: str | None) -> str:
    if not reference:
        return ""
    return reference.split(":line=", 1)[0]


def _session_matches(entry: dict, needle: str) -> bool:
    if needle in entry["session_id"].lower() or needle in entry["service"].lower():
        return True
    return any(needle in _local_haystack(event) for event in entry["events"])


def _forensic_badges(event: NormalizedEvent) -> list[str]:
    try:
        blob = json.dumps(event.metadata, ensure_ascii=False, default=str).lower()
    except (TypeError, ValueError):
        blob = ""
    return [label for label, token in _FORENSIC_MARKERS if token in blob]


# kind -> (default label, bubble alignment, background colour)
_BUBBLE_STYLE = {
    "prompt": ("USER INPUT", "right", "#dceceb"),
    "message": ("AGENT RESPONSE", "left", "#e9eef0"),
    "thinking": ("REASONING", "left", "#f2ecdc"),
    "tool": ("TOOL CALL", "left", "#e9e7ef"),
    "result": ("TOOL RESULT", "left", "#e1eee5"),
    "event": ("EVENT", "left", "#e9eef0"),
}


def _chat_document(events: list[NormalizedEvent] | tuple[NormalizedEvent, ...]) -> str:
    """Render a session's events as a chat-style HTML transcript."""
    if not events:
        return ""
    parts = [
        "<html><body style=\"background:#f7f9fa;color:#293e4b;"
        "font-family:'Segoe UI',sans-serif;\">"
    ]
    last_day = None
    for event in events:
        day = _format_local_datetime(event.timestamp, "%Y-%m-%d")
        if day != last_day:
            parts.append(
                f'<div style="text-align:center;color:#9aa0a6;font-size:11px;'
                f'margin:12px 0 4px;">— {day} —</div>'
            )
            last_day = day
        parts.append(_chat_bubble(event))
    parts.append("</body></html>")
    return "".join(parts)


def _chat_bubble(event: NormalizedEvent) -> str:
    _, kind = _event_kind(event)
    stamp = _format_local_datetime(event.timestamp, "%H:%M:%S")
    label, align, background = _BUBBLE_STYLE.get(kind, _BUBBLE_STYLE["event"])
    if kind == "tool" and event.tool_name:
        label = f"TOOL · {html.escape(event.tool_name)}"
    href = f"event:{event.event_id}"  # the whole bubble is one clickable anchor
    header = f'<span style="color:#5b707e;font-size:10px;">{label} &nbsp;·&nbsp; {stamp}</span>'

    if kind == "log":
        text = html.escape(
            _truncate(_oneline(event.result or event.command or event.path or event.event_type), 200)
        )
        return (
            '<div style="text-align:left;font-size:11px;margin:3px 0;">'
            f'<a href="{href}" style="color:#9aa0a6;text-decoration:none;">'
            f"LOG {stamp}&nbsp;&nbsp;{text}</a></div>"
        )

    extra = ""
    if kind in ("tool", "result"):
        extra = ";font-family:Consolas,'Courier New',monospace;font-size:11px"
    elif kind == "thinking":
        extra = ";font-style:italic;color:#70684c"
    # Qt's rich-text engine can't reliably right-align block bubbles, so render
    # clean colour-coded bubbles (roles distinguished by colour + icon) at a
    # fixed width.  The whole bubble is wrapped in an anchor so clicking anywhere
    # on it opens the full event record in the detail panel.
    inner = f"{header}<br/>{_bubble_body(event, kind)}"
    return (
        f'<table width="74%" cellspacing="0" cellpadding="0" style="margin:4px 0;"><tr>'
        f'<td bgcolor="{background}" style="padding:7px 11px{extra}">'
        f'<a href="{href}" style="color:#203644;text-decoration:none;">{inner}</a>'
        "</td></tr></table>"
    )


def _bubble_body(event: NormalizedEvent, kind: str) -> str:
    if kind == "tool":
        pieces = []
        if event.command:
            pieces.append(html.escape(_truncate(_oneline(event.command), 600)))
        if event.path:
            pieces.append(f'<span style="color:#5b707e;">PATH · {html.escape(event.path)}</span>')
        return "<br/>".join(pieces) or html.escape(event.tool_name or "tool call")
    text = _truncate(str(event.result or event.command or event.path or ""), 1200)
    return html.escape(text).replace("\n", "<br/>")


def _local_haystack(event: NormalizedEvent) -> str:
    return " ".join(
        part.lower()
        for part in (
            event.path,
            event.tool_name,
            event.command,
            event.session_id,
            event.event_type,
            event.service,
        )
        if part
    )


def _entry_narrative(entry: dict) -> Narrative:
    """Interpret everything known about one file/folder as a bilingual summary."""
    ops = entry["ops"]
    return summarize_file(
        display_name=entry["filename"] or entry["path"] or "(unknown)",
        actor_class=entry["actor"],
        service=entry["service"],
        narratives=tuple(v.narrative for v in ops if v.narrative is not None),
        behaviors=tuple(verdict.behavior for verdict in ops),
        is_directory=entry.get("is_dir"),
        mft_count=len(entry.get("mft", [])),
        logfile_count=len(entry["logs"]),
        logfile_operations=tuple(
            str(event.metadata.get("operation"))
            for event in entry["logs"]
            if event.metadata.get("operation")
        ),
        matched_service=(
            entry["matched"].service if entry.get("matched") is not None else None
        ),
    )


def _entry_haystack(entry: dict) -> str:
    """Searchable text for an entry — path, name and both interpretations, so a
    plain-language search ("휴지통", "atomic", "timestomping") finds the file."""
    narrative = entry.get("narrative")
    interpretation = f"{narrative.headline_ko} {narrative.headline_en}" if narrative else ""
    return f"{entry.get('path') or ''} {entry.get('filename') or ''} {interpretation}".lower()


def _entry_has_behavior(entry: dict, behavior: str) -> bool:
    if behavior == "logfile_recovered":
        return bool(entry["logs"])
    return any(verdict.behavior == behavior for verdict in entry["ops"])


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _select_parsers(all_parsers, checked_ids):
    """Return the parsers whose module is checked in the Parse tab.

    Selection is explicit via checkboxes (services) and locked radios (NTFS);
    the NTFS on/off state is decided by :meth:`MainWindow._update_ntfs_lock`.
    """
    return tuple(parser for parser in all_parsers if parser.metadata.parser_id in checked_ids)


def _count_text(shown: int, matched: int, total: int, noun: str) -> str:
    if matched > shown:
        return (
            f"Showing {shown:,} of {matched:,} matching {noun}(s) "
            f"({total:,} total) — refine filters or search to narrow the view"
        )
    return f"{matched:,} of {total:,} {noun}(s)"


def _verdict_summary(verdicts: tuple[OperationVerdict, ...]) -> str:
    counts: dict[str, int] = {}
    for verdict in verdicts:
        counts[verdict.actor_class.value] = counts.get(verdict.actor_class.value, 0) + 1
    return ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))


def _format_local_datetime(value: datetime, fmt: str | None = None) -> str:
    """Format evidence time without letting an OS timezone limit crash the UI."""
    try:
        local_value = value.astimezone()
        return local_value.strftime(fmt) if fmt else local_value.isoformat()
    except (OSError, OverflowError, ValueError):
        try:
            utc_value = value.astimezone(timezone.utc)
            rendered = utc_value.strftime(fmt) if fmt else utc_value.isoformat()
            return f"{rendered} UTC" if fmt else rendered
        except (OSError, OverflowError, ValueError):
            return value.isoformat()


def _format_size(size: int | None) -> str:
    if size is None:
        return "—"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return str(size)


def _diagnostic_count(options: dict[str, object]) -> int:
    total = 0
    for key, value in options.items():
        if not (key.endswith("issues") or key.endswith("errors") or key.endswith("bad_records")):
            continue
        if isinstance(value, (list, tuple, set, dict)):
            total += len(value)
        elif value:
            total += 1
    return total


def _diagnostic_messages(options: dict[str, object]) -> list[str]:
    messages: list[str] = []
    for key, value in options.items():
        if not (key.endswith("issues") or key.endswith("errors") or key.endswith("bad_records")):
            continue
        values = value.values() if isinstance(value, dict) else value
        if isinstance(values, (list, tuple, set)) or hasattr(values, "__iter__") and not isinstance(values, str):
            messages.extend(f"{key}: {item}" for item in values)
        elif value:
            messages.append(f"{key}: {value}")
    return messages
