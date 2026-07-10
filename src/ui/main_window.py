from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QSizeF
from PySide6.QtGui import QAction, QTextDocument
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from analysis.ntfs.attribution import OperationVerdict, attribute_ntfs_events, build_agent_index
from analysis.ntfs.signatures import basename_of, normalize_path
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
from parsers.registry import ParserRegistry
from reporting.exporters import (
    CaseReport,
    FileAttributionRow,
    SessionSummaryRow,
    export_activity_csv,
    export_case_report_json,
    export_html_report,
    render_html_report,
)
from reporting.parsed_writer import write_parsed_events
from utils.case_paths import CasePaths, create_case_paths
from utils.evidence_access import SourceAccessError, open_evidence_accessor
from version import __version__


SERVICES = ("All services", "Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")
LOCAL_SERVICES = ("Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")
NTFS_ACTORS = ("All actors", "AI agent", "Human", "System", "Unknown")
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
        self.service_tree_items: dict[str, QTreeWidgetItem] = {}
        self.service_parsers = {
            service: parser
            for parser in self.parser_registry.all()
            for service in parser.metadata.services
        }
        self.setWindowTitle("TraceAgent")
        self.resize(1440, 900)
        self.setMinimumSize(1120, 720)
        self._build_menu()
        self.setCentralWidget(self._build_content())
        self.statusBar().showMessage("Ready — no evidence source loaded")
        self.version_label = QLabel(f"VERSION  {__version__}", objectName="VersionLabel")
        self.version_label.setToolTip(f"TraceAgent {__version__}")
        self.statusBar().addPermanentWidget(self.version_label)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")
        open_action = QAction("Select Evidence Source…", self)
        open_action.triggered.connect(self._browse_source)
        file_menu.addAction(open_action)
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

        help_menu = self.menuBar().addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _build_content(self) -> QWidget:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(12)
        layout.addWidget(self._build_header())
        layout.addWidget(self._build_source_bar())

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_collect_tab(), "1  Collect")
        self.tabs.addTab(self._build_parse_tab(), "2  Parse")
        self.tabs.addTab(self._build_analyze_tab(), "3  Analyze")
        layout.addWidget(self.tabs, 1)
        return root

    def _build_header(self) -> QFrame:
        frame = QFrame(objectName="Header")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 12, 16, 12)
        title_box = QVBoxLayout()
        title_box.addWidget(QLabel("TraceAgent", objectName="AppTitle"))
        title_box.addWidget(QLabel("AI agent artifact and NTFS timeline analysis", objectName="Muted"))
        layout.addLayout(title_box)
        layout.addStretch()
        layout.addWidget(QLabel("READ-ONLY EVIDENCE", objectName="ReadOnlyBadge"))
        return frame

    def _build_source_bar(self) -> QFrame:
        frame = QFrame(objectName="SourceBar")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)
        layout.addWidget(QLabel("Evidence source"))
        self.source_kind = QComboBox()
        self.source_kind.addItem("Current PC", "live_system")
        self.source_kind.addItem("Disk image", "disk_image")
        self.source_kind.addItem("Extracted artifact folder", "artifact_directory")
        self.source_kind.currentIndexChanged.connect(self._source_kind_changed)
        layout.addWidget(self.source_kind)
        self.source_path = QLineEdit()
        self.source_path.setPlaceholderText("Local computer (live collection)")
        self.source_path.setReadOnly(True)
        layout.addWidget(self.source_path, 1)
        self.browse_button = QPushButton("Browse…")
        self.browse_button.clicked.connect(self._browse_source)
        self.browse_button.setEnabled(False)
        layout.addWidget(self.browse_button)
        self.load_button = QPushButton("Load Source", objectName="PrimaryButton")
        self.load_button.clicked.connect(self._load_source)
        layout.addWidget(self.load_button)
        return frame

    def _build_collect_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        controls = QFrame(objectName="Panel")
        controls_layout = QHBoxLayout(controls)
        title_box = QVBoxLayout()
        title_box.addWidget(QLabel("Evidence collection", objectName="SectionTitle"))
        title_box.addWidget(QLabel("Acquire artifacts without modifying the source.", objectName="Muted"))
        controls_layout.addLayout(title_box)
        controls_layout.addStretch()
        self.hash_check = QCheckBox("Calculate SHA-256")
        self.hash_check.setChecked(True)
        controls_layout.addWidget(self.hash_check)
        self.collect_button = QPushButton("Start Collection", objectName="PrimaryButton")
        self.collect_button.setEnabled(False)
        self.collect_button.clicked.connect(self._collect_artifacts)
        controls_layout.addWidget(self.collect_button)
        layout.addWidget(controls)
        self.collection_progress = QProgressBar()
        self.collection_progress.setTextVisible(False)
        layout.addWidget(self.collection_progress)
        self.collection_table = self._table(("Source", "Artifact", "Path", "Size", "SHA-256", "Status"), 2)
        layout.addWidget(self.collection_table, 1)
        hint = QLabel("No collected artifacts. Select and load an evidence source to begin.", objectName="Muted")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(hint)
        return page

    def _build_parse_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)

        module_panel = QFrame(objectName="Panel")
        module_layout = QVBoxLayout(module_panel)
        module_layout.addWidget(QLabel("Parser modules", objectName="SectionTitle"))
        module_layout.addWidget(QLabel("Check the services to parse.", objectName="Muted"))
        self.module_tree = QTreeWidget()
        self.module_tree.setSelectionMode(QAbstractItemView.NoSelection)
        self.module_tree.setHeaderLabels(("Module", "State"))
        self.module_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.module_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ntfs_radios: list[tuple[QRadioButton, str]] = []
        for group, children in (
            ("Service artifact parsers", ("Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")),
            ("Filesystem parsers", ("NTFS $MFT", "NTFS $UsnJrnl", "NTFS $LogFile")),
        ):
            parent = QTreeWidgetItem((group, ""))
            self.module_tree.addTopLevelItem(parent)
            for child in children:
                parser = self.service_parsers.get(child)
                if parser is None:
                    state = "Parser unavailable"
                elif parser.metadata.implementation_status == "placeholder":
                    state = "Parser pending"
                else:
                    state = "Parser ready"
                item = QTreeWidgetItem((child, state))
                if group == "Service artifact parsers":
                    self.service_tree_items[child] = item
                parent.addChild(item)
                if parser is None:
                    continue
                item.setToolTip(0, parser.metadata.description)
                item.setData(0, Qt.UserRole, parser.metadata.parser_id)
                if parser.metadata.category == "ntfs":
                    # NTFS is required: shown as a locked radio button (on by
                    # default, off on live systems), never a user checkbox.
                    item.setText(0, "")
                    radio = QRadioButton(child)
                    radio.setAutoExclusive(False)
                    radio.setChecked(True)
                    radio.setEnabled(False)
                    radio.setToolTip(parser.metadata.description)
                    self.ntfs_radios.append((radio, parser.metadata.parser_id))
                    self.module_tree.setItemWidget(item, 0, radio)
                else:
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(0, Qt.Checked)
            parent.setExpanded(True)
        module_layout.addWidget(self.module_tree, 1)
        module_layout.addWidget(
            QLabel(
                "NTFS is required and locked on; on live systems it is locked off "
                "(reading $MFT/$UsnJrnl needs Administrator).",
                objectName="Muted",
            )
        )
        layout.addWidget(module_panel, 2)

        run_panel = QFrame(objectName="Panel")
        run_layout = QVBoxLayout(run_panel)
        run_layout.addWidget(QLabel("Parsing queue", objectName="SectionTitle"))
        run_layout.addWidget(QLabel("Discovered artifacts and parser progress will appear here.", objectName="Muted"))
        self.parse_progress = QProgressBar()
        self.parse_progress.setTextVisible(False)
        run_layout.addWidget(self.parse_progress)
        self.parse_table = self._table(("Parser", "Artifacts", "Records", "Errors", "Status"), 1)
        run_layout.addWidget(self.parse_table, 1)
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
        self.parse_log.setMaximumHeight(140)
        run_layout.addWidget(self.parse_log)
        button_row = QHBoxLayout()
        button_row.addStretch()
        self.parse_button = QPushButton("Run Selected Parsers", objectName="PrimaryButton")
        self.parse_button.setEnabled(False)
        self.parse_button.clicked.connect(self._run_selected_parsers)
        button_row.addWidget(self.parse_button)
        run_layout.addLayout(button_row)
        layout.addWidget(run_panel, 5)
        return page

    def _build_analyze_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(
            QLabel(
                "Results are split into local application artifacts (by service) and "
                "NTFS file-system events (by file/folder, with human vs AI-agent attribution).",
                objectName="Muted",
            )
        )
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
        self.la_search.textChanged.connect(self._refresh_local_tree)
        filters.addWidget(self.la_search, 2)
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
        self.la_show_low_importance.toggled.connect(self._refresh_local_timeline)
        filters.addWidget(self.la_show_low_importance)
        outer.addWidget(bar)

        splitter = QSplitter(Qt.Horizontal)

        # Left: service -> session navigation tree
        nav = QFrame(objectName="Panel")
        nav_layout = QVBoxLayout(nav)
        nav_layout.addWidget(QLabel("Sessions by service", objectName="SectionTitle"))
        self.la_count = QLabel("No parsed local artifacts yet.", objectName="Muted")
        self.la_count.setWordWrap(True)
        nav_layout.addWidget(self.la_count)
        self.la_tree = QTreeWidget()
        self.la_tree.setHeaderLabels(("Service / session", "Events"))
        self.la_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.la_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.la_tree.itemSelectionChanged.connect(self._on_session_selected)
        nav_layout.addWidget(self.la_tree, 1)
        splitter.addWidget(nav)

        # Center: conversation/activity timeline for the selected session
        center = QFrame(objectName="Panel")
        center_layout = QVBoxLayout(center)
        center_layout.addWidget(QLabel("Conversation timeline", objectName="SectionTitle"))
        self.la_session_label = QLabel("Select a session to reconstruct its activity.", objectName="Muted")
        self.la_session_label.setWordWrap(True)
        center_layout.addWidget(self.la_session_label)
        self.la_chat = QTextBrowser()
        self.la_chat.setOpenLinks(False)
        self.la_chat.setStyleSheet("QTextBrowser { background:#fafbfc; border:none; }")
        self.la_chat.anchorClicked.connect(self._on_chat_anchor)
        center_layout.addWidget(self.la_chat, 1)
        splitter.addWidget(center)

        # Right: full event detail
        panel, self.la_detail = self._detail_panel(
            "Event details", "Select a timeline entry to inspect its full record."
        )
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 5)
        splitter.setStretchFactor(2, 3)
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
        self.ntfs_search.textChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_search, 2)
        self.ntfs_actor = QComboBox()
        self.ntfs_actor.addItems(NTFS_ACTORS)
        self.ntfs_actor.currentIndexChanged.connect(self._refresh_ntfs_events)
        filters.addWidget(self.ntfs_actor)
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
        self.ntfs_count = QLabel("No NTFS operations classified yet.", objectName="Muted")
        left_layout.addWidget(self.ntfs_count)
        self.ntfs_table = self._table(
            ("Filename", "Path", "Actor", "Service", "Operations", "Last activity"), 1
        )
        self.ntfs_table.setSortingEnabled(True)
        self.ntfs_table.itemSelectionChanged.connect(self._show_ntfs_detail)
        left_layout.addWidget(self.ntfs_table, 1)
        splitter.addWidget(left)
        panel, self.ntfs_detail = self._detail_panel(
            "File / folder activity",
            "Select a file or folder to see its full NTFS activity timeline and the human vs AI-agent verdict.",
        )
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        outer.addWidget(splitter, 1)
        return page

    @staticmethod
    def _table(headers: tuple[str, ...], stretch_column: int) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(stretch_column, QHeaderView.Stretch)
        return table

    def _source_kind_changed(self) -> None:
        live = self.source_kind.currentData() == "live_system"
        extracted = self.source_kind.currentData() == "artifact_directory"
        self.browse_button.setEnabled(not live)
        self.collect_button.setText("Use Artifact Folder" if extracted else "Start Collection")
        self.source_path.clear()
        self.source_path.setPlaceholderText("Local computer (live collection)" if live else "Select a source path")

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

        self.load_button.setEnabled(False)
        self.collect_button.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.statusBar().showMessage(f"Opening source read-only: {label}")
        QApplication.processEvents()
        try:
            with open_evidence_accessor(source) as accessor:
                info = accessor.info()
                detections = self.artifact_collector.scan(source, accessor)
            ntfs_folder_artifacts = self.ntfs_collector.scan(source)
        except (SourceAccessError, OSError, ValueError) as exc:
            self.current_source = None
            self.service_detections = ()
            self.ntfs_folder_artifacts = ()
            self.collection_table.setRowCount(0)
            self._update_parse_service_states()
            QMessageBox.critical(self, "Evidence Source", str(exc))
            self.statusBar().showMessage("Failed to open evidence source")
            return
        finally:
            self.load_button.setEnabled(True)

        self.current_source = source
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
        self.collect_button.setEnabled(
            present_count > 0
            or source.kind in {SourceKind.LIVE_SYSTEM, SourceKind.DISK_IMAGE}
            or bool(ntfs_folder_artifacts)
        )
        self.tabs.setCurrentIndex(0)

    def _show_service_detections(self, detections: tuple[ServiceDetection, ...]) -> None:
        self.collection_table.setRowCount(0)
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
        collected_counts: dict[str, int] = {}
        for artifact in self.collected_artifacts:
            if artifact.service:
                collected_counts[artifact.service] = collected_counts.get(artifact.service, 0) + 1

        for service, item in self.service_tree_items.items():
            parser = self.service_parsers.get(service)
            detection = detections.get(service)
            found = bool(detection and detection.present)
            collected = collected_counts.get(service, 0)

            if self.current_source is None:
                if parser is None:
                    state = "Parser unavailable"
                elif parser.metadata.implementation_status == "placeholder":
                    state = "Parser pending"
                else:
                    state = "Parser ready"
            elif not found:
                state = "Not detected"
            elif parser is None:
                state = "Artifacts found · no parser"
            elif parser.metadata.implementation_status == "placeholder":
                state = "Artifacts found · parser pending"
            elif collected:
                state = f"Ready · {collected} collected"
            else:
                state = "Ready · artifacts found"

            item.setText(1, state)

    def _collect_artifacts(self) -> None:
        if self.current_source is None:
            QMessageBox.warning(self, "Collection", "Load an evidence source first.")
            return

        self.collect_button.setEnabled(False)
        self.load_button.setEnabled(False)
        self.collection_table.setRowCount(0)
        self.collection_progress.setValue(0)
        if self.case_paths is None:
            try:
                self.case_paths = create_case_paths(self.current_source)
            except OSError as exc:
                QMessageBox.critical(self, "Collection", f"Unable to create case folder: {exc}")
                self.load_button.setEnabled(True)
                self.collect_button.setEnabled(True)
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
            self.load_button.setEnabled(True)
            self.collect_button.setEnabled(
                any(item.present for item in self.service_detections)
                or self.current_source.kind in {SourceKind.LIVE_SYSTEM, SourceKind.DISK_IMAGE}
                or bool(self.ntfs_folder_artifacts)
            )

        self.collected_artifacts = records
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
                )
            )
        errors = context.options.get("collection_errors", [])
        self._record_ntfs_collection_status(records, context)
        self.collection_progress.setValue(100)
        self.parse_button.setEnabled(bool(records) and bool(self.parser_registry.all()))
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
            self.collection_table.setItem(row, column, QTableWidgetItem(value))

    def _update_ntfs_lock(self, source_kind: SourceKind) -> None:
        """Lock the NTFS radios on (default) or off (live systems need Admin)."""
        on = source_kind != SourceKind.LIVE_SYSTEM
        for radio, _parser_id in getattr(self, "ntfs_radios", []):
            radio.setChecked(on)
            radio.setEnabled(False)  # locked either way

    def _checked_parser_ids(self) -> set[str]:
        ids: set[str] = set()
        for group_index in range(self.module_tree.topLevelItemCount()):
            group = self.module_tree.topLevelItem(group_index)
            for child_index in range(group.childCount()):
                child = group.child(child_index)
                parser_id = child.data(0, Qt.UserRole)
                if (
                    parser_id
                    and bool(child.flags() & Qt.ItemIsUserCheckable)
                    and child.checkState(0) == Qt.Checked
                ):
                    ids.add(parser_id)
        for radio, parser_id in getattr(self, "ntfs_radios", []):
            if radio.isChecked():
                ids.add(parser_id)
        return ids

    def _run_selected_parsers(self) -> None:
        if self.current_source is None or self.collection_root is None or self.case_paths is None:
            QMessageBox.warning(self, "Parsing", "Collect service artifacts first.")
            return

        self.parse_table.setRowCount(0)
        self.parse_log.clear()
        all_parsers = self.parser_registry.all()
        parsers = _select_parsers(all_parsers, self._checked_parser_ids())
        if not parsers:
            QMessageBox.information(self, "Parsing", "Check at least one parser module to run.")
            self.parse_button.setEnabled(True)
            return
        parse_source = EvidenceSource(
            SourceKind.ARTIFACT_DIRECTORY,
            self.collection_root,
            label=f"Collected artifacts from {self.current_source.label}",
            read_only=True,
            source_id=self.current_source.source_id,
        )
        all_events: list[NormalizedEvent] = []

        self.parse_button.setEnabled(False)
        self.parse_progress.setValue(0)
        for parser_index, parser in enumerate(parsers, start=1):
            artifact_count = 0
            record_count = 0
            error_count = 0
            status = "Completed"
            if parser.metadata.implementation_status == "placeholder":
                status = "Pending"
            else:
                context = ParseContext(
                    workspace=self.collection_root,
                    progress=lambda _percent, message, name=parser.metadata.name: self._parse_progress(
                        name, message
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
                except Exception as exc:
                    status = "Failed"
                    error_count += 1
                    self.parse_log.append(f"[{parser.metadata.name}] ERROR: {exc}")

            row = self.parse_table.rowCount()
            self.parse_table.insertRow(row)
            values = (
                parser.metadata.name,
                str(artifact_count),
                str(record_count),
                str(error_count),
                status,
            )
            for column, value in enumerate(values):
                self.parse_table.setItem(row, column, QTableWidgetItem(value))
            self.parse_progress.setValue(round(parser_index / max(len(parsers), 1) * 100))
            QApplication.processEvents()

        outcome = attribute_ntfs_events(all_events)
        self.ntfs_verdicts = outcome.verdicts
        self.parsed_events = tuple(sorted(outcome.events, key=lambda event: event.timestamp))
        self._populate_analyze_views()
        for action in self.export_actions.values():
            action.setEnabled(bool(self.parsed_events))
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
        self.parse_button.setEnabled(bool(self.collected_artifacts) and bool(all_parsers))
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

    def _parse_progress(self, parser_name: str, message: str) -> None:
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
        sessions: dict[str, dict] = {}
        for event in getattr(self, "_local_events", ()):
            service = event.service or "Unknown"
            session_id = event.session_id or "(session-less)"
            key = f"{service} {session_id}"
            entry = sessions.setdefault(
                key, {"service": service, "session_id": session_id, "events": []}
            )
            entry["events"].append(event)
        for entry in sessions.values():
            entry["events"].sort(key=lambda e: e.timestamp)
            entry["first"] = entry["events"][0].timestamp
            entry["last"] = entry["events"][-1].timestamp
        self._sessions = sessions
        self._current_session_key = None
        self._timeline_events: tuple[NormalizedEvent, ...] = ()
        self.la_chat.clear()
        self.la_session_label.setText("Select a session to reconstruct its activity.")
        self.la_detail.clear()
        self._refresh_local_tree()

    def _refresh_local_tree(self) -> None:
        tree = self.la_tree
        tree.clear()
        needle = self.la_search.text().strip().lower()
        sessions = getattr(self, "_sessions", {})
        by_service: dict[str, list] = {}
        shown = 0
        for key, entry in sessions.items():
            if needle and not _session_matches(entry, needle):
                continue
            by_service.setdefault(entry["service"], []).append((key, entry))
            shown += 1
        for service in sorted(by_service):
            entries = sorted(by_service[service], key=lambda item: item[1]["first"])
            n_events = sum(len(e["events"]) for _, e in entries)
            parent = QTreeWidgetItem((service, f"{len(entries)} · {n_events:,}"))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            tree.addTopLevelItem(parent)
            for key, entry in entries:
                session_id = entry["session_id"]
                short = session_id if len(session_id) <= 18 else f"{session_id[:8]}…{session_id[-4:]}"
                when = _format_local_datetime(entry["first"], "%m-%d %H:%M")
                child = QTreeWidgetItem((f"{when}  {short}", str(len(entry["events"]))))
                child.setToolTip(0, session_id)
                child.setData(0, Qt.UserRole, key)
                parent.addChild(child)
            parent.setExpanded(True)

        total_sessions = len(sessions)
        total_events = sum(len(e["events"]) for e in sessions.values())
        if total_sessions == 0:
            self.la_count.setText("No local artifact sessions parsed yet.")
            return
        counts = getattr(self, "_local_service_counts", Counter())
        breakdown = "   ".join(f"{name}: {count:,}" for name, count in sorted(counts.items()) if name)
        self.la_count.setText(
            f"{shown} of {total_sessions} session(s)  ·  {total_events:,} events\n{breakdown}"
        )

    def _on_session_selected(self) -> None:
        items = self.la_tree.selectedItems()
        if not items:
            return
        key = items[0].data(0, Qt.UserRole)
        if not key:  # a service group header, not a session
            return
        self._current_session_key = key
        self._refresh_local_timeline()

    def _refresh_local_timeline(self) -> None:
        key = getattr(self, "_current_session_key", None)
        entry = getattr(self, "_sessions", {}).get(key) if key else None
        if entry is None:
            self.la_chat.clear()
            self._timeline_events = ()
            return
        kind_filter = _TYPE_FILTER.get(self.la_type.currentText())
        show_low_importance = self.la_show_low_importance.isChecked()
        shown: list[NormalizedEvent] = []
        for event in entry["events"]:
            if not show_low_importance and event.metadata.get("importance") == "low":
                continue
            _, kind = _event_kind(event)
            if kind_filter and kind != kind_filter:
                continue
            shown.append(event)
            if len(shown) >= MAX_DISPLAY_ROWS:
                break
        self._timeline_events = tuple(shown)
        self.la_chat.setHtml(_chat_document(shown))
        self.la_session_label.setText(
            f"Session {entry['session_id']}  ·  {entry['service']}  ·  "
            f"{_format_local_datetime(entry['first'], '%Y-%m-%d %H:%M')}–"
            f"{_format_local_datetime(entry['last'], '%H:%M:%S')}  ·  "
            f"{len(shown)}/{len(entry['events'])} shown"
        )

    def _on_chat_anchor(self, url) -> None:
        target = url.toString()
        if target.startswith("event:"):
            event = self._event_by_id.get(target[len("event:") :])
            if event is not None:
                self._render_event_detail(event)

    def _render_event_detail(self, event: NormalizedEvent) -> None:
        icon, kind = _event_kind(event)
        lines = [
            f"{icon} {kind.upper()}",
            f"Timestamp : {_format_local_datetime(event.timestamp)}",
            f"Service   : {event.service or '—'}",
            f"Session   : {event.session_id or '—'}",
            f"Actor     : {event.actor or '—'}",
            f"Event type: {event.event_type}",
        ]
        if event.tool_name:
            lines.append(f"Tool      : {event.tool_name}")
        if event.path:
            lines.append(f"Path      : {event.path}")
        if event.command:
            lines += ["", "Command:", _truncate(event.command, 2000)]
        if event.result:
            lines += ["", "Result / content:", _truncate(event.result, 3000)]
        badges = _forensic_badges(event)
        if badges:
            lines += ["", "Forensic markers:"] + [f"  • {badge}" for badge in badges]
        lines += ["", f"Raw source: {event.raw_reference or '—'}"]
        self.la_detail.setPlainText("\n".join(lines))

    # -- NTFS events view (per file/folder) ----------------------------------
    def _refresh_ntfs_events(self) -> None:
        table = self.ntfs_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        needle = self.ntfs_search.text().strip().lower()
        actor = self.ntfs_actor.currentText()
        behavior = self.ntfs_behavior.currentText()
        hide_system = self.ntfs_hide_system.isChecked()
        entries = getattr(self, "_file_entries", ())
        matched = 0
        for entry in entries:
            if hide_system and entry["actor"] == ActorClass.SYSTEM:
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
        values = (
            entry["filename"] or "—",
            entry["path"] or "—",
            _actor_class_label(entry["actor"], entry["service"]),
            entry["service"] or "—",
            str(len(entry["ops"]) + len(entry["logs"]) + len(entry.get("mft", []))),
            _format_local_datetime(last, "%Y-%m-%d %H:%M:%S") if last else "—",
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setData(Qt.UserRole, f"file:{entry['key']}")
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
            "",
            "── Activity timeline ──",
        ]
        if not ops:
            recovered = ", ".join(s for s, present in (("$MFT", mft), ("$LogFile", logs)) if present)
            lines.append(f"  (no USN operations — recovered from {recovered or 'other artifacts'})")
        for verdict in ops:
            lines.append(
                f"{_format_local_datetime(verdict.start, '%Y-%m-%d %H:%M:%S')}  "
                f"[{_actor_class_label(verdict.actor_class, verdict.service)}]  {verdict.behavior}"
            )
            flow = self._operation_flow(verdict)
            if flow:
                lines.append(f"    flow: {flow}")
            if verdict.reasons:
                lines.append(f"    evidence: {', '.join(verdict.reasons[:3])}")
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
        return CaseReport(
            source_label=self.current_source.label if self.current_source else "Unknown source",
            generated_at=datetime.now(timezone.utc),
            events=self.parsed_events,
            file_rows=file_rows,
            session_rows=session_rows,
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


def _event_kind(event: NormalizedEvent) -> tuple[str, str]:
    """Classify a local-artifact event into a display kind + icon."""
    event_type = (event.event_type or "").lower()
    actor = (event.actor or "").lower()
    if "log" in event_type:
        return ("📄", "log")
    if "tool_result" in event_type or "function_call_output" in event_type or "tool-result" in event_type:
        return ("✅", "result")
    if "tool_use" in event_type or "tool_call" in event_type or (
        "function_call" in event_type and "output" not in event_type
    ):
        return ("🔧", "tool")
    if "thinking" in event_type or "reasoning" in event_type:
        return ("🧠", "thinking")
    if actor == "user" or "user" in event_type or "prompt" in event_type:
        return ("👤", "prompt")
    if actor == "assistant" or "assistant" in event_type or "message" in event_type:
        return ("💬", "message")
    return ("•", "event")


def _event_summary(event: NormalizedEvent, kind: str) -> str:
    if kind == "tool":
        name = event.tool_name or "tool"
        extra = event.command or event.path
        return f"{name}   {_oneline(extra)}".strip() if extra else name
    text = event.result or event.command or event.path or event.event_type
    return _truncate(_oneline(text), 400)


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
    "user": ("👤 user", "right", "#c3e1ff"),
    "message": ("💬 assistant", "left", "#eef0f2"),
    "thinking": ("🧠 thinking", "left", "#f4efe0"),
    "tool": ("🔧 tool", "left", "#ece7f8"),
    "result": ("✅ result", "left", "#e2f4e4"),
    "event": ("• event", "left", "#eef0f2"),
}


def _chat_document(events: list[NormalizedEvent] | tuple[NormalizedEvent, ...]) -> str:
    """Render a session's events as a chat-style HTML transcript."""
    if not events:
        return ""
    parts = ["<html><body style=\"font-family:'Segoe UI',sans-serif;\">"]
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
        label = f"🔧 {html.escape(event.tool_name)}"
    href = f"event:{event.event_id}"  # the whole bubble is one clickable anchor
    header = f'<span style="color:#5f6368;font-size:10px;">{label} &nbsp;·&nbsp; {stamp}</span>'

    if kind == "log":
        text = html.escape(
            _truncate(_oneline(event.result or event.command or event.path or event.event_type), 200)
        )
        return (
            '<div style="text-align:left;font-size:11px;margin:3px 0;">'
            f'<a href="{href}" style="color:#9aa0a6;text-decoration:none;">'
            f"📄 {stamp}&nbsp;&nbsp;{text}</a></div>"
        )

    extra = ""
    if kind in ("tool", "result"):
        extra = ";font-family:Consolas,'Courier New',monospace;font-size:11px"
    elif kind == "thinking":
        extra = ";font-style:italic;color:#6b6b6b"
    # Qt's rich-text engine can't reliably right-align block bubbles, so render
    # clean colour-coded bubbles (roles distinguished by colour + icon) at a
    # fixed width.  The whole bubble is wrapped in an anchor so clicking anywhere
    # on it opens the full event record in the detail panel.
    inner = f"{header}<br/>{_bubble_body(event, kind)}"
    return (
        f'<table width="74%" cellspacing="0" cellpadding="0" style="margin:4px 0;"><tr>'
        f'<td bgcolor="{background}" style="padding:7px 11px{extra}">'
        f'<a href="{href}" style="color:#202124;text-decoration:none;">{inner}</a>'
        "</td></tr></table>"
    )


def _bubble_body(event: NormalizedEvent, kind: str) -> str:
    if kind == "tool":
        pieces = []
        if event.command:
            pieces.append(html.escape(_truncate(_oneline(event.command), 600)))
        if event.path:
            pieces.append(f'<span style="color:#5f6368;">→ {html.escape(event.path)}</span>')
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


def _entry_haystack(entry: dict) -> str:
    return f"{entry.get('path') or ''} {entry.get('filename') or ''}".lower()


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
