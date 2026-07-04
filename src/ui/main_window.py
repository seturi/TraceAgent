from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
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
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from collection.artifact_collector import ServiceArtifactCollector
from collection.base import CollectionContext
from collection.service_catalog import ServiceDetection
from core.models import ArtifactRecord, EvidenceSource, NormalizedEvent, SourceKind
from parsers.base import ParseContext
from parsers.registry import ParserRegistry
from reporting.parsed_writer import write_parsed_events
from utils.case_paths import CasePaths, create_case_paths
from utils.evidence_access import SourceAccessError, open_evidence_accessor
from version import __version__


SERVICES = ("All services", "Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")
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
        for label in ("CSV…", "JSON…", "HTML Report…", "PDF Report…"):
            action = QAction(label, self)
            action.setEnabled(False)
            export_menu.addAction(action)

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
        module_layout.addWidget(QLabel("Parsers use the common module contract.", objectName="Muted"))
        self.module_tree = QTreeWidget()
        self.module_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.module_tree.setHeaderLabels(("Module", "State"))
        self.module_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.module_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        for group, children in (
            ("Service artifact parsers", ("Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")),
            ("Filesystem parsers", ("NTFS $MFT", "NTFS $LogFile", "NTFS $UsnJrnl")),
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
                if parser is not None:
                    item.setToolTip(0, parser.metadata.description)
                    item.setData(0, Qt.UserRole, parser.metadata.parser_id)
                parent.addChild(item)
            parent.setExpanded(True)
        module_layout.addWidget(self.module_tree, 1)
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
        filter_bar = QFrame(objectName="Panel")
        filters = QHBoxLayout(filter_bar)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search file path, tool, command, or session ID")
        filters.addWidget(self.search_input, 2)
        self.service_filter = QComboBox()
        self.service_filter.addItems(SERVICES)
        filters.addWidget(self.service_filter)
        self.event_filter = QComboBox()
        self.event_filter.addItems(("All events", "Create", "Modify", "Rename", "Move", "Copy", "Delete", "Permission", "Tool call"))
        filters.addWidget(self.event_filter)
        self.attribution_filter = QComboBox()
        self.attribution_filter.addItems(("All attribution", "Confirmed", "High", "Medium", "Low", "Not attributed"))
        filters.addWidget(self.attribution_filter)
        self.agent_only = QCheckBox("AI-attributed only")
        filters.addWidget(self.agent_only)
        layout.addWidget(filter_bar)

        splitter = QSplitter(Qt.Horizontal)
        timeline_panel = QFrame(objectName="Panel")
        timeline_layout = QVBoxLayout(timeline_panel)
        timeline_layout.addWidget(QLabel("File event timeline", objectName="SectionTitle"))
        self.timeline_table = self._table(("Time", "Event", "Path", "Service", "Tool", "AI attribution", "Score"), 2)
        self.timeline_table.setSortingEnabled(True)
        timeline_layout.addWidget(self.timeline_table, 1)
        splitter.addWidget(timeline_panel)

        detail_panel = QFrame(objectName="DetailPanel")
        detail_panel.setMinimumWidth(310)
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.addWidget(QLabel("Event details", objectName="SectionTitle"))
        detail_layout.addWidget(QLabel("Select an event to inspect provenance and attribution evidence.", objectName="Muted"))
        form = QFormLayout()
        for label in ("Timestamp", "Event type", "File path", "Service", "Session", "Tool / command", "Raw source"):
            value = QLabel("—")
            value.setWordWrap(True)
            form.addRow(label, value)
        detail_layout.addLayout(form)
        detail_layout.addWidget(QLabel("AI attribution", objectName="SectionTitle"))
        detail_layout.addWidget(QLabel("Not evaluated"))
        detail_layout.addWidget(QLabel("Attribution evidence", objectName="SectionTitle"))
        reasons = QTextEdit()
        reasons.setReadOnly(True)
        detail_layout.addWidget(reasons, 1)
        splitter.addWidget(detail_panel)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
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
        self.browse_button.setEnabled(not live)
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
        except (SourceAccessError, OSError, ValueError) as exc:
            self.current_source = None
            self.service_detections = ()
            self.collection_table.setRowCount(0)
            self._update_parse_service_states()
            QMessageBox.critical(self, "Evidence Source", str(exc))
            self.statusBar().showMessage("Failed to open evidence source")
            return
        finally:
            self.load_button.setEnabled(True)

        self.current_source = source
        self.service_detections = detections
        self.collected_artifacts = ()
        self.collection_root = None
        self.parsed_events = ()
        self.case_paths = None
        self._show_service_detections(detections)
        self._update_parse_service_states()
        present_count = sum(detection.present for detection in detections)
        fs_text = f", {info.filesystems} filesystem(s)" if info.filesystems is not None else ""
        self.statusBar().showMessage(
            f"Source opened read-only: {info.user_homes} user profile(s){fs_text}; "
            f"{present_count} supported service(s) found"
        )
        self.collect_button.setEnabled(present_count > 0)
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
            records = tuple(self.artifact_collector.collect(self.current_source, context))
        except (SourceAccessError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Collection", str(exc))
            self.statusBar().showMessage("Artifact collection failed")
            return
        finally:
            self.load_button.setEnabled(True)
            self.collect_button.setEnabled(any(item.present for item in self.service_detections))

        self.collected_artifacts = records
        self.collection_root = self.case_paths.artifacts
        self._update_parse_service_states()
        for record in records:
            self._append_collection_row(
                (
                    record.service or "Unknown",
                    record.artifact_type,
                    record.path,
                    _format_size(record.size),
                    record.sha256 or "Not calculated",
                    "Collected",
                )
            )
        errors = context.options.get("collection_errors", [])
        self.collection_progress.setValue(100)
        self.parse_button.setEnabled(bool(records) and bool(self.parser_registry.all()))
        self.statusBar().showMessage(
            f"Collected {len(records)} artifact file(s); {len(errors)} error(s) — "
            f"{self.case_paths.root}"
        )
        self.tabs.setCurrentIndex(1)

    def _collection_progress(self, percent: int, message: str) -> None:
        self.collection_progress.setValue(percent)
        self.statusBar().showMessage(message)
        QApplication.processEvents()

    def _append_collection_row(self, values: tuple[str, ...]) -> None:
        row = self.collection_table.rowCount()
        self.collection_table.insertRow(row)
        for column, value in enumerate(values):
            self.collection_table.setItem(row, column, QTableWidgetItem(value))

    def _run_selected_parsers(self) -> None:
        if self.current_source is None or self.collection_root is None or self.case_paths is None:
            QMessageBox.warning(self, "Parsing", "Collect service artifacts first.")
            return

        self.parse_table.setRowCount(0)
        timeline_sorting = self.timeline_table.isSortingEnabled()
        self.timeline_table.setSortingEnabled(False)
        self.timeline_table.setRowCount(0)
        self.parse_log.clear()
        selected_ids = {
            item.data(0, Qt.UserRole)
            for item in self.module_tree.selectedItems()
            if item.data(0, Qt.UserRole)
        }
        all_parsers = self.parser_registry.all()
        parsers = tuple(
            parser
            for parser in all_parsers
            if not selected_ids or parser.metadata.parser_id in selected_ids
        )
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

        self.parsed_events = tuple(sorted(all_events, key=lambda event: event.timestamp))
        for event in self.parsed_events:
            self._append_timeline_event(event)
        self.timeline_table.setSortingEnabled(timeline_sorting)
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
        if self.parsed_events:
            self.tabs.setCurrentIndex(2)

    def _parse_progress(self, parser_name: str, message: str) -> None:
        self.statusBar().showMessage(f"{parser_name}: {message}")
        QApplication.processEvents()

    def _append_timeline_event(self, event: NormalizedEvent) -> None:
        row = self.timeline_table.rowCount()
        self.timeline_table.insertRow(row)
        values = (
            event.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            event.event_type,
            event.path or "—",
            event.service or "—",
            event.tool_name or event.command or "—",
            event.attribution.value,
            f"{event.attribution_score:.2f}",
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(Qt.UserRole, event.event_id)
            self.timeline_table.setItem(row, column, item)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About TraceAgent",
            f"TraceAgent {__version__}\n\nCollection, parser orchestration, NTFS timeline analysis, and AI-agent attribution.",
        )


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
