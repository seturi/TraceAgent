from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from parsers.registry import ParserRegistry
from version import __version__


SERVICES = ("All services", "Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")
IMAGE_FILTER = "Disk images (*.E01 *.e01 *.raw *.dd *.img *.vhd *.vhdx);;All files (*.*)"


class MainWindow(QMainWindow):
    def __init__(self, parser_registry: ParserRegistry | None = None) -> None:
        super().__init__()
        self.parser_registry = parser_registry or ParserRegistry()
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
        controls_layout.addWidget(self.collect_button)
        layout.addWidget(controls)
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
        self.module_tree.setHeaderLabels(("Module", "State"))
        self.module_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.module_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        registered_services = {
            service: parser
            for parser in self.parser_registry.all()
            for service in parser.metadata.services
        }
        for group, children in (
            ("Service artifact parsers", ("Claude Cowork", "Claude Code", "ChatGPT Desktop", "Antigravity", "Codex")),
            ("Filesystem parsers", ("NTFS $MFT", "NTFS $LogFile", "NTFS $UsnJrnl")),
        ):
            parent = QTreeWidgetItem((group, ""))
            self.module_tree.addTopLevelItem(parent)
            for child in children:
                parser = registered_services.get(child)
                if parser is None:
                    state = "Not installed"
                elif parser.metadata.implementation_status == "placeholder":
                    state = "Connected · placeholder"
                else:
                    state = "Ready"
                item = QTreeWidgetItem((child, state))
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
        self.parse_table = self._table(("Parser", "Artifact", "Records", "Errors", "Status"), 1)
        run_layout.addWidget(self.parse_table, 1)
        self.parse_log = QTextEdit()
        self.parse_log.setReadOnly(True)
        self.parse_log.setPlaceholderText("Parser diagnostics and audit messages")
        if self.parser_registry.all():
            self.parse_log.setPlainText(
                "Connected parser modules:\n"
                + "\n".join(
                    f"- {parser.metadata.name} ({parser.metadata.implementation_status})"
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
        label = "Current PC" if kind == "live_system" else self.source_path.text().strip()
        self.statusBar().showMessage(f"Source loaded read-only: {label}")
        self.collect_button.setEnabled(True)
        self.parse_button.setEnabled(bool(self.parser_registry.all()))
        self.tabs.setCurrentIndex(0)

    def _run_selected_parsers(self) -> None:
        self.parse_table.setRowCount(0)
        parsers = self.parser_registry.all()
        for parser in parsers:
            row = self.parse_table.rowCount()
            self.parse_table.insertRow(row)
            values = (
                parser.metadata.name,
                "No artifacts selected",
                "0",
                "0",
                parser.metadata.implementation_status.title(),
            )
            for column, value in enumerate(values):
                self.parse_table.setItem(row, column, QTableWidgetItem(value))
        self.parse_progress.setValue(100 if parsers else 0)
        if parsers:
            self.parse_log.append("\nPlaceholder run completed; no forensic events were emitted.")

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About TraceAgent",
            f"TraceAgent {__version__}\n\nCollection, parser orchestration, NTFS timeline analysis, and AI-agent attribution.",
        )
