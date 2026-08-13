"""Warm, modern light theme for the TraceAgent forensic workstation."""

LIGHT_THEME = r"""
QWidget {
    background: #FAFAF9; color: #1C1917;
    font-family: "Inter", "Segoe UI", sans-serif; font-size: 13px;
    selection-background-color: #EEF2FF; selection-color: #1C1917;
}
QMainWindow, QDialog { background: #FAFAF9; }
QDialog#EventDetailsDialog { background: #FFFFFF; }
QLabel, QCheckBox, QRadioButton { background: transparent; }
QLabel#SectionTitle { color: #1C1917; font-size: 13px; font-weight: 600; }
QLabel#FieldLabel { color: #57534E; font-size: 12px; }
QLabel#Muted { color: #A8A29E; font-size: 11px; }

QMenuBar { background: #FAFAF9; color: #57534E; border-bottom: 1px solid #E7E5E4; padding: 2px 8px; }
QMenuBar::item { padding: 5px 9px; border-radius: 4px; }
QMenuBar::item:selected { background: #F5F5F4; color: #1C1917; }
QMenu { background: #FFFFFF; color: #1C1917; border: 1px solid #E7E5E4; padding: 4px; }
QMenu::item { padding: 6px 28px 6px 9px; border-radius: 4px; }
QMenu::item:selected { background: #F5F5F4; }

QToolBar#MainToolBar { background: #FFFFFF; border: none; border-bottom: 1px solid #E7E5E4; spacing: 3px; padding: 5px 8px; }
QToolBar#MainToolBar::separator { background: #E7E5E4; width: 1px; margin: 4px 6px; }
QToolButton { background: transparent; color: #57534E; border: 1px solid transparent; border-radius: 6px; padding: 5px 8px; }
QToolButton:hover { background: #F5F5F4; color: #1C1917; }
QToolButton:pressed, QToolButton:checked { background: #EEF2FF; color: #3730A3; }
QToolButton:disabled { color: rgba(168,162,158,102); background: transparent; }

QFrame#SourceBar, QFrame#FilterBar { background: #FFFFFF; border: none; border-radius: 8px; }
QFrame#Panel { background: #FFFFFF; border: none; border-radius: 8px; }
QFrame#DetailPanel { background: #FFFFFF; border: none; border-radius: 8px; }
QFrame#ParsePlanPanel, QFrame#ParseRunPanel { background: #FFFFFF; border: none; border-radius: 8px; }
QLabel#ParserGroupLabel { color: #A8A29E; font-size: 10px; font-weight: 600; padding: 2px 1px 0; }
QLabel#ParsePlanSummary { color: #57534E; font-size: 12px; padding-right: 5px; }
QFrame#ParserOption { background: #FAFAF9; border: none; border-radius: 6px; }
QFrame#ParserOption:hover { background: #F5F5F4; }
QFrame#ParserOption[selected="true"] { background: #FFFFFF; border: 1px solid #818CF8; }
QFrame#ParserOption[selected="true"] QLabel#ParserOptionName { color: #3730A3; }
QFrame#ParserOption[available="false"] QLabel { color: #A8A29E; }
QLabel#ParserOptionName { color: #1C1917; font-size: 12px; font-weight: 600; }
QLabel#ParserOptionState { color: #78716C; font-size: 11px; }
QLabel#ParserServiceIcon { background: transparent; border: none; }
QLabel#ParserSelectedBadge { color: #4338CA; background: #EEF2FF; border: none; border-radius: 4px; padding: 3px 6px; font-size: 9px; font-weight: 700; }
QLabel#ParseEmptyState { color: #A8A29E; font-size: 12px; }
QFrame#WorkspacePanel { background: #FAFAF9; border: none; border-right: 1px solid #E7E5E4; }
QLabel#PaneTitle { background: transparent; color: #57534E; border: none; padding: 6px 7px; font-size: 11px; font-weight: 600; }

QPushButton { background: #FFFFFF; color: #57534E; border: 1px solid #E7E5E4; border-radius: 6px; padding: 5px 11px; min-height: 20px; }
QPushButton:hover { background: #F5F5F4; color: #1C1917; }
QPushButton:pressed { background: #E7E5E4; }
QPushButton:focus { border: 1px solid #4F46E5; }
QPushButton#AccentButton, QPushButton#AccentButton:default { background: #4F46E5; color: #FFFFFF; border: 1px solid #4F46E5; font-weight: 600; }
QPushButton#AccentButton:hover { background: #4338CA; }
QPushButton#ActivityToggle, QPushButton#QuietButton { background: transparent; border: none; color: #57534E; padding: 3px 5px; min-height: 18px; }
QPushButton#ActivityToggle:hover, QPushButton#QuietButton:hover { background: #F5F5F4; color: #1C1917; }
QPushButton:disabled { background: #F5F5F4; color: rgba(168,162,158,102); border-color: #E7E5E4; }

QLineEdit, QComboBox { background: #FFFFFF; color: #1C1917; border: 1px solid #E7E5E4; border-radius: 6px; padding: 5px 8px; min-height: 20px; }
QLineEdit:focus, QComboBox:focus { border: 1px solid #4F46E5; }
QLineEdit:read-only { color: #A8A29E; background: #FAFAF9; }
QLineEdit:disabled, QComboBox:disabled { color: #A8A29E; background: #F5F5F4; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: #FFFFFF; color: #1C1917; border: 1px solid #E7E5E4; selection-background-color: #EEF2FF; selection-color: #1C1917; }
QComboBox#CompactSort { min-width: 92px; font-size: 11px; padding: 3px 7px; min-height: 18px; }

QTabWidget::pane { background: #FFFFFF; border: none; border-radius: 0; }
QTabBar { background: #FFFFFF; }
QTabBar::tab { background: transparent; color: #A8A29E; border: none; border-bottom: 2px solid transparent; padding: 8px 16px 7px; margin: 0 4px 0 0; }
QTabBar::tab:hover { color: #57534E; background: #F5F5F4; }
QTabBar::tab:selected { color: #1C1917; border-bottom: 2px solid #4F46E5; font-weight: 600; }

QHeaderView::section { background: #FAFAF9; color: #57534E; border: none; border-bottom: 1px solid #E7E5E4; padding: 5px 7px; font-size: 11px; font-weight: 600; }
QTableWidget, QTreeWidget { background: #FFFFFF; alternate-background-color: #FAFAF9; color: #1C1917; border: 1px solid #E7E5E4; border-radius: 6px; gridline-color: #E7E5E4; selection-background-color: #EEF2FF; selection-color: #1C1917; font-size: 12px; }
QTableWidget::item, QTreeWidget::item { padding: 2px 6px; }
QTableWidget::item:hover, QTreeWidget::item:hover { background: #F5F5F4; }
QTableWidget::item:selected, QTreeWidget::item:selected { background: #EEF2FF; color: #1C1917; border-left: 3px solid #4F46E5; }
QTreeWidget#WorkspaceTree { background: #FAFAF9; border: none; border-radius: 0; }
QTreeWidget#WorkspaceTree::item { min-height: 28px; border: none; padding: 0 5px; }

QListWidget#SessionList, QListWidget#TimelineList { background: #FAFAF9; border: none; border-radius: 6px; outline: 0; padding: 0; }
QListWidget#SessionList::item, QListWidget#TimelineList::item { border: none; margin: 0; padding: 0; }
QListWidget#ParseTimeline { background: #FFFFFF; border: none; border-radius: 0; outline: 0; padding: 0; }
QListWidget#ParseTimeline::item { border: none; border-bottom: 1px solid #F5F5F4; margin: 0; padding: 0; }
QListWidget#ParseTimeline::item:hover { background: #FAFAF9; }
QListWidget#ParseTimeline::item:selected { background: #EEF2FF; color: #1C1917; }

QTextEdit, QTextBrowser { background: #FFFFFF; color: #1C1917; border: 1px solid #E7E5E4; border-radius: 6px; selection-background-color: #EEF2FF; selection-color: #1C1917; font-size: 12px; }
QTextBrowser#StructuredDetails { border: none; background: #FFFFFF; }
QDialog#EventDetailsDialog QTextBrowser#StructuredDetails { border: 1px solid #E7E5E4; background: #FFFFFF; padding: 4px; }

QProgressBar { background: #F5F5F4; border: none; border-radius: 3px; height: 6px; }
QProgressBar::chunk { background: #4F46E5; border-radius: 3px; }
QSplitter::handle { background: transparent; width: 8px; }
QSplitter::handle:hover { background: #F5F5F4; }
QLabel#SplitterGrip { color: #A8A29E; background: transparent; border: none; }

QStatusBar { background: #FAFAF9; color: #57534E; border-top: 1px solid #E7E5E4; min-height: 28px; max-height: 28px; font-size: 11px; }
QLabel#EvidenceModeStatus { color: #57534E; background: #F5F5F4; border: none; border-radius: 4px; padding: 2px 7px; margin: 3px 5px; font-size: 10px; }
QLabel#VersionLabel { color: #A8A29E; border-left: 1px solid #E7E5E4; padding: 1px 8px; font-family: Consolas; font-size: 10px; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #D6D3D1; min-height: 28px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: #A8A29E; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; }
QScrollBar::handle:horizontal { background: #D6D3D1; min-width: 28px; border-radius: 5px; margin: 2px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""
