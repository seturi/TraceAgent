LIGHT_THEME = """
QWidget {
    background: #f6f8fb; color: #172033;
    font-family: "Segoe UI"; font-size: 13px;
}
QMainWindow, QDialog { background: #f6f8fb; }
QFrame#Header, QFrame#SourceBar, QFrame#Panel, QFrame#DetailPanel {
    background: #ffffff; border: 1px solid #dfe5ee; border-radius: 8px;
}
QLabel#AppTitle { font-size: 20px; font-weight: 700; color: #14213d; }
QLabel#SectionTitle { font-size: 15px; font-weight: 650; color: #14213d; }
QLabel#Muted { color: #68758a; }
QLabel#VersionLabel {
    color: #ffffff;
    background: #2e9187;
    border: 1px solid #24786f;
    border-radius: 8px;
    padding: 3px 10px;
    margin: 2px 4px 2px 0;
    font-family: "Consolas";
    font-size: 11px;
    font-weight: 700;
}
QLabel#ReadOnlyBadge {
    color: #17633a; background: #e8f7ee; border: 1px solid #b8e2c8;
    border-radius: 9px; padding: 3px 8px; font-weight: 600;
}
QPushButton {
    background: #ffffff; border: 1px solid #cbd4e1;
    border-radius: 6px; padding: 7px 13px;
}
QPushButton:hover { background: #f1f5fa; border-color: #9dadc2; }
QPushButton#PrimaryButton {
    background: #2855d9; color: #ffffff; border-color: #2855d9; font-weight: 600;
}
QPushButton#PrimaryButton:hover { background: #2149bf; }
QPushButton:disabled, QPushButton#PrimaryButton:disabled {
    color: #8f9bad; background: #e9edf3; border-color: #d8dee7;
}
QLineEdit, QComboBox {
    background: #ffffff; border: 1px solid #cbd4e1;
    border-radius: 6px; padding: 6px 9px; min-height: 20px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #5377e8; }
QTabWidget::pane {
    background: #ffffff; border: 1px solid #dfe5ee;
    border-radius: 8px; top: -1px;
}
QTabBar::tab {
    background: #edf1f7; border: 1px solid #dfe5ee; padding: 9px 24px;
    margin-right: 4px; border-top-left-radius: 6px;
    border-top-right-radius: 6px; font-weight: 600;
}
QTabBar::tab:selected { background: #ffffff; color: #234dc7; border-bottom-color: #ffffff; }
QHeaderView::section {
    background: #eef2f7; color: #334158; border: none;
    border-right: 1px solid #dce2ea; border-bottom: 1px solid #d6dde7;
    padding: 7px; font-weight: 650;
}
QTableWidget, QTreeWidget {
    background: #ffffff; alternate-background-color: #f8fafc;
    border: 1px solid #dfe5ee; border-radius: 6px;
    gridline-color: #e7ebf1; selection-background-color: #dce7ff;
    selection-color: #172033;
}
QProgressBar {
    background: #edf1f6; border: none; border-radius: 5px;
    height: 10px; text-align: center;
}
QProgressBar::chunk { background: #3768e5; border-radius: 5px; }
QTextEdit { background: #fbfcfe; border: 1px solid #dfe5ee; border-radius: 6px; }
QSplitter::handle { background: #e3e8f0; width: 1px; }
"""
