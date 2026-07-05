from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication

from parsers.bootstrap import create_default_parser_registry
from ui.main_window import MainWindow
from ui.theme import LIGHT_THEME
from version import __version__


def _quiet_dissect_logs() -> None:
    """Silence dissect's benign volume-probe warnings.

    When opening a normal NTFS disk, dissect probes RAID (MD/DDF) logical volume
    systems and logs ``WARNING`` lines such as "Failed to detect ... logical
    volume" when they do not apply.  These are not errors; suppress everything
    below ERROR so the console isn't flooded and users aren't alarmed.
    """
    logging.getLogger("dissect").setLevel(logging.ERROR)


def create_application(argv: list[str] | None = None) -> QApplication:
    _quiet_dissect_logs()
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("TraceAgent")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Digital Forensics Lab")
    app.setStyle("Fusion")
    app.setStyleSheet(LIGHT_THEME)
    return app


def main() -> int:
    app = create_application()
    window = MainWindow(parser_registry=create_default_parser_registry())
    window.show()
    return app.exec()
