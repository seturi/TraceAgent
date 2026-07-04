# TraceAgent

Version: `1.0.260704`

Windows-oriented forensic tooling for collecting, parsing, and correlating AI agent artifacts with NTFS events.

## Current scope

- Compact English, light-theme desktop interface
- Evidence source selection for live systems, disk images, and extracted folders
- Parser plugin contract for service artifacts and NTFS records
- Normalized timeline/event model with AI attribution confidence and evidence
- SQLite project database skeleton
- Empty-state UI ready for parser modules; no synthetic evidence is inserted

## Run

```powershell
python -m pip install --user -e ".[dev]"
python src/main.py
```

The project uses the user account's local Python installation. A project-specific virtual environment is not required.

## Architecture

```text
src/
  core/         normalized evidence and event models
  collection/   live-system and disk-image collector contracts
  parsers/      service artifact and NTFS parser contracts
  analysis/     timeline queries and AI attribution logic
  storage/      SQLite persistence
  reporting/    CSV, JSON, HTML, and PDF export contracts
  ui/           PySide6 main window and theme
  app.py        application bootstrap
  main.py       direct development entry point
```

The application reads source evidence and writes only to its separate workspace/database. Parser implementations will be added as independent plugins.
