# TraceAgent

AI Agent Forensics

Version: `1.2.260706`

## Requirements

- Windows 10 or 11
- Python 3.11 or later
- Git

## Initial setup

Install Git before setting up TraceAgent. From the `TraceAgent` directory,
install TraceAgent and all runtime dependencies:

```powershell
python -m pip install --user -e .
```

The command installs PySide6, Brotli, CCL Chromium Reader, Dissect Target, and
their transitive dependencies into the current user's Python environment. A
virtual environment is not required.

## Run

```powershell
python src/main.py
```
