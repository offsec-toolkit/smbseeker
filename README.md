# SMBSeeker

Proactive SMB scanning, discovery, and content analysis tool.

## Features
- ✔ **Credential & Guest Scanning**: Automated login attempts with generic or provided credentials.
- ✔ **Depth & Profile Based Scanning**: Configurable scan depth for large file systems.
- ✔ **Intelligent Regex & IOC Extraction**: Automated search for secrets, keys, and indicators of compromise.
- ✔ **Multi Reporting Formats**: Export results to JSON, CSV, and SQLite.
- ✔ **Plugin Support**: Easily extendable analysis engine.
- ✔ **Fast Async Scanning**: High-performance scanning engine using Python's `asyncio`.

## Architecture
- `src/core/`: Scanning motor and orchestration.
- `src/smb/`: SMB protocol modules (Impacket-based).
- `src/analysis/`: File content and regex analysis.
- `src/reporting/`: Report generation (JSON, CSV, SQLite).
- `src/cli/`: Command-line interface.
- `src/plugins/`: Extensible plugin modules.

## Getting Started

### Prerequisites
- Python 3.11+

### Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Development
```bash
pip install -r requirements-dev.txt
pre-commit install
```

## Usage
```bash
python3 -m src.cli.main --help
```

## License
MIT
