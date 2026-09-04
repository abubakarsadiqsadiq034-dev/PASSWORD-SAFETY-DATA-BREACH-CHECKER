"""
Safe local JSON file handling for reports and application data.

Owner: Angelica Ejezie (feature/file-json)

Rule: raw passwords must NEVER be written by any function in this module.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List

DATA_DIR = "data"
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")


def _ensure_data_dir() -> None:
    """Create the data directory if it doesn't already exist."""
    os.makedirs(DATA_DIR, exist_ok=True)


def load_json(path: str) -> Any:
    """Load JSON data from a file, returning an empty list if the file is
    missing or corrupted rather than crashing the application.
    """
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        # File exists but isn't valid JSON - back it up rather than
        # silently overwriting or crashing.
        backup_path = f"{path}.corrupted.{int(datetime.now().timestamp())}.bak"
        try:
            os.replace(path, backup_path)
        except OSError:
            pass
        return []
    except OSError as exc:
        raise IOError(f"Could not read {path}: {exc}") from exc


def save_json(path: str, data: Any) -> None:
    """Write JSON data to a file safely (write-to-temp-then-replace),
    so an interrupted write can't corrupt existing data.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp"

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except OSError as exc:
        raise IOError(f"Could not write {path}: {exc}") from exc
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def append_report(report_dict: Dict) -> None:
    """Append a single safe report dictionary to the reports file.

    Existing reports are preserved - this never overwrites the whole file
    with just the new entry.
    """
    _ensure_data_dir()
    reports: List[Dict] = load_json(REPORTS_FILE)
    if not isinstance(reports, list):
        reports = []
    reports.append(report_dict)
    save_json(REPORTS_FILE, reports)


def load_reports() -> List[Dict]:
    """Load all stored security reports."""
    _ensure_data_dir()
    reports = load_json(REPORTS_FILE)
    return reports if isinstance(reports, list) else []
