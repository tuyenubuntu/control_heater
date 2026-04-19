from __future__ import annotations

import csv
import threading
from datetime import datetime
from pathlib import Path


_FILE_LOCKS: dict[str, threading.Lock] = {}


def _get_file_lock(path: str) -> threading.Lock:
    if path not in _FILE_LOCKS:
        _FILE_LOCKS[path] = threading.Lock()
    return _FILE_LOCKS[path]


class LoggingService:
    def __init__(self, csv_path: str | Path = "log/logs.csv"):
        self.csv_path = Path(csv_path)
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = _get_file_lock(str(self.csv_path))
        self._ensure_header()

    def _ensure_header(self) -> None:
        if not self.csv_path.exists() or self.csv_path.stat().st_size == 0:
            with self._lock:
                with self.csv_path.open("a", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["timestamp", "level", "source", "message", "details"])

    def log(
        self,
        level: str,
        source: str,
        message: str,
        details: str = "",
        timestamp: datetime | None = None,
    ) -> None:
        timestamp = timestamp or datetime.now()
        row = [
            timestamp.isoformat(sep=" ", timespec="seconds"),
            level.upper(),
            str(source),
            str(message),
            str(details),
        ]
        with self._lock:
            with self.csv_path.open("a", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(row)

    def info(self, source: str, message: str, details: str = "") -> None:
        self.log("INFO", source, message, details)

    def warning(self, source: str, message: str, details: str = "") -> None:
        self.log("WARNING", source, message, details)

    def error(self, source: str, message: str, details: str = "") -> None:
        self.log("ERROR", source, message, details)

    def debug(self, source: str, message: str, details: str = "") -> None:
        self.log("DEBUG", source, message, details)
