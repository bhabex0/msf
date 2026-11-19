"""SQLite inventory for software installed by the tool manager.

Stores executable paths, setup/archive files, source URLs, configured web UIs,
install dates and the job that produced each record. All access is local and
thread-safe; no records are created unless an explicit install/update job runs
or the dashboard backfills tools that are already present.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config

_LOCK = threading.RLock()

_COLUMNS = (
    "tool_id", "name", "category", "method", "version",
    "executable_path", "setup_path", "source_url", "homepage_url",
    "web_url", "job_id", "installed_at", "updated_at", "metadata",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_path() -> Path:
    return Path(config.INSTALLED_DB_PATH)


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS installed_tools (
            tool_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            executable_path TEXT NOT NULL DEFAULT '',
            setup_path TEXT NOT NULL DEFAULT '',
            source_url TEXT NOT NULL DEFAULT '',
            homepage_url TEXT NOT NULL DEFAULT '',
            web_url TEXT NOT NULL DEFAULT '',
            job_id TEXT NOT NULL DEFAULT '',
            installed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}'
        )
    """)
    return conn


def ensure() -> bool:
    """Create the database/schema if needed. Returns True on success."""
    try:
        with _LOCK, closing(_connect()) as conn, conn:
            return True
    except Exception:
        return False


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = {column: row[column] for column in _COLUMNS}
    try:
        data["metadata"] = json.loads(data.get("metadata") or "{}")
    except Exception:
        data["metadata"] = {}
    return data


def upsert(record: dict[str, Any]) -> dict[str, Any] | None:
    """Insert or update one installed-software record."""
    tool_id = str(record.get("tool_id") or "").strip()
    if not tool_id:
        return None
    now = _now()
    try:
        metadata = json.dumps(record.get("metadata") or {}, ensure_ascii=False, default=str)
    except Exception:
        metadata = "{}"
    with _LOCK, closing(_connect()) as conn, conn:
        previous = conn.execute(
            "SELECT installed_at FROM installed_tools WHERE tool_id = ?", (tool_id,)
        ).fetchone()
        installed_at = previous["installed_at"] if previous else now
        values = (
            tool_id,
            str(record.get("name") or tool_id),
            str(record.get("category") or ""),
            str(record.get("method") or ""),
            str(record.get("version") or ""),
            str(record.get("executable_path") or ""),
            str(record.get("setup_path") or ""),
            str(record.get("source_url") or ""),
            str(record.get("homepage_url") or ""),
            str(record.get("web_url") or ""),
            str(record.get("job_id") or ""),
            installed_at,
            now,
            metadata,
        )
        conn.execute(
            """
            INSERT INTO installed_tools (
                tool_id, name, category, method, version, executable_path,
                setup_path, source_url, homepage_url, web_url, job_id,
                installed_at, updated_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_id) DO UPDATE SET
                name=excluded.name,
                category=excluded.category,
                method=excluded.method,
                version=excluded.version,
                executable_path=excluded.executable_path,
                setup_path=excluded.setup_path,
                source_url=excluded.source_url,
                homepage_url=excluded.homepage_url,
                web_url=excluded.web_url,
                job_id=excluded.job_id,
                updated_at=excluded.updated_at,
                metadata=excluded.metadata
            """,
            values,
        )
        row = conn.execute(
            "SELECT * FROM installed_tools WHERE tool_id = ?", (tool_id,)
        ).fetchone()
        return _row_to_dict(row)


def get(tool_id: str) -> dict[str, Any] | None:
    if not tool_id or not all(ch.isalnum() or ch in "-_" for ch in tool_id):
        return None
    try:
        with _LOCK, closing(_connect()) as conn:
            row = conn.execute(
                "SELECT * FROM installed_tools WHERE tool_id = ?", (tool_id,)
            ).fetchone()
            return _row_to_dict(row)
    except Exception:
        return None


def list_tools(limit: int = 200) -> list[dict[str, Any]]:
    try:
        with _LOCK, closing(_connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM installed_tools ORDER BY updated_at DESC LIMIT ?",
                (min(max(int(limit), 1), 500),),
            ).fetchall()
            return [item for row in rows if (item := _row_to_dict(row)) is not None]
    except Exception:
        return []


def delete(tool_id: str) -> bool:
    if not tool_id or not all(ch.isalnum() or ch in "-_" for ch in tool_id):
        return False
    try:
        with _LOCK, closing(_connect()) as conn, conn:
            cursor = conn.execute(
                "DELETE FROM installed_tools WHERE tool_id = ?", (tool_id,)
            )
            return cursor.rowcount > 0
    except Exception:
        return False


def count() -> int:
    try:
        with _LOCK, closing(_connect()) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM installed_tools").fetchone()[0])
    except Exception:
        return 0
