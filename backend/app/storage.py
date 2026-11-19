"""Filesystem-backed scan storage (no external database required)."""

from __future__ import annotations

import json
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

from .config import SCANS_DIR
from .models import ScanRecord

_LOCK = threading.RLock()


def new_scan_id() -> str:
    return uuid.uuid4().hex[:16]


def scan_dir(scan_id: str) -> Path:
    # Prevent path traversal from ever reaching the filesystem.
    safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")
    if safe != scan_id or not safe:
        raise ValueError("invalid scan id")
    return SCANS_DIR / safe


def paths(scan_id: str) -> dict[str, Path]:
    d = scan_dir(scan_id)
    return {
        "dir": d,
        "apk": d / "upload.apk",
        "record": d / "record.json",
        "html": d / "report.html",
        "work": d / "work",
    }


def ensure_scan(scan_id: str, filename: str) -> ScanRecord:
    with _LOCK:
        p = paths(scan_id)
        p["dir"].mkdir(parents=True, exist_ok=True)
        p["work"].mkdir(parents=True, exist_ok=True)
        record = ScanRecord(scan_id=scan_id, filename=filename)
        save_record(record)
        return record


def save_record(record: ScanRecord) -> None:
    with _LOCK:
        p = paths(record.scan_id)
        p["dir"].mkdir(parents=True, exist_ok=True)
        tmp = p["record"].with_suffix(".json.tmp")
        tmp.write_text(record.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(p["record"])


def load_record(scan_id: str) -> ScanRecord | None:
    with _LOCK:
        p = paths(scan_id)["record"]
        if not p.exists():
            return None
        try:
            data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
            return ScanRecord.model_validate(data)
        except Exception:
            return None


def list_records() -> list[ScanRecord]:
    with _LOCK:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        out: list[ScanRecord] = []
        for d in SCANS_DIR.iterdir():
            if d.is_dir():
                r = load_record(d.name)
                if r is not None:
                    out.append(r)
        return sorted(out, key=lambda r: r.uploaded_at, reverse=True)


def delete_scan(scan_id: str) -> bool:
    with _LOCK:
        d = scan_dir(scan_id)
        if not d.exists():
            return False
        shutil.rmtree(d, ignore_errors=True)
        return True
