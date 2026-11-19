"""Direct pipeline smoke test (no HTTP server required)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app import storage  # noqa: E402
from app.scanner.pipeline import run_scan  # noqa: E402


def main() -> None:
    apk = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "sample-vulnerable.apk").resolve()
    scan_id = storage.new_scan_id()
    storage.ensure_scan(scan_id, apk.name)
    target = storage.paths(scan_id)["apk"]
    target.write_bytes(apk.read_bytes())
    print(f"scan_id={scan_id}")
    run_scan(scan_id)
    record = storage.load_record(scan_id)
    assert record is not None
    print(f"status={record.status} error={record.error}")
    print(f"package={record.manifest.package} sha256={record.sha256[:16]}")
    print(f"summary={record.summary.model_dump()}")
    print(f"SAST findings={len(record.findings)}  SCA findings={len(record.sca_findings)}")
    print(f"components={[c.name + ':' + str(c.version) for c in record.components]}")
    print(f"DAST status={record.dast_status}")
    for f in record.findings[:8]:
        print(f"  [{f.severity:8}] {f.title}")
    for f in record.sca_findings[:8]:
        print(f"  [{f.severity:8}] {f.title}")
    html = storage.paths(scan_id)["html"]
    print(f"report={html} exists={html.exists()} bytes={html.stat().st_size if html.exists() else 0}")


if __name__ == "__main__":
    main()
