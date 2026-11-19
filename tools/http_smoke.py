"""End-to-end HTTP smoke test against a running API.

Exercises upload, polling, every report/export endpoint, medical/toolchain/lab
endpoints, guarded lab actions, rule CRUD, policy, diff, SSE progress and the
dashboard. The server must already be running.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8123"
APK = Path(sys.argv[2] if len(sys.argv) > 2 else "sample-vulnerable.apk").resolve()

with httpx.Client(base_url=BASE, timeout=30) as c:
    health = c.get("/api/health").json()
    print("health:", health)
    print("config:", c.get("/api/config").json())

    with open(APK, "rb") as fh:
        r = c.post("/api/scans", files={"file": (APK.name, fh, "application/vnd.android.package-archive")})
    print("upload:", r.status_code, r.json())
    scan_id = r.json()["scan_id"]
    for _ in range(120):
        data = c.get(f"/api/scans/{scan_id}").json()
        if data["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)
    print("final:", data["status"], data["summary"])
    print("findings:", len(data["findings"]), "sca:", len(data["sca_findings"]))
    print("advanced:", sorted(data.get("advanced", {})))
    print("chains:", len(data.get("attack_chains", [])),
          "playbook:", len(data.get("playbook", [])),
          "custom:", len(data.get("custom_rules_applied", [])))
    print("policy:", data.get("policy", {}).get("status"))
    medical = data.get("medical", {})
    print("medical:", medical.get("status"), "phi:", medical.get("phi_present"),
          "risk:", medical.get("risk_level"),
          "gaps:", (medical.get("standards") or {}).get("gap_count"))
    print("toolchain:", len(data.get("toolchain", [])),
          "lab commands:", len((data.get("emulator") or {}).get("commands", [])),
          "patch workflows:", len((data.get("patching") or {}).get("steps", [])))

    checks = {
        "health": c.get("/health"),
        "healthz": c.get("/healthz"),
        "html": c.get(f"/api/scans/{scan_id}/report.html"),
        "json": c.get(f"/api/scans/{scan_id}/report.json"),
        "medical": c.get(f"/api/scans/{scan_id}/medical"),
        "toolchain": c.get(f"/api/scans/{scan_id}/toolchain"),
        "lab": c.get(f"/api/scans/{scan_id}/lab"),
        "advanced_tools": c.get("/api/tools/advanced"),
        "tool_catalog": c.get("/api/tools/catalog"),
        "installed": c.get("/api/tools/installed"),
        "installed_dashboard": c.get("/tools/dashboard"),
        "tool_jobs": c.get("/api/tools/jobs"),
        "lab_status": c.get("/api/lab/status"),
        "sbom": c.get(f"/api/scans/{scan_id}/export/sbom.json"),
        "sarif": c.get(f"/api/scans/{scan_id}/export/sarif.json"),
        "events": c.get(f"/api/scans/{scan_id}/events"),
        "dashboard": c.get("/"),
        "shell_help": c.post("/api/tools/shell", json={"command": "help", "confirm": True}),
    }
    print("http:", {k: (v.status_code, len(v.content)) for k, v in checks.items()})

    catalog = checks["tool_catalog"].json()
    print("tool manager:", catalog.get("enabled"), "catalog:", len(catalog.get("tools", [])),
          "sources:", len(catalog.get("allowed_hosts", [])),
          "os:", catalog.get("os", {}).get("system", ""),
          "installed:", checks["installed"].json().get("count", 0))
    print("tool groups:", [g["id"] for g in catalog.get("groups", [])],
          "icons:", sum(1 for t in catalog.get("tools", []) if t.get("icon")),
          "dashboard cards:", checks["installed_dashboard"].text.count("tool-card"),
          "main-ui cards:", checks["dashboard"].text.count("tool-card"))
    guarded = {
        "install_all": c.post("/api/tools/install-all", json={"confirm": False}),
        "update_all": c.post("/api/tools/update-all", json={"confirm": False}),
        "emulator": c.post("/api/tools/emulator/install", json={"confirm": False}),
        "single": c.post("/api/tools/apktool/install", json={"confirm": False}),
        "inventory_sync": c.post("/api/tools/installed/sync", json={"confirm": False}),
        "web_open": c.post("/api/tools/web/apktool", json={"confirm": False}),
        "shell_invalid": c.post("/api/tools/shell", json={"command": "rm -rf /"}),
    }
    print("tool manager guards:", {k: v.status_code for k, v in guarded.items()})
    print("shell colour level:", checks["shell_help"].json().get("level"))

    lab_actions = {
        "proxy_clear": c.post("/api/lab/proxy", json={"clear": True}),
        "open_mobsf": c.post("/api/lab/open-mobsf", json={"scan_id": scan_id}),
        "patch": c.post("/api/lab/patch", json={
            "workflow": "patch-apk.py", "scan_id": scan_id,
        }),
    }
    print("lab actions:", {
        k: (v.status_code, v.json().get("status") if v.headers.get("content-type", "").startswith("application/json") else None)
        for k, v in lab_actions.items()
    })

    others = [s["scan_id"] for s in c.get("/api/scans").json() if s["scan_id"] != scan_id]
    if others:
        diff = c.get(f"/api/scans/{scan_id}/diff", params={"against": others[0]})
        print("diff:", diff.status_code, diff.json().get("counts"))

    rules = c.get("/api/rules").json()
    print("rules:", len(rules))
    login = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    print("login:", login.status_code)
    if login.status_code == 200:
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        added = c.post("/api/rules", json={
            "id": "HTTP-SMOKE-TEMP", "title": "Temporary smoke rule",
            "severity": "low", "scope": "strings", "pattern": "HTTP_SMOKE_TEMP_ONLY",
        }, headers=headers)
        deleted = c.request("DELETE", "/api/rules", json={"rule_id": "HTTP-SMOKE-TEMP"}, headers=headers)
        print("rule crud:", added.status_code, deleted.status_code)
