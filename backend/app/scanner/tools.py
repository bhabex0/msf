"""Optional hooks for external tools. Built-in engines work without any of these."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..config import (
    MOBSF_API_KEY,
    MOBSF_TIMEOUT,
    MOBSF_URL,
    SEMGREP_TIMEOUT,
    TOOL_AAPT,
    TOOL_APKTOOL,
    TOOL_FINDING_LIMIT,
    TOOL_JADX,
    TOOL_SEMGREP,
)
from .rules import finding


@dataclass
class ToolOutcome:
    name: str
    available: bool
    enabled: bool
    ran: bool = False
    detail: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def as_result(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "enabled": self.enabled,
            "ran": self.ran,
            "detail": self.detail,
            "findings_count": len(self.findings),
        }


def _which(name: str) -> str | None:
    return shutil.which(name)


def probe_tools() -> list[dict[str, Any]]:
    return [
        {"name": "apktool", "available": bool(_which("apktool")), "enabled": TOOL_APKTOOL},
        {"name": "jadx", "available": bool(_which("jadx")), "enabled": TOOL_JADX},
        {"name": "aapt", "available": bool(_which("aapt") or _which("aapt2")), "enabled": TOOL_AAPT},
        {
            "name": "adb",
            "available": bool(_which("adb")),
            "enabled": True,
        },
        {"name": "frida", "available": bool(_which("frida")), "enabled": True},
        {"name": "semgrep", "available": bool(_which("semgrep")), "enabled": TOOL_SEMGREP},
        {"name": "MobSF", "available": bool(MOBSF_URL), "enabled": bool(MOBSF_URL)},
    ]


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, "executable not found"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except Exception as exc:
        return 1, str(exc)


def _read_texts(directory: Path, patterns: tuple[str, ...], max_files: int = 400) -> list[str]:
    out: list[str] = []
    count = 0
    for pattern in patterns:
        for path in directory.rglob(pattern):
            if count >= max_files:
                return out
            try:
                out.append(path.read_text(encoding="utf-8", errors="replace")[:400_000])
                count += 1
            except Exception:
                pass
    return out


def run_apktool(apk: Path, work: Path) -> ToolOutcome:
    exe = _which("apktool")
    outcome = ToolOutcome("apktool", bool(exe), TOOL_APKTOOL)
    if not exe or not TOOL_APKTOOL:
        outcome.detail = "not installed or disabled"
        return outcome
    out = work / "apktool"
    code, log = _run([exe, "d", "-f", "-s", "-o", str(out), str(apk)], timeout=240)
    if code != 0:
        outcome.detail = f"failed (exit {code}): {log[-400:]}"
        return outcome
    texts = _read_texts(out, ("AndroidManifest.xml", "*.xml"))
    outcome.strings = "\n".join(texts).splitlines()
    outcome.data = {"output_dir": str(out), "manifest_decompiled": (out / "AndroidManifest.xml").exists()}
    outcome.detail = f"decompiled resources/manifest into {out.name}"
    outcome.ran = True
    return outcome


def run_jadx(apk: Path, work: Path) -> ToolOutcome:
    exe = _which("jadx")
    outcome = ToolOutcome("jadx", bool(exe), TOOL_JADX)
    if not exe or not TOOL_JADX:
        outcome.detail = "not installed or disabled"
        return outcome
    out = work / "jadx"
    code, log = _run([exe, "-d", str(out), str(apk)], timeout=300)
    if code != 0:
        outcome.detail = f"failed (exit {code}): {log[-400:]}"
        return outcome
    texts = _read_texts(out, ("*.java",))
    outcome.strings = "\n".join(texts).splitlines()
    outcome.data = {"output_dir": str(out), "source_files": len(texts)}
    outcome.detail = f"decompiled {len(texts)} Java source files"
    outcome.ran = True
    return outcome


def run_aapt(apk: Path) -> ToolOutcome:
    exe = _which("aapt2") or _which("aapt")
    outcome = ToolOutcome("aapt", bool(exe), TOOL_AAPT)
    if not exe or not TOOL_AAPT:
        outcome.detail = "not installed or disabled"
        return outcome
    args = [exe, "dump", "badging", str(apk)] if exe.endswith("aapt") else [exe, "dump", "badging", str(apk)]
    code, log = _run(args, timeout=90)
    if code != 0:
        outcome.detail = f"failed (exit {code}): {log[-400:]}"
        return outcome
    outcome.strings = log.splitlines()
    outcome.data = {"badging": log[:8000]}
    outcome.detail = "captured package badging metadata"
    outcome.ran = True
    return outcome


def _mobsf_finding(item: dict[str, Any]) -> dict[str, Any] | None:
    title = item.get("finding") or item.get("title") or item.get("name")
    if not title:
        return None
    sev = str(item.get("severity", "info")).lower()
    if sev not in ("critical", "high", "medium", "low", "info", "good", "warning", "secure"):
        sev = "info"
    if sev in ("good", "secure"):
        return None
    if sev == "warning":
        sev = "medium"
    description = str(item.get("description") or item.get("info") or "")
    evidence = str(item.get("match") or item.get("evidence") or "")
    remediation = str(item.get("remediation") or item.get("recommendation") or "")
    # A readable slug plus a content hash keeps distinct findings with the same
    # truncated title instead of silently collapsing them into one result.
    slug = "".join(
        c for c in str(title).upper().replace(" ", "-") if c.isalnum() or c in "-_"
    )[:40] or "FINDING"
    identity = "|".join((str(title), sev, description, evidence, remediation))
    suffix = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:8]
    return finding(
        f"TOOL-MOBSF-{slug}-{suffix}",
        f"MobSF: {title}",
        sev,  # type: ignore[arg-type]
        category="TOOL",
        description=description[:1000],
        evidence=evidence[:800],
        remediation=remediation,
        cwe=item.get("cwe"),
        masvs=item.get("masvs"),
        confidence="medium",
        references=[item.get("reference")] if isinstance(item.get("reference"), str) else [],
    )


def run_mobsf(apk: Path, poll_timeout: int = MOBSF_TIMEOUT) -> ToolOutcome:
    outcome = ToolOutcome("MobSF", bool(MOBSF_URL), bool(MOBSF_URL))
    if not MOBSF_URL:
        outcome.detail = "not configured (set APKPT_MOBSF_URL)"
        return outcome
    headers = {"Authorization": MOBSF_API_KEY} if MOBSF_API_KEY else {}
    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            with open(apk, "rb") as fh:
                up = client.post(
                    f"{MOBSF_URL}/api/v1/upload",
                    files={"file": (apk.name, fh, "application/vnd.android.package-archive")},
                )
            up.raise_for_status()
            scan_id = up.json().get("scan_id")
            if not scan_id:
                outcome.detail = "upload did not return a scan_id"
                return outcome
            scan = client.post(f"{MOBSF_URL}/api/v1/scan", data={"scan_id": scan_id, "scan_type": "apk"})
            scan.raise_for_status()

            deadline = time.time() + poll_timeout
            report: dict[str, Any] | None = None
            while time.time() < deadline:
                try:
                    r = client.get(f"{MOBSF_URL}/api/v1/scan_status/{scan_id}")
                    if r.status_code == 200 and str(r.json().get("status", "")).lower() in ("done", "completed"):
                        rr = client.get(f"{MOBSF_URL}/api/v1/report_json/{scan_id}")
                        rr.raise_for_status()
                        report = rr.json()
                        break
                except Exception:
                    pass
                time.sleep(4)
            if report is None:
                outcome.detail = f"scan did not finish within {poll_timeout}s"
                return outcome

            seen: set[str] = set()
            for section, value in report.items():
                if not isinstance(value, list):
                    continue
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    f = _mobsf_finding(item)
                    if f and f["id"] not in seen:
                        seen.add(f["id"])
                        outcome.findings.append(f)
            outcome.data = {
                "scan_id": scan_id,
                "sections": [k for k, v in report.items() if isinstance(v, list)],
            }
            outcome.detail = f"MobSF report received ({len(outcome.findings)} findings)"
            outcome.ran = True
    except Exception as exc:
        outcome.detail = f"error: {exc}"[:500]
    return outcome


SEMGREP_RULES = """rules:
  - id: apkpt-webview-javascript
    languages: [java]
    severity: WARNING
    message: WebView JavaScript is enabled.
    pattern-regex: 'setJavaScriptEnabled\\s*\\(\\s*true'
  - id: apkpt-webview-bridge
    languages: [java]
    severity: ERROR
    message: A JavaScript-to-Java bridge is exposed.
    pattern-regex: 'addJavascriptInterface\\s*\\('
  - id: apkpt-trust-all
    languages: [java]
    severity: ERROR
    message: Custom TLS trust implementation requires review.
    pattern-regex: 'checkServerTrusted\\s*\\(|ALLOW_ALL_HOSTNAME_VERIFIER'
  - id: apkpt-weak-crypto
    languages: [java]
    severity: WARNING
    message: Weak cryptographic primitive used.
    pattern-regex: 'MessageDigest\\.getInstance\\s*\\(\\s*" *(MD5|SHA-1|SHA1)'
  - id: apkpt-log-sensitive
    languages: [java]
    severity: WARNING
    message: Potentially sensitive data written to logs.
    pattern-regex: 'Log\\.[dvewi]\\s*\\([^;]*(password|token|secret|apiKey)'
  - id: apkpt-sql-concat
    languages: [java]
    severity: WARNING
    message: Raw SQL query with concatenation requires review.
    pattern-regex: 'rawQuery\\s*\\([^;]*\\+'
  - id: apkpt-world-readable
    languages: [java]
    severity: ERROR
    message: World-readable or world-writeable file mode.
    pattern-regex: 'MODE_WORLD_(READABLE|WRITEABLE)'
"""


def run_semgrep(apk: Path, work: Path, java_source: Path | None = None) -> ToolOutcome:
    exe = _which("semgrep")
    outcome = ToolOutcome("semgrep", bool(exe), TOOL_SEMGREP)
    if not exe or not TOOL_SEMGREP:
        outcome.detail = "not installed or disabled"
        return outcome
    if not java_source or not java_source.exists():
        outcome.detail = "requires jadx-generated Java source (install jadx or enable APKPT_TOOL_JADX)"
        return outcome
    rules = work / "semgrep-rules.yml"
    try:
        rules.write_text(SEMGREP_RULES, encoding="utf-8")
    except Exception as exc:
        outcome.detail = f"could not write rules: {exc}"
        return outcome
    code, log = _run([exe, "scan", "--json", "--config", str(rules), str(java_source)], timeout=SEMGREP_TIMEOUT)
    if code not in (0, 1, 2):
        code, log2 = _run([exe, "--json", "--config", str(rules), str(java_source)], timeout=SEMGREP_TIMEOUT)
        if code not in (0, 1, 2):
            outcome.detail = f"failed (exit {code}): {log2[-400:]}"
            return outcome
        log = log2
    try:
        payload = json.loads(log[log.find("{"):log.rfind("}") + 1])
    except Exception:
        outcome.detail = f"could not parse semgrep JSON: {log[-300:]}"
        return outcome
    results = payload.get("results", [])
    if TOOL_FINDING_LIMIT > 0:
        results = results[:TOOL_FINDING_LIMIT]
    for item in results:
        extra = item.get("extra", {})
        sev = str(extra.get("severity", "WARNING")).lower()
        severity = "high" if sev in ("error", "critical", "high") else "medium" if sev in ("warning", "medium") else "low"
        check_id = str(item.get("check_id", "semgrep.rule")).split(".")[-1]
        location = f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}"
        evidence = str(extra.get("lines", ""))
        message = str(extra.get("message", check_id))
        # Semgrep often reports many matches for one rule. Include the match
        # location and evidence in the ID so each occurrence survives dedupe.
        identity = "|".join((check_id, location, evidence, message))
        suffix = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:8]
        outcome.findings.append(
            finding(
                f"SEMGREP-{check_id.upper()}-{suffix}",
                f"Semgrep: {message}",
                severity,  # type: ignore[arg-type]
                category="SEMGREP",
                description=str(extra.get("message", "Semgrep rule matched decompiled source.")),
                evidence=evidence[:1000],
                location=location,
                remediation="Review the matched source location and apply the corresponding secure coding control.",
                masvs="MASVS-CODE-2",
                confidence="medium",
            )
        )
    outcome.data = {"result_count": len(payload.get("results", [])), "rule_file": str(rules)}
    outcome.detail = f"semgrep reported {len(payload.get('results', []))} match(es)"
    outcome.ran = True
    return outcome


def run_all_tools(apk: Path, work: Path) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    apktool = run_apktool(apk, work)
    jadx = run_jadx(apk, work)
    semgrep = run_semgrep(apk, work, Path(jadx.data["output_dir"]) if jadx.data.get("output_dir") else None)
    outcomes = [apktool, jadx, semgrep, run_aapt(apk), run_mobsf(apk)]
    results = [o.as_result() for o in outcomes]
    strings: list[str] = []
    for o in outcomes:
        strings.extend(o.strings)
    data: dict[str, Any] = {}
    for o in outcomes:
        entry = dict(o.data)
        if o.findings:
            entry["findings"] = o.findings
        if entry:
            data[o.name] = entry
    return results, strings, data
