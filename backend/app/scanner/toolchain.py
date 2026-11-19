"""Optional advanced toolchain orchestration.

Built-in engines always work. The tools in this module are hooks: each one
reports availability, configuration, execution status and skip reasons instead
of failing a scan. Network or device-modifying tools require explicit opt-in.

For authorized security testing only.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .. import config
from .lab import AUTHORIZATION_NOTICE, build_lab_plan, emulator_status, split_command
from .rules import excerpt, finding

URL_RE = re.compile(r"https?://[^\s\"'<>]{6,}", re.I)
SECRET_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([^'\"\s,;]{6,})",
    re.I,
)
SEVERITY_ALIASES = {
    "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "warning": "medium", "low": "low", "info": "info", "informational": "info",
    "good": "info", "secure": "info", "pass": "info",
}


@dataclass
class ToolOutcome:
    name: str
    category: str
    available: bool
    enabled: bool
    detail: str = ""
    ran: bool = False
    command: str = ""
    invasive: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def as_result(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "available": self.available,
            "enabled": self.enabled,
            "ran": self.ran,
            "detail": self.detail,
            "findings_count": len(self.findings),
            "command": self.command,
            "invasive": self.invasive,
        }


@dataclass
class ToolchainResult:
    tools: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    lab: dict[str, Any] = field(default_factory=dict)
    patching: dict[str, Any] = field(default_factory=dict)


def _command_available(command: str) -> bool:
    parts = split_command(command)
    if not parts:
        return False
    if shutil.which(parts[0]) or Path(parts[0]).exists():
        return True
    for token in parts[1:]:
        if Path(token).suffix.lower() in (".py", ".jar", ".sh") and Path(token).exists():
            return True
    return False


def _render(template: str, **values: Any) -> str:
    out = str(template or "")
    for key, value in values.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def _run(cmd: list[str], timeout: int, cwd: Path | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except FileNotFoundError:
        return 127, "executable not found"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except Exception as exc:
        return 1, str(exc)


def _slug(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", str(value).upper()).strip("-")[:48] or "FINDING"


def _normalise_severity(value: Any, default: str = "info") -> str:
    sev = SEVERITY_ALIASES.get(str(value or "").strip().lower(), "")
    return sev or default


def _limited(items: list[Any], limit: int | None = None) -> list[Any]:
    """Return every item when the cap is 0 (unlimited); otherwise cap it."""
    cap = config.TOOL_FINDING_LIMIT if limit is None else max(0, int(limit))
    return list(items) if cap == 0 else list(items)[:cap]


def _findings_from_payload(
    payload: Any, tool: str, limit: int | None = None,
) -> list[dict[str, Any]]:
    """Convert common JSON finding shapes into platform findings.

    The default cap comes from ``APKPT_TOOL_FINDING_LIMIT``. ``0`` means every
    finding is imported. Only exact duplicates are suppressed; distinct findings
    that share a title are preserved with a unique ID suffix.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def visit(node: Any, depth: int = 0) -> None:
        # Depth guard is structural safety for untrusted JSON, not a finding cap.
        if depth > 8:
            return
        if isinstance(node, list):
            for item in node:
                visit(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        title = (
            node.get("title") or node.get("finding") or node.get("name")
            or node.get("issue") or node.get("rule") or node.get("id")
        )
        severity_node = node.get("severity") or node.get("risk") or node.get("level")
        if title and severity_node is not None:
            severity = _normalise_severity(severity_node, "medium")
            evidence = str(
                node.get("evidence") or node.get("match") or node.get("location") or "",
            )
            key = (str(title), severity, evidence[:200], str(node.get("id") or ""))
            if key not in seen:
                seen.add(key)
                slug = _slug(str(title))
                suffix = hashlib.sha1("|".join(key).encode("utf-8")).hexdigest()[:6]
                out.append(finding(
                    f"TOOL-{_slug(tool)}-{slug}-{suffix}",
                    f"{tool}: {title}",
                    severity,  # type: ignore[arg-type]
                    category="TOOL",
                    description=str(
                        node.get("description") or node.get("info") or node.get("message") or "",
                    )[:1000],
                    evidence=evidence[:800],
                    remediation=str(
                        node.get("remediation") or node.get("recommendation")
                        or "Review the tool evidence.",
                    ),
                    cwe=node.get("cwe"),
                    masvs=node.get("masvs"),
                    confidence="medium",
                ))
        for value in node.values():
            visit(value, depth + 1)

    visit(payload)
    return _limited(out, limit)


def _findings_from_text(
    text: str, tool: str, limit: int | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    urls = _limited(list(dict.fromkeys(URL_RE.findall(text))), limit)
    if urls:
        out.append(finding(
            f"TOOL-{_slug(tool)}-ENDPOINTS",
            f"{tool}: extracted network endpoints",
            "medium",
            category="TOOL",
            description=f"{tool} extracted {len(urls)} endpoint(s) from the APK. Confirm each endpoint is intended and uses TLS.",
            evidence=excerpt(urls),
            remediation="Review all endpoints, remove debug hosts and enforce TLS 1.2+ with certificate validation.",
            confidence="low",
        ))
    secrets = _limited(list(dict.fromkeys(SECRET_RE.findall(text))), limit)
    if secrets:
        out.append(finding(
            f"TOOL-{_slug(tool)}-SECRETS",
            f"{tool}: credential-like strings in APK",
            "high",
            category="TOOL",
            description=f"{tool} found {len(secrets)} credential-like value(s). Values are masked in this report.",
            evidence=excerpt([s[:2] + "***" for s in secrets]),
            remediation="Move secrets to a backend service or secure device storage and rotate any exposed credential.",
            cwe="CWE-798",
            confidence="low",
        ))
    return out


def probe_toolchain() -> list[dict[str, Any]]:
    """Report every integrated tool without running anything."""
    tools = [
        {
            "name": "APKHunt", "category": "static",
            "available": bool(config.APKHUNT_URL) or _command_available(config.APKHUNT_CMD),
            "enabled": config.TOOL_APKHUNT, "invasive": False,
            "detail": "Local web workbench HTTP hook or legacy CLI",
        },
        {
            "name": "APKLeaks", "category": "static",
            "available": _command_available(config.APKLEAKS_CMD),
            "enabled": config.TOOL_APKLEAKS, "invasive": False,
            "detail": "URIs, endpoints and secrets",
        },
        {
            "name": "HCL AppScan", "category": "static/cloud",
            "available": _command_available(config.APPSCAN_CMD) and bool(config.APPSCAN_SERVER and config.APPSCAN_API_KEY),
            "enabled": config.TOOL_APPSCAN, "invasive": False,
            "detail": "Requires APKPT_APPSCAN_SERVER, APKPT_APPSCAN_API_KEY and a non-interactive command template",
        },
        {
            "name": "MobSF Dynamic", "category": "dynamic",
            "available": bool(config.MOBSF_DYNAMIC_URL),
            "enabled": config.TOOLCHAIN_AUTO, "invasive": False,
            "detail": "Set APKPT_MOBSF_DYNAMIC_URL and APKPT_TOOLCHAIN_AUTO=1",
        },
        {
            "name": "TrashDroid", "category": "dynamic",
            "available": _command_available(config.TRASHDROID_CMD),
            "enabled": config.TOOL_TRASHDROID, "invasive": True,
            "detail": "9-phase adb/drozer DAST; requires rooted authorized device and explicit opt-ins",
        },
        {
            "name": "Runtime Mobile Security (RMS)", "category": "runtime",
            "available": _command_available(config.RMS_CMD),
            "enabled": config.TOOL_RMS, "invasive": True,
            "detail": "Interactive Frida web UI; plan and launch instructions only",
        },
        {
            "name": "Burp Suite", "category": "proxy",
            "available": _command_available(config.BURP_CMD),
            "enabled": config.TOOL_BURP, "invasive": False,
            "detail": "Interception proxy listener; configure CA and device proxy",
        },
        {
            "name": "OWASP ZAP", "category": "proxy",
            "available": _command_available(config.ZAP_CMD),
            "enabled": config.TOOL_ZAP, "invasive": False,
            "detail": "Daemon mode listener; configure CA and device proxy",
        },
        {
            "name": "mitmproxy", "category": "proxy",
            "available": _command_available(config.MITMPROXY_CMD),
            "enabled": config.TOOL_MITMPROXY, "invasive": False,
            "detail": "mitmdump with generated APKPT addon",
        },
        {
            "name": "patch-apk.py", "category": "patch",
            "available": _command_available(config.PATCHAPK_CMD),
            "enabled": True, "invasive": True,
            "detail": "Injection + user-CA support for split APKs",
        },
        {
            "name": "objection", "category": "patch",
            "available": _command_available(config.OBJECTION_CMD),
            "enabled": True, "invasive": True,
            "detail": "Frida gadget injection and runtime exploration",
        },
        {
            "name": "APatch", "category": "root",
            "available": _command_available(config.APATCH_CMD),
            "enabled": config.ALLOW_INVASIVE, "invasive": True,
            "detail": "Kernel root/system modification; manual, approval-gated",
        },
        {
            "name": "ReC Manager", "category": "reverse",
            "available": _command_available(config.RECMANAGER_CMD),
            "enabled": config.TOOL_RECMANAGER and config.ALLOW_INVASIVE, "invasive": True,
            "detail": "Deployment-specific command contract; manual if unset",
        },
        {
            "name": "Manual smali patching", "category": "reverse",
            "available": _command_available(config.APKTOOL_CMD) and (
                _command_available(config.JARSIGNER_CMD) or _command_available(config.APKSIGNER_CMD)
            ),
            "enabled": config.ALLOW_INVASIVE, "invasive": True,
            "detail": "apktool + jarsigner/apksigner; human review required",
        },
        {
            "name": "Chromium / MobSF browser", "category": "browser",
            "available": bool(config.CHROMIUM_CMD) or True,
            "enabled": config.BROWSER_OPEN_ENABLED, "invasive": False,
            "detail": "System browser fallback; server-side launch is opt-in",
        },
        {
            "name": "ADB / emulator", "category": "lab",
            "available": _command_available(config.ADB_CMD),
            "enabled": config.EMULATOR_AUTO, "invasive": False,
            "detail": "Device/emulator status is read-only unless APKPT_EMULATOR_AUTO=1",
        },
    ]
    for tool in tools:
        tool["authorization"] = AUTHORIZATION_NOTICE
    return tools


def _http_findings(client: httpx.Client, url: str, upload_name: str, apk: Path, headers: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    with open(apk, "rb") as fh:
        up = client.post(
            url,
            files={"file": (upload_name, fh, "application/vnd.android.package-archive")},
        )
    up.raise_for_status()
    payload = up.json() if "json" in up.headers.get("content-type", "") else {}
    scan_id = payload.get("scan_id") or payload.get("id") or payload.get("hash")
    return [], {"upload_response": str(payload)[:2000], "scan_id": scan_id}, str(scan_id or "")


def run_apkhunt(apk: Path, work: Path) -> ToolOutcome:
    base = config.APKHUNT_URL.rstrip("/")
    cmd = config.APKHUNT_CMD
    outcome = ToolOutcome(
        "APKHunt", "static", bool(base) or _command_available(cmd),
        config.TOOL_APKHUNT and config.TOOLCHAIN_AUTO,
    )
    if not outcome.enabled:
        outcome.detail = "set APKPT_TOOLCHAIN_AUTO=1 to run third-party tool hooks"
        return outcome
    if base:
        headers = {"Authorization": config.APKHUNT_API_KEY} if config.APKHUNT_API_KEY else {}
        try:
            with httpx.Client(timeout=30, headers=headers, follow_redirects=False) as client:
                upload_url = base + config.APKHUNT_UPLOAD_PATH
                _, meta, scan_id = _http_findings(client, upload_url, apk.name, apk, headers)
                if not scan_id:
                    outcome.detail = "APKHunt upload did not return scan_id/hash"
                    outcome.data = meta
                    return outcome
                report_path = _render(config.APKHUNT_REPORT_PATH, scan_id=scan_id)
                rr = client.get(base + report_path)
                rr.raise_for_status()
                payload = rr.json()
                outcome.findings = _findings_from_payload(payload, "APKHunt")
                outcome.strings = [json.dumps(payload)[:50_000]]
                outcome.data = {**meta, "report": str(payload)[:4000]}
                outcome.detail = f"APKHunt report received ({len(outcome.findings)} findings)"
                outcome.ran = True
        except Exception as exc:
            outcome.detail = f"APKHunt HTTP hook error: {type(exc).__name__}: {exc}"[:500]
        return outcome
    if not _command_available(cmd):
        outcome.detail = "APKHunt URL/command not configured (APKPT_APKHUNT_URL or APKPT_APKHUNT_CMD)"
        return outcome
    output = work / "apkhunt.json"
    command = _render(cmd + " -p {apk} -o {output}", apk=str(apk), output=str(output), work=str(work))
    code, log = _run(split_command(command), timeout=config.TOOLCHAIN_TIMEOUT, cwd=work)
    if code != 0:
        outcome.detail = f"APKHunt CLI failed (exit {code}): {log[-400:]}"
        return outcome
    try:
        payload = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        outcome.findings = _findings_from_payload(payload, "APKHunt")
    except Exception:
        outcome.findings = _findings_from_text(log, "APKHunt")
    outcome.strings = [log[:50_000]]
    outcome.data = {"output": str(output)}
    outcome.command = command
    outcome.detail = f"APKHunt CLI completed ({len(outcome.findings)} findings)"
    outcome.ran = True
    return outcome


def run_apkleaks(apk: Path, work: Path) -> ToolOutcome:
    cmd = config.APKLEAKS_CMD
    outcome = ToolOutcome("APKLeaks", "static", _command_available(cmd), config.TOOL_APKLEAKS)
    if not outcome.enabled or not outcome.available:
        outcome.detail = "not installed or disabled"
        return outcome
    output = work / "apkleaks.json"
    command = _render(cmd + " -f {apk} -o {output} --json", apk=str(apk), output=str(output), work=str(work))
    code, log = _run(split_command(command), timeout=config.TOOLCHAIN_TIMEOUT, cwd=work)
    if code != 0:
        outcome.detail = f"APKLeaks failed (exit {code}): {log[-400:]}"
        return outcome
    text = log
    if output.exists():
        text += "\n" + output.read_text(encoding="utf-8", errors="replace")[:100_000]
    try:
        payload = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        outcome.findings = _findings_from_payload(payload, "APKLeaks") or _findings_from_text(text, "APKLeaks")
    except Exception:
        outcome.findings = _findings_from_text(text, "APKLeaks")
    outcome.strings = [line for line in text.splitlines() if URL_RE.search(line) or SECRET_RE.search(line)][:2000]
    outcome.data = {"output": str(output) if output.exists() else ""}
    outcome.command = command
    outcome.detail = f"APKLeaks completed ({len(outcome.findings)} findings)"
    outcome.ran = True
    return outcome


def run_appscan(apk: Path, work: Path) -> ToolOutcome:
    cmd = config.APPSCAN_CMD
    outcome = ToolOutcome(
        "HCL AppScan", "static/cloud",
        _command_available(cmd) and bool(config.APPSCAN_SERVER and config.APPSCAN_API_KEY),
        config.TOOL_APPSCAN and config.TOOLCHAIN_AUTO,
    )
    if not outcome.enabled:
        outcome.detail = "set APKPT_TOOLCHAIN_AUTO=1 to upload to AppScan"
        return outcome
    if not config.APPSCAN_SERVER or not config.APPSCAN_API_KEY:
        outcome.detail = "set APKPT_APPSCAN_SERVER and APKPT_APPSCAN_API_KEY (upload is explicit)"
        return outcome
    if not _command_available(cmd):
        outcome.detail = "AppScan CLI not found"
        return outcome
    if not any(token in cmd for token in ("{apk}", "{server}", "{key}", "{output}")):
        outcome.detail = "APKPT_APPSCAN_CMD must be a non-interactive template using {apk}/{server}/{key}/{output}"
        return outcome
    output = work / "appscan.json"
    command = _render(
        cmd, apk=str(apk), server=config.APPSCAN_SERVER, key=config.APPSCAN_API_KEY,
        output=str(output), work=str(work),
    )
    outcome.command = command.replace(config.APPSCAN_API_KEY, "***")
    code, log = _run(split_command(command), timeout=config.TOOLCHAIN_TIMEOUT, cwd=work)
    if code != 0:
        outcome.detail = f"AppScan failed (exit {code}): {log[-400:]}"
        return outcome
    try:
        payload = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        outcome.findings = _findings_from_payload(payload, "HCL AppScan")
    except Exception:
        outcome.findings = _findings_from_text(log, "HCL AppScan")
    outcome.data = {"output": str(output) if output.exists() else ""}
    outcome.detail = f"AppScan completed ({len(outcome.findings)} findings)"
    outcome.ran = True
    return outcome


def run_trashdroid(apk: Path, work: Path, package: str | None) -> ToolOutcome:
    cmd = config.TRASHDROID_CMD
    outcome = ToolOutcome(
        "TrashDroid", "dynamic", _command_available(cmd),
        config.TOOL_TRASHDROID and config.TOOLCHAIN_AUTO and config.EMULATOR_AUTO and config.ALLOW_INVASIVE,
        invasive=True,
    )
    if not outcome.enabled:
        outcome.detail = "requires APKPT_TOOLCHAIN_AUTO=1, APKPT_EMULATOR_AUTO=1 and APKPT_ALLOW_INVASIVE=1"
        return outcome
    if not outcome.available:
        outcome.detail = "TrashDroid not installed"
        return outcome
    status = emulator_status()
    if not status["adb_available"] or not status["devices"]:
        outcome.detail = "no authorized adb device connected"
        return outcome
    if not package:
        outcome.detail = "package name unavailable"
        return outcome
    device = config.DAST_DEVICE_SERIAL or status["devices"][0]
    out = work / "trashdroid"
    out.mkdir(parents=True, exist_ok=True)
    command = _render(
        cmd + " --auto --device {device} --package {package} --apk {apk} --report client",
        device=device, package=package, apk=str(apk), work=str(out),
    )
    code, log = _run(split_command(command), timeout=max(config.TOOLCHAIN_TIMEOUT, 600), cwd=out)
    if code != 0:
        outcome.detail = f"TrashDroid failed (exit {code}): {log[-400:]}"
        return outcome
    reports = sorted(out.rglob("findings_*.json"))
    payload: Any = {}
    if reports:
        try:
            payload = json.loads(reports[-1].read_text(encoding="utf-8", errors="replace"))
        except Exception:
            payload = {}
    outcome.findings = _findings_from_payload(payload, "TrashDroid") or _findings_from_text(log, "TrashDroid")
    outcome.strings = [line for line in log.splitlines()][:2000]
    outcome.data = {"output_dir": str(out), "report": str(reports[-1]) if reports else ""}
    outcome.command = command
    outcome.detail = f"TrashDroid completed ({len(outcome.findings)} findings)"
    outcome.ran = True
    return outcome


def run_mobsf_dynamic(apk: Path, work: Path) -> ToolOutcome:
    url = config.MOBSF_DYNAMIC_URL.rstrip("/")
    outcome = ToolOutcome(
        "MobSF Dynamic", "dynamic", bool(url),
        config.TOOLCHAIN_AUTO and bool(url),
    )
    if not outcome.enabled:
        outcome.detail = "set APKPT_MOBSF_DYNAMIC_URL and APKPT_TOOLCHAIN_AUTO=1"
        return outcome
    headers = {"Authorization": config.MOBSF_API_KEY} if config.MOBSF_API_KEY else {}
    try:
        with httpx.Client(timeout=30, headers=headers, follow_redirects=False) as client:
            _, meta, scan_id = _http_findings(client, url + "/api/v1/upload", apk.name, apk, headers)
            if not scan_id:
                outcome.detail = "dynamic upload did not return scan_id/hash"
                outcome.data = meta
                return outcome
            started = client.post(
                url + "/api/v1/dynamic/scan",
                json={"scan_id": scan_id, "hash": scan_id},
            )
            if started.status_code >= 400:
                outcome.detail = f"dynamic scan endpoint returned {started.status_code}"
                outcome.data = meta
                return outcome
            deadline = time.time() + min(config.MOBSF_TIMEOUT, config.TOOLCHAIN_TIMEOUT)
            payload: dict[str, Any] | None = None
            while time.time() < deadline:
                try:
                    r = client.get(url + f"/api/v1/dynamic/report/{scan_id}")
                    if r.status_code == 200:
                        payload = r.json()
                        break
                except Exception:
                    pass
                time.sleep(4)
            if payload is None:
                outcome.detail = "dynamic report was not ready before timeout"
                outcome.data = meta
                return outcome
            outcome.findings = _findings_from_payload(payload, "MobSF Dynamic")
            outcome.strings = [json.dumps(payload)[:50_000]]
            outcome.data = {**meta, "report": str(payload)[:4000]}
            outcome.detail = f"MobSF dynamic report received ({len(outcome.findings)} findings)"
            outcome.ran = True
    except Exception as exc:
        outcome.detail = f"MobSF dynamic hook error: {type(exc).__name__}: {exc}"[:500]
    return outcome


def run_toolchain(
    apk: Path,
    work: Path,
    summary: dict[str, Any] | None = None,
    network_config: dict[str, Any] | None = None,
) -> ToolchainResult:
    """Run safe hooks, plan invasive hooks and return a single serialisable result."""
    work.mkdir(parents=True, exist_ok=True)
    summary = summary or {}
    outcomes = [
        run_apkhunt(apk, work),
        run_apkleaks(apk, work),
        run_appscan(apk, work),
        run_mobsf_dynamic(apk, work),
        run_trashdroid(apk, work, str(summary.get("package") or "") or None),
    ]
    result = ToolchainResult()
    for outcome in outcomes:
        result.tools.append(outcome.as_result())
        result.findings.extend(outcome.findings)
        result.strings.extend(outcome.strings[:2000])
        if outcome.data:
            result.data[outcome.name] = outcome.data

    # Status-only integrations are recorded so reports show full coverage.
    for tool in probe_toolchain():
        if tool["name"] in {o.name for o in outcomes}:
            continue
        result.tools.append({
            "name": tool["name"],
            "category": tool["category"],
            "available": tool["available"],
            "enabled": tool["enabled"],
            "ran": False,
            "detail": tool["detail"],
            "findings_count": 0,
            "command": "",
            "invasive": tool["invasive"],
        })

    result.lab = build_lab_plan(
        apk, work, str(summary.get("package") or "") or None, network_config=network_config,
    )
    result.patching = result.lab["patching"]
    return result
