"""Orchestrate parse -> tools -> toolchain/lab -> SAST -> SCA -> advanced -> DAST -> medical -> report."""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Callable

from .. import config, storage
from ..config import ENABLE_SAST, ENABLE_SCA
from ..models import (
    Component,
    DastCheck,
    Finding,
    ManifestSummary,
    ScaFinding,
    ToolResult,
)
from .apk import ApkPackage, find_all
from .advanced import AdvancedResult, analyze_advanced, build_compliance
from .bluetooth import analyze_bluetooth
from .custom import load_custom_rules, run_custom_rules
from .dast import DastResult, run_dast
from .exports import save_exports
from .live import run_live_checks
from .medical import analyze_medical
from .pki import analyze_pki
from .policy import evaluate_policy
from .reporting import generate_html_report
from .rules import finding
from .sast import SastContext, run_sast
from .sca import run_sca
from .tools import run_all_tools
from .toolchain import run_toolchain

log = logging.getLogger("apkpt.pipeline")


def _save(record: Any, stage: str, progress: int) -> None:
    record.stage = stage
    record.progress = progress
    storage.save_record(record)


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Suppress exact duplicates only, preserving distinct matches/occurrences."""
    seen: set[tuple[str, ...]] = set()
    out = []
    for f in findings:
        key = (
            str(f.get("id")),
            str(f.get("title")),
            str(f.get("severity")),
            str(f.get("description")),
            str(f.get("evidence")),
            str(f.get("location")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _safe(label: str, fn: Callable[[], Any], default: Any, all_findings: list[dict[str, Any]]) -> Any:
    """Run one engine without allowing it to abort the whole scan."""
    try:
        return fn()
    except Exception as exc:
        log.exception("engine %s failed", label)
        all_findings.append(finding(
            f"ENGINE-ERROR-{label.upper().replace(' ', '-')}",
            f"{label} engine failed",
            "info",
            category="TOOL",
            description=f"The {label} engine raised an exception; other engines continued.",
            evidence=f"{type(exc).__name__}: {exc}",
            remediation="Report this as a tool issue and check the server logs.",
            confidence="high",
        ))
        return default


def run_scan(scan_id: str) -> None:
    record = storage.load_record(scan_id)
    if record is None:
        log.error("scan %s not found", scan_id)
        return
    paths = storage.paths(scan_id)
    apk: ApkPackage | None = None
    all_findings: list[dict[str, Any]] = []
    try:
        record.status = "running"
        record.error = None
        _save(record, "parsing apk", 5)

        apk = ApkPackage(paths["apk"])
        record.sha256 = apk.sha256
        record.size_bytes = apk.size_bytes
        summary = apk.manifest_summary()
        record.manifest = ManifestSummary.model_validate(
            {k: v for k, v in summary.items() if k in ManifestSummary.model_fields}
        )
        record.certificate = apk.certificate
        record.apk_files = apk.names[:1000]
        _save(record, "enriching with external tools", 18)

        tool_results, tool_strings, tool_data = _safe(
            "external tools", lambda: run_all_tools(paths["apk"], paths["work"]),
            ([], [], {}), all_findings,
        )
        record.tools = [ToolResult.model_validate(t) for t in tool_results]
        for tool_name, entry in tool_data.items():
            for f in entry.get("findings", []):
                all_findings.append(f)

        network_config = apk.network_security_config()
        toolchain = _safe(
            "advanced toolchain",
            lambda: run_toolchain(paths["apk"], paths["work"], summary, network_config),
            None, all_findings,
        )
        if toolchain is not None:
            record.toolchain = toolchain.tools
            record.emulator = toolchain.lab
            record.patching = toolchain.patching
            for f in toolchain.findings:
                all_findings.append(f)
            tool_strings.extend(toolchain.strings[:5000])
        else:
            record.toolchain = [{
                "name": "advanced toolchain", "category": "lab", "available": False,
                "enabled": False, "ran": False, "detail": "engine error; see server logs",
                "findings_count": 0, "command": "", "invasive": False,
            }]
        _save(record, "static analysis", 35)

        if ENABLE_SAST:
            app_node = next(iter(find_all(apk.manifest, "application")), None)
            ctx = SastContext(
                apk=apk,
                manifest=apk.manifest,
                summary=summary,
                network_config=network_config,
                app_node=app_node,
                extra_strings=tool_strings,
            )
            all_findings.extend(_safe("SAST", lambda: run_sast(ctx), [], all_findings))
        _save(record, "composition analysis", 50)

        if ENABLE_SCA:
            sca = _safe(
                "SCA",
                lambda: run_sca(apk.all_strings + tool_strings, apk.names, logger=lambda msg, *a: log.info(msg, *a)),
                ([], [], {}), all_findings,
            )
            components, sca_findings, sca_meta = sca
            record.components = [Component.model_validate(c) for c in components]
            record.sca_findings = [ScaFinding.model_validate(f) for f in sca_findings]
            record.sca_meta = sca_meta
        _save(record, "custom rules", 58)

        if config.ENABLE_ADVANCED:
            custom_rules = _safe("custom rules", load_custom_rules, [], all_findings)
            custom_findings = _safe(
                "custom rule evaluation",
                lambda: run_custom_rules(custom_rules, strings=apk.all_strings + tool_strings, summary=summary, apk_names=apk.names),
                [], all_findings,
            )
            all_findings.extend(custom_findings)
            record.custom_rules_applied = [r["id"] for r in custom_rules]
        _save(record, "live checks", 65)

        live = _safe(
            "live checks",
            lambda: run_live_checks(apk.all_strings + tool_strings, apk.sha256),
            ([{
                "name": "live_checks", "status": "skipped",
                "detail": "Live-check engine unavailable; see server logs.", "evidence": "",
            }], []), all_findings,
        )
        live_checks, live_findings = live
        record.live_checks = live_checks
        all_findings.extend(live_findings)
        _save(record, "PKI analysis", 70)

        pki = _safe(
            "PKI",
            lambda: analyze_pki(apk.certificate, network_config),
            {
                "status": "error", "summary": {}, "signers": [], "trust": {},
                "lab": {}, "findings": [],
            },
            all_findings,
        )
        record.pki = {k: v for k, v in pki.items() if k != "findings"}
        all_findings.extend(pki.get("findings", []))
        _save(record, "Bluetooth analysis", 71)

        bluetooth = _safe(
            "Bluetooth",
            lambda: analyze_bluetooth(summary, apk.all_strings + tool_strings),
            {"status": "error", "summary": {}, "lab": {}, "findings": []},
            all_findings,
        )
        record.bluetooth = {k: v for k, v in bluetooth.items() if k != "findings"}
        all_findings.extend(bluetooth.get("findings", []))
        _save(record, "advanced analysis", 72)

        if config.ENABLE_ADVANCED:
            advanced = _safe(
                "advanced analysis",
                lambda: analyze_advanced(
                    apk, summary, apk.all_strings + tool_strings, record.certificate,
                    live_findings=live_findings, all_findings=all_findings,
                ),
                AdvancedResult(), all_findings,
            )
            all_findings.extend(advanced.findings)
            advanced_payload = asdict(advanced)
            advanced_payload.pop("findings", None)
            record.advanced = advanced_payload
            record.attack_chains = advanced.attack_chains
            record.playbook = advanced.playbook
        else:
            record.advanced = {"status": "disabled"}
        _save(record, "dynamic analysis", 82)

        dast = _safe(
            "DAST",
            lambda: run_dast(paths["apk"], summary, paths["work"], network_config=network_config),
            DastResult(status="error"), all_findings,
        )
        record.dast_status = dast.status
        record.dast_checks = [DastCheck.model_validate(c) for c in dast.checks]
        record.dast_info = {k: v for k, v in dast.info.items() if k not in ("logcat_excerpt", "dumpsys_excerpt")}
        record.dast_info["logcat_excerpt"] = dast.info.get("logcat_excerpt", "")[:6000]
        all_findings.extend(dast.findings)
        _save(record, "medical analysis", 88)

        medical = _safe(
            "medical analysis",
            lambda: analyze_medical(
                summary=summary,
                strings=apk.all_strings + tool_strings,
                findings=all_findings,
                network_config=network_config,
            ),
            {"status": "error", "detail": "medical engine unavailable", "findings": []},
            all_findings,
        )
        record.medical = {k: v for k, v in medical.items() if k != "findings"}
        all_findings.extend(medical.get("findings", []))

        record.compliance = build_compliance(all_findings)
        medical_controls = record.medical.get("standards", {}) if isinstance(record.medical, dict) else {}
        if medical_controls:
            record.compliance["medical"] = {
                "status": record.medical.get("status"),
                "risk_level": record.medical.get("risk_level"),
                "frameworks": medical_controls.get("frameworks", []),
                "gap_count": medical_controls.get("gap_count", 0),
                "review_count": medical_controls.get("review_count", 0),
                "disclaimer": record.medical.get("disclaimer"),
            }
        if isinstance(record.advanced, dict) and record.advanced:
            record.advanced["compliance"] = record.compliance
        _save(record, "generating report", 92)

        record.findings = [Finding.model_validate(f) for f in _dedupe(all_findings)]
        record.compute_summary()
        record.policy = evaluate_policy(record)
        record.exports = _safe(
            "exports", lambda: save_exports(scan_id, record, paths["dir"]),
            {}, all_findings,
        )
        paths["html"].write_text(generate_html_report(record), encoding="utf-8")
        record.status = "completed"
        record.progress = 100
        storage.save_record(record)
        log.info("scan %s completed with %d findings", scan_id, record.summary.total)
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        record.status = "failed"
        record.error = f"{type(exc).__name__}: {exc}"
        record.stage = "failed"
        storage.save_record(record)
    finally:
        if apk is not None:
            try:
                apk.close()
            except Exception:
                pass
