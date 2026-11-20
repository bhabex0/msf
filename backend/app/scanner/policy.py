"""Configurable release-gate policy evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import config
from ..models import ScanRecord


def evaluate_policy(record: ScanRecord, thresholds: dict[str, int] | None = None) -> dict[str, Any]:
    limits = dict(config.POLICY_THRESHOLDS)
    if thresholds:
        limits.update({k: int(v) for k, v in thresholds.items() if k in limits})

    # PKI and Bluetooth evidence is informational context only. It is never
    # counted as a threat/malware signal and can never fail a release gate,
    # regardless of the severity stored on an individual passive finding.
    passive_categories = {"PKI", "BLUETOOTH"}
    all_findings = list(record.findings) + list(record.sca_findings)
    gate_findings = [
        f for f in all_findings
        if getattr(f, "category", "") not in passive_categories
    ]
    excluded_by_category = {
        category: sum(
            1 for f in all_findings if getattr(f, "category", "") == category
        )
        for category in passive_categories
    }
    pki_findings_excluded = excluded_by_category["PKI"]
    bluetooth_findings_excluded = excluded_by_category["BLUETOOTH"]
    counted = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for item in gate_findings:
        sev = getattr(item, "severity", "info")
        if sev in counted:
            counted[sev] += 1
    actual = {sev: counted[sev] for sev in ("critical", "high", "medium", "low")}
    violations = [
        {
            "severity": sev,
            "allowed": limit,
            "found": actual[sev],
            "message": f"{actual[sev]} {sev} finding(s) exceed the allowed maximum of {limit}.",
        }
        for sev, limit in limits.items()
        if actual[sev] > limit
    ]

    medical = record.medical if isinstance(record.medical, dict) else {}
    medical_gaps = len(medical.get("gaps") or []) if medical.get("phi_present") else 0
    medical_gate = {
        "enabled": config.POLICY_MEDICAL_GAPS >= 0,
        "allowed_gaps": config.POLICY_MEDICAL_GAPS,
        "found_gaps": medical_gaps,
        "phi_present": bool(medical.get("phi_present")),
    }
    if medical_gate["enabled"] and config.POLICY_MEDICAL_GAPS >= 0:
        if medical_gaps > config.POLICY_MEDICAL_GAPS:
            violations.append({
                "severity": "medical",
                "allowed": config.POLICY_MEDICAL_GAPS,
                "found": medical_gaps,
                "message": (
                    f"{medical_gaps} unresolved medical control gap(s) exceed the allowed maximum of "
                    f"{config.POLICY_MEDICAL_GAPS}. Evidence mapping is not certification."
                ),
            })

    return {
        "status": "fail" if violations else "pass",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": limits,
        "actual": actual,
        "pki_findings_excluded": pki_findings_excluded,
        "bluetooth_findings_excluded": bluetooth_findings_excluded,
        "passive_findings_excluded": sum(excluded_by_category.values()),
        "violations": violations,
        "risk_score": record.summary.risk_score,
        "medical_gate": medical_gate,
    }
