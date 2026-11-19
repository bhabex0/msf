"""Machine-readable exports and scan-to-scan diffing."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from ..models import ScanRecord
from .rules import SEVERITY_RANK

CVSS_SEVERITY = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "low": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": None,
}


def cyclonedx_sbom(record: ScanRecord) -> dict[str, Any]:
    data = record.model_dump()
    components = []
    for c in data.get("components", []):
        component: dict[str, Any] = {
            "type": "library",
            "name": c.get("name", "unknown"),
            "bom-ref": f"pkg:generic/{c.get('name', 'unknown')}@{c.get('version') or 'unknown'}",
            "description": c.get("source") or "",
            "evidence": {"identity": c.get("evidence") or ""},
        }
        if c.get("version"):
            component["version"] = c["version"]
        components.append(component)
    vulnerabilities = []
    for f in data.get("sca_findings", []):
        vuln: dict[str, Any] = {
            "bom-ref": f"vuln:{f.get('id', uuid.uuid4().hex)}",
            "id": f.get("vulnerability_id") or f.get("id"),
            "description": f.get("description") or f.get("title", ""),
            "recommendation": f.get("remediation") or "",
            "affects": [{"ref": f"pkg:generic/{f.get('component')}@{f.get('version') or 'unknown'}"}],
        }
        ratings = []
        cvss = CVSS_SEVERITY.get(f.get("severity"))
        ratings.append({
            "severity": f.get("severity", "unknown"),
            "method": "CVSSv3" if cvss else "other",
            **({"vector": cvss} if cvss else {}),
        })
        vuln["ratings"] = ratings
        if f.get("references"):
            vuln["references"] = [{"url": r} for r in f["references"]]
        vulnerabilities.append(vuln)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": data.get("uploaded_at"),
            "tools": [{"vendor": "apk-pentest-platform", "name": "APK Pentest Platform", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": data.get("manifest", {}).get("package") or data.get("filename"),
                "version": str(data.get("manifest", {}).get("version_name") or "unknown"),
                "bom-ref": f"app:{data.get('sha256') or data.get('scan_id')}",
            },
            "properties": [
                {"name": "apkpt:medical:status", "value": str(data.get("medical", {}).get("status") or "disabled")},
                {"name": "apkpt:medical:phi_present", "value": str(bool(data.get("medical", {}).get("phi_present"))).lower()},
                {"name": "apkpt:medical:risk_level", "value": str(data.get("medical", {}).get("risk_level") or "informational")},
                {"name": "apkpt:toolchain:tools", "value": ", ".join(
                    str(t.get("name")) for t in data.get("toolchain", []) if t.get("available")
                )},
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def sarif_report(record: ScanRecord) -> dict[str, Any]:
    data = record.model_dump()
    findings = list(data.get("findings", [])) + list(data.get("sca_findings", []))
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for f in findings:
        rid = str(f.get("id") or "UNKNOWN")
        if rid in rule_index:
            continue
        rule_index[rid] = len(rules)
        rules.append({
            "id": rid,
            "name": f.get("title", rid),
            "shortDescription": {"text": f.get("title", rid)[:200]},
            "fullDescription": {"text": f.get("description") or f.get("title", "")},
            "help": {"text": f.get("remediation") or "Review and remediate the finding."},
            "properties": {"category": f.get("category"), "tags": [f.get("owasp_masvs"), f.get("cwe")]},
        })
    results = []
    for f in findings:
        rid = str(f.get("id") or "UNKNOWN")
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
            str(f.get("severity")), "note"
        )
        result: dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": level,
            "message": {"text": f.get("description") or f.get("title") or ""},
            "properties": {
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "category": f.get("category"),
                "cwe": f.get("cwe"),
                "owasp_masvs": f.get("owasp_masvs"),
                "component": f.get("component"),
                "version": f.get("version"),
            },
        }
        if f.get("location") or f.get("evidence"):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("location") or "APK")},
                    "region": {"startLine": 1, "snippet": {"text": (f.get("evidence") or "")[:1000]}},
                }
            }]
        if f.get("references"):
            result["relatedLocations"] = [
                {"id": i + 1, "physicalLocation": {"artifactLocation": {"uri": r}}} for i, r in enumerate(f["references"][:5])
            ]
        results.append(result)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "APK Pentest Platform",
                    "version": "1.0",
                    "informationUri": "https://github.com/",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "scan_id": record.scan_id,
                "sha256": record.sha256,
                "risk_score": record.summary.risk_score,
                "medical": {
                    "status": data.get("medical", {}).get("status"),
                    "phi_present": data.get("medical", {}).get("phi_present", False),
                    "risk_level": data.get("medical", {}).get("risk_level"),
                    "gaps": len(data.get("medical", {}).get("gaps") or []),
                },
                "toolchain": [
                    {"name": t.get("name"), "ran": t.get("ran"), "available": t.get("available")}
                    for t in data.get("toolchain", [])
                ],
            },
        }],
    }


def save_exports(scan_id: str, record: ScanRecord, directory: Path) -> dict[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    sbom = directory / "sbom.cdx.json"
    sarif = directory / "report.sarif"
    sbom.write_text(json.dumps(cyclonedx_sbom(record), indent=2), encoding="utf-8")
    sarif.write_text(json.dumps(sarif_report(record), indent=2), encoding="utf-8")
    return {
        "sbom": str(sbom),
        "sarif": str(sarif),
        "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
        "sarif_sha256": hashlib.sha256(sarif.read_bytes()).hexdigest(),
    }


def _finding_key(f: dict[str, Any]) -> tuple[str, str]:
    return (str(f.get("id") or ""), str(f.get("title") or ""))


def diff_scans(current: ScanRecord, previous: ScanRecord) -> dict[str, Any]:
    cur = [f.model_dump() for f in current.findings] + [f.model_dump() for f in current.sca_findings]
    old = [f.model_dump() for f in previous.findings] + [f.model_dump() for f in previous.sca_findings]
    cur_map = {_finding_key(f): f for f in cur}
    old_map = {_finding_key(f): f for f in old}
    new_keys = set(cur_map) - set(old_map)
    resolved_keys = set(old_map) - set(cur_map)
    changed = []
    for key in set(cur_map) & set(old_map):
        a, b = old_map[key], cur_map[key]
        fields = [name for name in ("severity", "description", "evidence", "remediation") if a.get(name) != b.get(name)]
        if fields:
            changed.append({
                "id": key[0], "title": key[1], "fields": fields,
                "previous": {n: a.get(n) for n in fields},
                "current": {n: b.get(n) for n in fields},
            })
    rank = lambda f: SEVERITY_RANK.get(str(f.get("severity")), 9)
    new_findings = sorted((cur_map[k] for k in new_keys), key=rank)
    resolved_findings = sorted((old_map[k] for k in resolved_keys), key=rank)
    changed.sort(key=lambda c: SEVERITY_RANK.get(str(cur_map[(c["id"], c["title"])].get("severity")), 9))
    return {
        "current_scan_id": current.scan_id,
        "previous_scan_id": previous.scan_id,
        "current_sha256": current.sha256,
        "previous_sha256": previous.sha256,
        "package_changed": current.manifest.package != previous.manifest.package,
        "new": new_findings,
        "resolved": resolved_findings,
        "changed": changed,
        "counts": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "changed": len(changed),
            "unchanged": len(set(cur_map) & set(old_map)) - len(changed),
        },
    }
