"""Software Composition Analysis: component detection + vulnerability matching."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx

from ..config import DATA_DIR, SCA_ONLINE_LOOKUP, SCA_ONLINE_TIMEOUT, TOOL_FINDING_LIMIT
from .rules import excerpt, finding


def _version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", value))[:6]


def _version_lt(version: str | None, fixed_in: str | None) -> bool:
    if not version or not fixed_in:
        return False
    a, b = _version_tuple(version), _version_tuple(fixed_in)
    if not a or not b:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def load_vuln_db(path: Path | None = None) -> dict[str, Any]:
    target = path or DATA_DIR / "vuln_db.json"
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return {"components": []}


def _osv_query(name: str, ecosystem: str, version: str | None, timeout: float) -> list[dict[str, Any]]:
    if not version:
        return []
    query: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": "apk-pentest-platform/1.0"}) as client:
            response = client.post("https://api.osv.dev/v1/query", json=query)
            response.raise_for_status()
            vulns = response.json().get("vulns", [])
            if TOOL_FINDING_LIMIT > 0:
                vulns = vulns[:TOOL_FINDING_LIMIT]
    except Exception:
        return []
    out = []
    for v in vulns:
        severity = "medium"
        for sev in v.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score = str(sev.get("score", ""))
                m = re.search(r"/(CRITICAL|HIGH|MEDIUM|LOW)/", score)
                if m:
                    severity = m.group(1).lower()
                    break
        if not v.get("severity"):
            dbs = str(v.get("database_specific", {}).get("severity", "")).lower()
            if dbs in ("critical", "high", "medium", "low"):
                severity = dbs
        out.append(
            {
                "id": v.get("id", "OSV-UNKNOWN"),
                "severity": severity,
                "title": v.get("summary", "OSV advisory")[:180],
                "description": (v.get("details") or "")[:600],
                "remediation": "Upgrade the dependency to a fixed version listed in the advisory.",
                "references": [r.get("url") for r in v.get("references", [])[:3] if r.get("url")],
                "source": "OSV.dev",
            }
        )
    return out


def run_sca(
    strings: list[str],
    apk_names: list[str],
    *,
    online: bool | None = None,
    logger: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Return (components, findings, meta)."""
    use_online = SCA_ONLINE_LOOKUP if online is None else online
    db = load_vuln_db()
    joined = "\n".join(strings[:200_000])
    native_names = [n.rsplit("/", 1)[-1].lower() for n in apk_names if n.startswith("lib/") and n.endswith(".so")]
    components: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {
        "db_version": db.get("_version"),
        "offline_components": len(db.get("components", [])),
        "online_lookup": use_online,
        "online_results": 0,
    }

    for comp in db.get("components", []):
        matched = False
        evidence: list[str] = []
        for marker in comp.get("markers", []):
            if marker in joined:
                matched = True
                evidence.append(marker)
        for lib in comp.get("native_libraries", []):
            if lib.lower() in native_names:
                matched = True
                evidence.append(lib)
        if not matched:
            continue

        version = None
        for pattern in comp.get("version_patterns", []):
            m = re.search(pattern, joined, re.I)
            if m:
                version = m.group(1)
                evidence.append(m.group(0)[:80])
                break

        components.append(
            {
                "name": comp["name"],
                "version": version,
                "source": "offline-db",
                "evidence": excerpt(evidence, max_items=4),
            }
        )

        advisories: list[dict[str, Any]] = []
        for vuln in comp.get("vulnerabilities", []):
            if _version_lt(version, vuln.get("fixed_in")) or version is None:
                item = dict(vuln)
                item["source"] = "offline-db"
                advisories.append(item)

        if use_online and version:
            online_hits = _osv_query(
                comp.get("osv_name", comp["name"]),
                comp.get("ecosystem", "Maven"),
                version,
                SCA_ONLINE_TIMEOUT,
            )
            meta["online_results"] += len(online_hits)
            seen_ids = {a["id"] for a in advisories}
            for hit in online_hits:
                if hit["id"] not in seen_ids:
                    advisories.append(hit)

        reported_advisories = (
            advisories if TOOL_FINDING_LIMIT == 0 else advisories[:TOOL_FINDING_LIMIT]
        )
        for adv in reported_advisories:
            unknown_version = version is None
            item = finding(
                f"SCA-{adv['id'].replace(' ', '-').replace('/', '-')}",
                f"{comp['name']}: {adv['title']}",
                adv.get("severity", "medium"),
                category="SCA",
                description=adv.get("description", "")
                + (" Version could not be determined, so this is a potential match only." if unknown_version else ""),
                evidence=excerpt(evidence, max_items=4),
                remediation=adv.get("remediation", "Upgrade to the fixed version."),
                location=comp["name"],
                cwe=None,
                masvs="MASVS-CODE-1",
                confidence="low" if unknown_version else "high" if adv.get("source") == "OSV.dev" else "medium",
                references=adv.get("references", []),
            )
            item["component"] = comp["name"]
            item["version"] = version
            item["vulnerability_id"] = adv["id"]
            item["source"] = adv.get("source", "offline-db")
            findings.append(item)

    if logger:
        logger("SCA completed: %d components, %d findings", len(components), len(findings))
    return components, findings, meta
