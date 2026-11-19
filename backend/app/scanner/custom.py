"""Administrator-defined detection rules.

Rules are stored as JSON in DATA_DIR/custom_rules.json by default. Each rule
has an id, title, severity, scope (strings|manifest|permission|component|
package|filename) and a regular-expression pattern.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import CUSTOM_RULES_PATH
from .rules import excerpt, finding

ALLOWED_SCOPES = {"strings", "manifest", "permission", "component", "package", "filename"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    clean = {k: v for k, v in rule.items() if k in {
        "id", "title", "severity", "scope", "pattern", "description",
        "remediation", "cwe", "masvs", "category", "confidence", "references",
    }}
    for key in ("id", "title", "pattern"):
        if not clean.get(key) or not isinstance(clean[key], str):
            raise ValueError(f"rule field '{key}' is required and must be a string")
    clean["id"] = re.sub(r"[^A-Z0-9_-]+", "-", clean["id"].upper()).strip("-") or "CUSTOM-RULE"
    clean["scope"] = str(clean.get("scope", "strings")).lower()
    if clean["scope"] not in ALLOWED_SCOPES:
        raise ValueError(f"scope must be one of: {', '.join(sorted(ALLOWED_SCOPES))}")
    clean["severity"] = str(clean.get("severity", "medium")).lower()
    if clean["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}")
    clean["confidence"] = str(clean.get("confidence", "medium")).lower()
    if clean["confidence"] not in ("high", "medium", "low"):
        clean["confidence"] = "medium"
    clean["category"] = "CUSTOM"
    if not isinstance(clean.get("references", []), list):
        clean["references"] = []
    try:
        re.compile(clean["pattern"], re.I)
    except re.error as exc:
        raise ValueError(f"invalid regex pattern: {exc}") from exc
    return clean


def load_custom_rules(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or CUSTOM_RULES_PATH
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except Exception:
        return []
    rules = payload.get("rules", payload) if isinstance(payload, dict) else payload
    if not isinstance(rules, list):
        return []
    out: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        try:
            out.append(validate_rule(rule))
        except ValueError:
            continue
    return out


def save_custom_rules(rules: list[dict[str, Any]], path: Path | None = None) -> list[dict[str, Any]]:
    target = path or CUSTOM_RULES_PATH
    clean = [validate_rule(r) for r in rules]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"rules": clean}, indent=2), encoding="utf-8")
    return clean


def add_custom_rule(rule: dict[str, Any], path: Path | None = None) -> list[dict[str, Any]]:
    rules = load_custom_rules(path)
    clean = validate_rule(rule)
    rules = [r for r in rules if r["id"] != clean["id"]]
    rules.append(clean)
    return save_custom_rules(rules, path)


def delete_custom_rule(rule_id: str, path: Path | None = None) -> list[dict[str, Any]]:
    rules = [r for r in load_custom_rules(path) if r["id"] != rule_id.upper()]
    return save_custom_rules(rules, path)


def run_custom_rules(
    rules: list[dict[str, Any]],
    *,
    strings: list[str],
    summary: dict[str, Any],
    apk_names: list[str],
) -> list[dict[str, Any]]:
    if not rules:
        return []
    string_corpus = "\n".join(strings[:200_000])
    manifest_corpus = json.dumps(summary, ensure_ascii=False, default=str)
    name_corpus = "\n".join(apk_names[:20_000])
    findings: list[dict[str, Any]] = []
    for rule in rules:
        try:
            rx = re.compile(rule["pattern"], re.I)
            scope = rule["scope"]
            if scope == "strings":
                corpus, source = string_corpus, "DEX/resources"
            elif scope in ("manifest", "component"):
                corpus, source = manifest_corpus, "AndroidManifest.xml"
            elif scope == "permission":
                corpus, source = "\n".join(summary.get("permissions") or []), "AndroidManifest.xml"
            elif scope == "package":
                corpus, source = str(summary.get("package") or ""), "AndroidManifest.xml"
            else:
                corpus, source = name_corpus, "APK contents"
            matches = [m.group(0)[:200] for m in rx.finditer(corpus)]
            if not matches:
                continue
            findings.append(
                finding(
                    f"CUSTOM-{rule['id']}",
                    rule["title"],
                    rule["severity"],
                    category="CUSTOM",
                    description=rule.get("description") or f"Custom rule {rule['id']} matched {len(matches)} time(s).",
                    evidence=excerpt(matches),
                    remediation=rule.get("remediation") or "Review the matched code/configuration and remediate as appropriate.",
                    location=source,
                    cwe=rule.get("cwe"),
                    masvs=rule.get("masvs"),
                    confidence=rule.get("confidence", "medium"),
                    references=rule.get("references") or [],
                )
            )
        except Exception:
            continue
    return findings
