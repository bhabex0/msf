"""Passive PKI/certificate analysis for Android packages.

This engine only interprets data already extracted from the APK and local lab
configuration. It never contacts a network service or modifies a device.

For authorized security testing only. PKI findings are heuristic leads and
require manual verification.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .. import pki_lab
from .rules import finding

NOTICE = (
    "For authorized security testing only. PKI findings are informational "
    "evidence for manual review, not malware, threat or exploit verdicts and "
    "not certifications. PKI tooling is not a malware/threat detection engine."
)
WEAK_SIGNATURE_TOKENS = ("MD5", "SHA1")
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
LONG_VALIDITY_DAYS = 3650

# Every PKI observation is context, never a threat/malware verdict. Info severity
# also keeps these findings out of critical/high/medium/low release-gate counts.
PKI_SEVERITY = "info"
DISPOSITION = "Informational PKI evidence only; not a malware, threat or exploit verdict."


def pki_finding(rule_id: str, title: str, **kwargs: Any) -> dict[str, Any]:
    """Build an informational, explicitly non-accusatory PKI finding."""
    kwargs.pop("severity", None)
    kwargs["description"] = f"{kwargs.get('description', '')} {DISPOSITION}".strip()
    return finding(rule_id, title, PKI_SEVERITY, **kwargs)


def _parse_date(value: Any) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _signer_flags(signer: dict[str, Any], now: dt.datetime) -> list[str]:
    flags: list[str] = []
    algorithm = str(signer.get("signature_algorithm") or "").upper()
    if any(token in algorithm for token in WEAK_SIGNATURE_TOKENS):
        flags.append("weak_signature_algorithm")

    key_algorithm = str(signer.get("public_key_algorithm") or "").lower()
    key_size = signer.get("key_size")
    if isinstance(key_size, int):
        if "rsa" in key_algorithm and key_size < MIN_RSA_BITS:
            flags.append("small_rsa_key")
        if "ec" in key_algorithm and key_size < MIN_EC_BITS:
            flags.append("small_ec_key")

    start = _parse_date(signer.get("valid_from"))
    end = _parse_date(signer.get("valid_until"))
    if end and end < now:
        flags.append("expired")
    if start and end and (end - start).days > LONG_VALIDITY_DAYS:
        flags.append("long_validity")
    if signer.get("basic_constraints_ca"):
        flags.append("ca_certificate_used_as_app_signer")
    if signer.get("self_signed"):
        flags.append("self_signed")
    return flags


def analyze_pki(
    certificate: dict[str, Any] | None,
    network_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return structured PKI evidence and findings from an already-parsed APK."""
    cert = certificate or {}
    net = network_config or {}
    now = dt.datetime.now(dt.timezone.utc)
    signers: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for index, raw in enumerate(cert.get("signers") or []):
        if not isinstance(raw, dict):
            continue
        signer = dict(raw)
        flags = _signer_flags(signer, now)
        signer["flags"] = flags
        signers.append(signer)
        evidence = (
            f"subject={signer.get('subject', '')} · "
            f"issuer={signer.get('issuer', '')} · "
            f"algorithm={signer.get('signature_algorithm', '')} · "
            f"key={signer.get('public_key_algorithm', '')}/{signer.get('key_size', '')} · "
            f"sha256={signer.get('sha256_fingerprint', '')}"
        )
        for flag in flags:
            findings.append(pki_finding(
                f"PKI-{flag.upper()}-{index + 1}",
                f"PKI: {flag.replace('_', ' ')} in signing certificate {index + 1}",
                category="PKI",
                description=(
                    f"The APK signing certificate has the PKI flag '{flag}'. "
                    "Confirm this is intentional for the owned or authorized test application."
                ),
                evidence=evidence,
                remediation=(
                    "Use a non-debug signing identity, a current signature algorithm and an "
                    "adequate key size. Do not treat this heuristic as proof of exploitability."
                ),
                cwe="CWE-295",
                masvs="MASVS-CODE-3",
                confidence="medium",
            ))

    v1_only = bool(cert.get("v1_signature")) and not bool(cert.get("v2_or_v3_signature"))
    if v1_only:
        findings.append(pki_finding(
            "PKI-V1-ONLY",
            "APK uses only the v1 signature scheme",
            category="PKI",
            description="Only JAR v1 signing was detected; APK Signature Scheme v2/v3 was not found.",
            evidence="v1_signature=true, v2_or_v3_signature=false",
            remediation="Sign with v2/v3 as well as v1 where compatibility requires it.",
            cwe="CWE-345",
            masvs="MASVS-CODE-3",
            confidence="medium",
        ))

    if cert.get("parse_error"):
        findings.append(pki_finding(
            "PKI-PARSE-ERROR",
            "Signing certificate details could not be parsed",
            category="PKI",
            description="The local certificate parser could not fully read the APK signature block.",
            evidence=str(cert.get("parse_error")),
            remediation="Verify with apksigner/keytool in the authorized test environment.",
            confidence="low",
        ))

    user_ca_trusted = bool(net.get("trust_user_certs_debug_only"))
    if user_ca_trusted:
        findings.append(pki_finding(
            "PKI-USER-CA-TRUSTED",
            "User-installed CA certificates are trusted",
            category="PKI",
            description=(
                "The network security configuration allows user-installed CA certificates. "
                "Confirm this is restricted to debug/authorized lab builds."
            ),
            evidence=f"resource={net.get('resource', '')}, debug_overridable={user_ca_trusted}",
            remediation="Remove user-CA trust from release builds or scope it to debug-only resources.",
            cwe="CWE-295",
            masvs="MASVS-NETWORK-1",
            confidence="medium",
        ))

    cleartext = bool(net.get("cleartext_traffic_permitted"))
    if cleartext:
        findings.append(pki_finding(
            "PKI-CLEARTEXT-PERMITTED",
            "Cleartext network traffic is permitted",
            category="PKI",
            description="The network security configuration permits cleartext traffic.",
            evidence=f"resource={net.get('resource', '')}",
            remediation="Disable cleartext traffic and require TLS 1.2+ with certificate validation.",
            cwe="CWE-319",
            masvs="MASVS-NETWORK-1",
            confidence="medium",
        ))

    counts: dict[str, int] = {}
    for flag in (f for s in signers for f in s.get("flags", [])):
        counts[flag] = counts.get(flag, 0) + 1

    return {
        "status": "ok",
        "notice": NOTICE,
        "summary": {
            "signer_count": len(signers),
            "v1_signature": bool(cert.get("v1_signature")),
            "v2_or_v3_signature": bool(cert.get("v2_or_v3_signature")),
            "v1_only": v1_only,
            "flags": counts,
            "finding_count": len(findings),
        },
        "signers": signers,
        "trust": {
            "resource": net.get("resource"),
            "cleartext_traffic_permitted": cleartext,
            "pinning_configured": bool(net.get("pinning_configured")),
            "user_ca_trusted": user_ca_trusted,
            "domains": net.get("domains") or [],
        },
        "lab": pki_lab.status(),
        "findings": findings,
    }
