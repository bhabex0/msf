"""Healthcare-focused analysis for medical and mHealth Android applications.

This module adds PHI/medical-domain detection and maps technical findings to
healthcare standards and regulations. It does not claim certification or legal
compliance; it produces evidence and review gaps for an authorized assessment.

Standards referenced:
- HIPAA Security Rule, 45 CFR 164.312 (access control, audit, integrity,
  authentication, transmission security)
- GDPR Articles 5, 6 and 32 (data minimisation, lawful basis, security)
- FDA "Cybersecurity in Medical Devices: QMS Considerations and Content of
  Premarket Submissions", final guidance issued 3 Feb 2026
- IEC 62304, ISO 14971, AAMI TIR57 / SW96, UL 2900-2-1, HITRUST CSF
- OWASP MASVS v2.1 privacy and OWASP Mobile Top 10
- HL7 FHIR / HIPAA interoperability expectations

For authorized testing only. All patterns are deliberately synthetic-safe and
report indicators rather than storing raw patient data where avoidable.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .. import config
from .rules import excerpt, finding

# PHI / medical identifiers. Values are capped and masked in evidence.
PHI_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("MRN", "Direct identifier", re.compile(r"\b(?:MRN|medical\s+record\s*(?:no\.?|number))\s*[:#-]?\s*\d{4,}\b", re.I), "CWE-359"),
    ("SSN", "Direct identifier", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "CWE-359"),
    ("DOB", "Direct identifier", re.compile(r"\b(?:DOB|date\s+of\s+birth)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.I), "CWE-359"),
    ("INSURANCE", "Direct identifier", re.compile(r"\b(?:insurance|member|policy)\s*(?:id|no\.?|number)?\s*[:#-]?\s*[A-Z0-9]{6,}\b", re.I), "CWE-359"),
    ("ICD10", "Clinical code", re.compile(r"\b[A-TV-Z][01]\d(?:\.[A-Z0-9]{1,4})?\b", re.I), "CWE-359"),
    ("CPT", "Clinical code", re.compile(r"\b(?:CPT|HCPCS)\s*[:#]?\s*\d{5}\b", re.I), "CWE-359"),
    ("NDC", "Clinical code", re.compile(r"\b\d{5}-\d{4}-\d{2}\b"), "CWE-359"),
    ("FHIR_RESOURCE", "Interoperability", re.compile(r"\b(?:Patient|Observation|DiagnosticReport|MedicationRequest|Encounter|Condition)/[A-Za-z0-9-]{2,}\b", re.I), "CWE-200"),
    ("HL7", "Interoperability", re.compile(r"\b(?:HL7|FHIR|fhir\+json|fhir\+xml|MSH\|)\b", re.I), "CWE-200"),
    ("CLINICAL_TERM", "Clinical context", re.compile(
        r"\b(?:patient|patient_id|patientId|diagnos(?:is|es)|medication|prescription|lab\s+result|"
        r"ehr|emr|phi|ephi|clinic|hospital|insurance|claim|provider|physician|nurse|caregiver|"
        r"appointment|treatment|therapy|symptom|allerg(?:y|ies)|vital\s+signs|blood\s+pressure|"
        r"glucose|a1c|ecg|ekg|dicom|pacs|radiology|pathology|surgery|discharge)\b", re.I), "CWE-359"),
]

MEDICAL_PERMISSIONS: dict[str, tuple[str, str]] = {
    "android.permission.READ_SMS": ("high", "SMS can contain PHI, appointment codes or 2FA tokens."),
    "android.permission.RECEIVE_SMS": ("high", "SMS can contain PHI, appointment codes or 2FA tokens."),
    "android.permission.READ_CONTACTS": ("medium", "Patient/provider contact lists may be exposed."),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "Location can reveal patient home or clinic visits."),
    "android.permission.ACCESS_COARSE_LOCATION": ("low", "Location can reveal clinic visits."),
    "android.permission.CAMERA": ("medium", "Can capture medical documents or wounds."),
    "android.permission.RECORD_AUDIO": ("high", "Can capture clinical consultations."),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Can read exported medical documents/images."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Can write PHI to shared storage."),
    "android.permission.BODY_SENSORS": ("high", "Direct health sensor data."),
    "android.permission.ACTIVITY_RECOGNITION": ("medium", "Health/activity data."),
    "android.permission.BLUETOOTH": ("low", "May pair with medical devices."),
    "android.permission.BLUETOOTH_ADMIN": ("low", "May pair with medical devices."),
    "android.permission.NFC": ("low", "May read medical device or patient tags."),
    "android.permission.READ_CALENDAR": ("medium", "Appointment data may be PHI."),
    "android.permission.POST_NOTIFICATIONS": ("medium", "Notifications may reveal PHI on lock screen."),
    "android.permission.USE_BIOMETRIC": ("info", "Positive control if bound to cryptographic keys."),
    "android.permission.USE_FINGERPRINT": ("info", "Positive control if bound to cryptographic keys."),
}

# Map existing finding-id prefixes to healthcare controls.
CONTROL_MAP: dict[str, list[str]] = {
    "SAST-DEBUGGABLE": ["HIPAA-164-312-A", "FDA-SECURITY-ARCHITECTURE"],
    "SAST-ALLOW-BACKUP": ["HIPAA-164-312-A", "GDPR-ART32", "FDA-DATA-PROTECTION"],
    "SAST-CLEARTEXT": ["HIPAA-164-312-E", "GDPR-ART32", "FDA-TRANSMISSION-SECURITY"],
    "SAST-HTTP": ["HIPAA-164-312-E", "GDPR-ART32", "FDA-TRANSMISSION-SECURITY"],
    "SAST-TLS": ["HIPAA-164-312-E", "GDPR-ART32", "FDA-TRANSMISSION-SECURITY"],
    "SAST-WEAK-CRYPTO": ["HIPAA-164-312-A", "GDPR-ART32", "FDA-DATA-PROTECTION"],
    "SAST-WEAK-RANDOM": ["FDA-DATA-PROTECTION"],
    "SAST-SECRET": ["HIPAA-164-312-D", "GDPR-ART32", "FDA-CREDENTIAL-MANAGEMENT"],
    "SAST-UNSAFE-STORAGE": ["HIPAA-164-312-A", "GDPR-ART32", "FDA-DATA-PROTECTION"],
    "SAST-LOGGING": ["HIPAA-164-312-B", "GDPR-ART32", "FDA-LOGGING"],
    "SAST-SQLI": ["HIPAA-164-312-C", "FDA-DATA-INTEGRITY"],
    "SAST-EXPORTED": ["HIPAA-164-312-A", "FDA-ACCESS-CONTROL"],
    "SAST-WEBVIEW": ["FDA-PLATFORM-INTERACTION"],
    "ADV-DEEPLINK": ["FDA-PLATFORM-INTERACTION"],
    "ADV-NSC": ["HIPAA-164-312-E", "FDA-TRANSMISSION-SECURITY"],
    "ADV-PIN": ["HIPAA-164-312-E", "FDA-TRANSMISSION-SECURITY"],
    "ADV-HIGH-ENTROPY": ["HIPAA-164-312-D", "FDA-CREDENTIAL-MANAGEMENT"],
    "ADV-TRACKERS": ["GDPR-ART5", "GDPR-ART6", "MASVS-PRIVACY"],
    "ADV-PACKER": ["FDA-SECURITY-ARCHITECTURE"],
    "ADV-ANTI": ["FDA-SECURITY-ARCHITECTURE"],
    "SCA-": ["FDA-SBOM", "FDA-VULNERABILITY-MANAGEMENT", "IEC-62304"],
    "CUSTOM-": ["FDA-SECURITY-TESTING"],
    "SEMGREP-": ["FDA-SECURITY-TESTING"],
    "DAST-": ["FDA-SECURITY-TESTING"],
    "LIVE-": ["FDA-SECURITY-TESTING"],
}

STANDARD_LABELS: dict[str, tuple[str, str]] = {
    "HIPAA-164-312-A": ("HIPAA 45 CFR 164.312(a)", "Access control and unique user identification"),
    "HIPAA-164-312-B": ("HIPAA 45 CFR 164.312(b)", "Audit controls"),
    "HIPAA-164-312-C": ("HIPAA 45 CFR 164.312(c)(1)", "Integrity of ePHI"),
    "HIPAA-164-312-D": ("HIPAA 45 CFR 164.312(d)", "Person or entity authentication"),
    "HIPAA-164-312-E": ("HIPAA 45 CFR 164.312(e)", "Transmission security"),
    "GDPR-ART5": ("GDPR Art. 5", "Data minimisation and purpose limitation"),
    "GDPR-ART6": ("GDPR Art. 6", "Lawful basis for processing"),
    "GDPR-ART32": ("GDPR Art. 32", "Security of processing"),
    "FDA-SECURITY-ARCHITECTURE": ("FDA 2026 Premarket Cybersecurity Guidance", "Security architecture and threat modelling"),
    "FDA-DATA-PROTECTION": ("FDA 2026 Premarket Cybersecurity Guidance", "Data protection at rest and in use"),
    "FDA-TRANSMISSION-SECURITY": ("FDA 2026 Premarket Cybersecurity Guidance", "Authenticated encrypted communications"),
    "FDA-CREDENTIAL-MANAGEMENT": ("FDA 2026 Premarket Cybersecurity Guidance", "Credential and secret management"),
    "FDA-ACCESS-CONTROL": ("FDA 2026 Premarket Cybersecurity Guidance", "Least privilege and interface access control"),
    "FDA-LOGGING": ("FDA 2026 Premarket Cybersecurity Guidance", "Security logging and auditability"),
    "FDA-DATA-INTEGRITY": ("FDA 2026 Premarket Cybersecurity Guidance", "Data integrity"),
    "FDA-PLATFORM-INTERACTION": ("FDA 2026 Premarket Cybersecurity Guidance", "Platform and WebView interaction"),
    "FDA-SBOM": ("FDA 2026 Premarket Cybersecurity Guidance", "Software bill of materials"),
    "FDA-VULNERABILITY-MANAGEMENT": ("FDA 2026 Premarket Cybersecurity Guidance", "Vulnerability management and disclosure"),
    "FDA-SECURITY-TESTING": ("FDA 2026 Premarket Cybersecurity Guidance", "Security testing evidence"),
    "IEC-62304": ("IEC 62304", "Medical device software lifecycle processes"),
    "ISO-14971": ("ISO 14971 / AAMI SW96", "Medical device risk management"),
    "UL-2900-2-1": ("UL 2900-2-1", "Network-connectable healthcare product security"),
    "HITRUST": ("HITRUST CSF", "Healthcare information security controls"),
    "MASVS-PRIVACY": ("OWASP MASVS v2.1 PRIVACY", "Mobile privacy controls"),
    "HL7-FHIR": ("HL7 FHIR", "Healthcare data exchange security"),
}


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:6] + "…" + value[-2:]


def _finding_dicts(findings: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in findings:
        if isinstance(item, dict):
            out.append(item)
        elif hasattr(item, "model_dump"):
            out.append(item.model_dump())
        elif hasattr(item, "__dict__"):
            out.append(dict(item.__dict__))
    return out


def detect_phi(strings: list[str], max_evidence: int = 12) -> list[dict[str, Any]]:
    indicators: dict[str, dict[str, Any]] = {}
    corpus = strings[:250_000]
    for label, category, pattern, cwe in PHI_PATTERNS:
        matches: list[str] = []
        for text in corpus:
            for match in pattern.finditer(text):
                matches.append(_mask(match.group(0)))
                if len(matches) >= max_evidence:
                    break
            if len(matches) >= max_evidence:
                break
        if matches:
            indicators[label] = {
                "label": label,
                "category": category,
                "count_hint": len(matches),
                "evidence": excerpt([f"{label}: {m}" for m in matches[:6]]),
                "cwe": cwe,
            }
    return list(indicators.values())


def detect_medical_permissions(permissions: Iterable[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for perm in permissions:
        name = str(perm)
        if name in MEDICAL_PERMISSIONS:
            sev, why = MEDICAL_PERMISSIONS[name]
            out.append({"permission": name, "severity": sev, "reason": why})
    return out


def _standards_from_findings(findings: list[dict[str, Any]], phi_present: bool) -> dict[str, Any]:
    controls: dict[str, dict[str, Any]] = {}
    for f in findings:
        fid = str(f.get("id") or "")
        mapped: list[str] = []
        for prefix, control_ids in CONTROL_MAP.items():
            if fid.startswith(prefix):
                mapped = control_ids
                break
        for control in mapped:
            entry = controls.setdefault(control, {
                "control": control,
                "title": STANDARD_LABELS.get(control, (control, ""))[0],
                "requirement": STANDARD_LABELS.get(control, (control, ""))[1],
                "status": "gap",
                "finding_ids": [],
                "recommendation": f.get("remediation") or "Review and remediate the mapped finding.",
            })
            if fid not in entry["finding_ids"]:
                entry["finding_ids"].append(fid)
    if phi_present:
        for control in ("ISO-14971", "UL-2900-2-1", "HITRUST", "HL7-FHIR"):
            controls.setdefault(control, {
                "control": control,
                "title": STANDARD_LABELS[control][0],
                "requirement": STANDARD_LABELS[control][1],
                "status": "review",
                "finding_ids": [],
                "recommendation": "Confirm this control in the device risk-management file and clinical security plan.",
            })
    return {
        "frameworks": sorted({STANDARD_LABELS.get(c, (c, ""))[0] for c in controls}),
        "controls": sorted(controls.values(), key=lambda x: (x["status"] != "gap", x["control"])),
        "gap_count": sum(1 for c in controls.values() if c["status"] == "gap"),
        "review_count": sum(1 for c in controls.values() if c["status"] == "review"),
    }


def analyze_medical(
    *,
    summary: dict[str, Any],
    strings: list[str],
    findings: list[dict[str, Any]],
    network_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the medical analysis payload and append medical findings."""
    if not config.ENABLE_MEDICAL or config.MEDICAL_PHI_MODE == "off":
        return {"status": "disabled", "domain": config.MEDICAL_DOMAIN, "findings": []}

    nsc = network_config or {}
    phi = detect_phi(strings)
    perms = detect_medical_permissions(summary.get("permissions") or [])
    direct_ids = {p["label"] for p in phi if p["category"] in ("Direct identifier", "Clinical code", "Interoperability")}
    phi_present = bool(phi)
    fids = {str(f.get("id") or "") for f in findings}
    own_findings: list[dict[str, Any]] = []

    def add(fid: str, title: str, sev: str, description: str, remediation: str, evidence: str, cwe: str | None = None) -> None:
        own_findings.append(finding(
            fid, title, sev, category="MEDICAL", description=description,
            evidence=evidence, remediation=remediation, location="APK strings / manifest",
            cwe=cwe, masvs="MASVS-PRIVACY-1", confidence="medium",
            references=[
                "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
                "https://www.fda.gov/medical-devices/medical-device-cybersecurity",
            ],
        ))

    if direct_ids:
        add(
            "MED-PHI-HARDCODED", "Potential PHI or clinical identifiers in app strings", "high",
            f"The APK contains synthetic/observable medical identifiers or clinical codes: {', '.join(sorted(direct_ids))}. "
            "In a medical app these may be real ePHI and must not be hardcoded or logged.",
            "Remove all real identifiers from release builds, use tokenisation, store ePHI only in approved encrypted stores, "
            "and add automated PHI leakage tests to CI.",
            "; ".join(f"{p['label']}: {p['evidence'][:240]}" for p in phi[:6]),
            "CWE-359",
        )

    if phi_present and any("LOGGING" in x or "DAST-SENSITIVE-LOGS" in x for x in fids):
        add(
            "MED-PHI-LOGGING", "PHI-capable app writes sensitive data to logs", "high",
            "Medical/clinical keywords and logging APIs were both observed. Logcat is accessible on rooted/debug devices "
            "and may be captured by support tools.",
            "Disable verbose logging in release builds, redact all identifiers and add a log-scrubbing test gate.",
            "Medical indicators: " + ", ".join(p["label"] for p in phi[:8]),
            "CWE-532",
        )

    if phi_present and any("BACKUP" in x for x in fids):
        add(
            "MED-PHI-BACKUP", "PHI-capable app allows unrestricted backup", "high",
            "The app appears to handle patient/clinical data while allowing OS backup, which can copy ePHI off-device.",
            "Disable allowBackup or provide a strict backup rule that excludes all ePHI; encrypt any permitted backup.",
            "allowBackup indicator present with medical strings.",
            "CWE-530",
        )

    if phi_present and (nsc.get("cleartext_enabled") or any("CLEARTEXT" in x or "TLS" in x or "HTTP" in x for x in fids)):
        add(
            "MED-PHI-CLEARTEXT", "PHI-capable app permits unencrypted or weakly validated transport", "critical",
            "Cleartext traffic, missing pinning or TLS bypass was identified in an app with medical/PHI indicators. "
            "This directly undermines HIPAA transmission security and FDA encrypted-communication expectations.",
            "Enforce TLS 1.2+, validate certificates, pin where appropriate, set cleartextTrafficPermitted=false and "
            "verify with an interception proxy using a non-production CA.",
            f"cleartext_enabled={nsc.get('cleartext_enabled')}; TLS-related findings present.",
            "CWE-319",
        )

    if phi_present and any("EXPORTED" in x for x in fids):
        add(
            "MED-PHI-EXPORTED", "Exported components on a PHI-capable app", "high",
            "Exported activities/services/providers can expose patient data or accept hostile Intents in a medical app.",
            "Set exported=false unless required, enforce signature-level permissions and validate all Intent extras.",
            "Exported-component findings present with medical/PHI indicators.",
            "CWE-926",
        )

    if phi_present and any("STORAGE" in x or "UNSAFE" in x for x in fids):
        add(
            "MED-PHI-STORAGE", "Unsafe storage in a PHI-capable app", "high",
            "The app handles clinical data indicators and has unsafe-storage signals, risking unauthorised ePHI access.",
            "Store ePHI only in internal encrypted storage or Android Keystore-backed stores; never use public external storage.",
            "Unsafe-storage findings present with medical/PHI indicators.",
            "CWE-311",
        )

    fhir_http = [s for s in strings[:250_000] if re.search(r"http://[^\s\"']*fhir[^\s\"']*", s, re.I)]
    if fhir_http:
        add(
            "MED-FHIR-INSECURE", "FHIR endpoint referenced over plaintext HTTP", "critical",
            "A HL7 FHIR endpoint uses http://. Patient resource payloads would be exposed in transit.",
            "Use https:// with certificate validation, enforce TLS at the gateway and document the data flow in the threat model.",
            excerpt(fhir_http[:5]),
            "CWE-319",
        )

    if phi_present and any("TRACKERS" in x or "ADV-TRACKERS" in x for x in fids):
        add(
            "MED-TRACKER-PHI", "Third-party trackers in a PHI-capable app", "high",
            "Analytics/advertising SDKs are present in an app with clinical data indicators. They may collect identifiers "
            "or endpoint data that becomes ePHI when linked to a patient.",
            "Remove non-essential trackers from medical builds, document all SDK data flows, obtain lawful basis and sign BAAs where required.",
            "Tracker findings present with medical/PHI indicators.",
            "CWE-359",
        )

    if not any("BIOMETRIC" in fid or "KEYSTORE" in fid for fid in fids):
        if phi_present:
            add(
                "MED-AUTH-REVIEW", "Strong local authentication / Keystore binding not evidenced", "medium",
                "No biometric or Android Keystore binding signal was found in a PHI-capable app. This is a review item, "
                "not proof that authentication is absent.",
                "Require strong authentication for ePHI access, bind keys to biometrics with setUserAuthenticationRequired(true) "
                "and invalidate keys on enrolment changes.",
                "No biometric/Keystore markers in findings.",
                "CWE-287",
            )

    high_sens = [p for p in perms if p["severity"] == "high"]
    if high_sens:
        add(
            "MED-PERMISSION-HIGH", "High-impact health-related permissions requested", "medium",
            "The app requests permissions that can access consultations, messages or body-sensor data.",
            "Justify each permission in the privacy notice and threat model, request at point of use, and minimising scope.",
            "; ".join(f"{p['permission']}: {p['reason']}" for p in high_sens[:6]),
            "CWE-250",
        )

    all_findings = findings + own_findings
    standards = _standards_from_findings(all_findings, phi_present)

    if phi_present and (fhir_http or any(x.startswith(("MED-PHI-CLEARTEXT", "MED-FHIR-INSECURE")) for x in [f["id"] for f in own_findings])):
        risk = "critical"
    elif phi_present and own_findings:
        risk = "high"
    elif phi_present:
        risk = "medium"
    elif perms:
        risk = "low"
    else:
        risk = "informational"

    return {
        "status": "enabled",
        "domain": config.MEDICAL_DOMAIN,
        "phi_mode": config.MEDICAL_PHI_MODE,
        "disclaimer": "Evidence mapping only; not a certification of HIPAA, GDPR, FDA, IEC 62304 or HITRUST compliance.",
        "phi_present": phi_present,
        "direct_identifiers": sorted(direct_ids),
        "phi_indicators": phi,
        "medical_permissions": perms,
        "risk_level": risk,
        "standards": standards,
        "gaps": [c for c in standards["controls"] if c["status"] == "gap"],
        "review_items": [c for c in standards["controls"] if c["status"] == "review"],
        "findings": own_findings,
    }
