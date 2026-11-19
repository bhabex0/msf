"""Pydantic models shared by the API and the scan engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
ScanStatus = Literal["queued", "running", "completed", "failed"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity = "medium"
    category: Literal[
        "SAST", "SCA", "DAST", "TOOL", "ADVANCED", "CHAIN", "LIVE", "CUSTOM",
        "SEMGREP", "MEDICAL", "PKI",
    ] = "SAST"
    confidence: Literal["high", "medium", "low"] = "medium"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    location: str | None = None
    cwe: str | None = None
    owasp_masvs: str | None = None
    references: list[str] = Field(default_factory=list)


class Component(BaseModel):
    name: str
    version: str | None = None
    source: str = ""
    evidence: str = ""


class ScaFinding(BaseModel):
    id: str = ""
    title: str
    component: str = ""
    version: str | None = None
    vulnerability_id: str = ""
    severity: Severity = "medium"
    category: Literal["SCA"] = "SCA"
    confidence: Literal["high", "medium", "low"] = "medium"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    location: str | None = None
    cwe: str | None = None
    owasp_masvs: str | None = None
    source: str = "offline-db"
    references: list[str] = Field(default_factory=list)


class DastCheck(BaseModel):
    name: str
    status: Literal["passed", "failed", "skipped", "error", "not_applicable"]
    detail: str = ""
    evidence: str = ""


class ToolResult(BaseModel):
    name: str
    available: bool
    enabled: bool
    ran: bool = False
    detail: str = ""
    findings_count: int = 0


class ManifestSummary(BaseModel):
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    permissions: list[str] = Field(default_factory=list)
    activities: list[dict[str, Any]] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    receivers: list[dict[str, Any]] = Field(default_factory=list)
    providers: list[dict[str, Any]] = Field(default_factory=list)


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    risk_score: int = 0
    risk_label: str = "Unknown"


class ScanRecord(BaseModel):
    scan_id: str
    filename: str
    uploaded_at: str = Field(default_factory=utcnow)
    status: ScanStatus = "queued"
    stage: str = "queued"
    progress: int = 0
    error: str | None = None
    sha256: str | None = None
    size_bytes: int = 0

    manifest: ManifestSummary = Field(default_factory=ManifestSummary)
    certificate: dict[str, Any] = Field(default_factory=dict)
    pki: dict[str, Any] = Field(default_factory=dict)
    apk_files: list[str] = Field(default_factory=list)

    findings: list[Finding] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    sca_findings: list[ScaFinding] = Field(default_factory=list)
    dast_status: str = "not_run"
    dast_checks: list[DastCheck] = Field(default_factory=list)
    dast_info: dict[str, Any] = Field(default_factory=dict)
    sca_meta: dict[str, Any] = Field(default_factory=dict)

    # Advanced analysis (see scanner/advanced.py)
    advanced: dict[str, Any] = Field(default_factory=dict)
    attack_chains: list[dict[str, Any]] = Field(default_factory=list)
    playbook: list[str] = Field(default_factory=list)
    compliance: dict[str, Any] = Field(default_factory=dict)
    live_checks: list[dict[str, Any]] = Field(default_factory=list)
    custom_rules_applied: list[str] = Field(default_factory=list)
    policy: dict[str, Any] = Field(default_factory=dict)
    exports: dict[str, str] = Field(default_factory=dict)
    medical: dict[str, Any] = Field(default_factory=dict)
    toolchain: list[dict[str, Any]] = Field(default_factory=list)
    emulator: dict[str, Any] = Field(default_factory=dict)
    patching: dict[str, Any] = Field(default_factory=dict)

    tools: list[ToolResult] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)

    def compute_summary(self) -> None:
        all_findings: list[dict[str, Any]] = [f.model_dump() for f in self.findings]
        all_findings += [f.model_dump() for f in self.sca_findings]
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        score = sum(counts[s] * weights[s] for s in counts)
        self.summary = ScanSummary(
            **counts,
            total=sum(counts.values()),
            risk_score=min(100, score),
            risk_label=(
                "Critical" if score >= 70
                else "High" if score >= 40
                else "Medium" if score >= 15
                else "Low" if score > 0
                else "None"
            ),
        )
