"""Self-contained HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any

from ..models import ScanRecord

SEV_COLORS = {
    "critical": "#b42318",
    "high": "#d92d20",
    "medium": "#dc6803",
    "low": "#1570ef",
    "info": "#667085",
}


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _severity_badge(sev: str) -> str:
    color = SEV_COLORS.get(sev, "#667085")
    return f'<span class="badge" style="background:{color}">{esc(sev.upper())}</span>'


def _finding_block(f: dict[str, Any], index: int) -> str:
    sev = str(f.get("severity", "info"))
    evidence = f.get("evidence") or ""
    refs = f.get("references") or []
    meta = []
    if f.get("cwe"):
        meta.append(esc(f["cwe"]))
    if f.get("owasp_masvs"):
        meta.append(esc(f["owasp_masvs"]))
    if f.get("confidence"):
        meta.append(f"confidence: {esc(f['confidence'])}")
    return f"""
    <article class="finding" data-severity="{esc(sev)}">
      <div class="finding-head">
        <span class="num">{index}</span>
        <h3>{esc(f.get('title'))}</h3>
        {_severity_badge(sev)}
      </div>
      <div class="meta">{esc(f.get('category'))} &middot; {esc(f.get('id'))} &middot; {' &middot; '.join(meta)}</div>
      <p>{esc(f.get('description'))}</p>
      {'<pre>' + esc(evidence) + '</pre>' if evidence else ''}
      <p class="fix"><strong>Remediation:</strong> {esc(f.get('remediation'))}</p>
      {'<p class="refs"><strong>References:</strong> ' + ', '.join(f'<a href="{esc(r)}">{esc(r)}</a>' for r in refs) + '</p>' if refs else ''}
    </article>"""


def _table(headers: list[str], rows: list[list[Any]], empty: str = "No data available.") -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows)
    if not body:
        body = f'<tr><td colspan="{len(headers)}" class="empty">{esc(empty)}</td></tr>'
    return f'<div class="tw"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _ordered_list(items: list[str]) -> str:
    if not items:
        return '<p class="empty">No entries.</p>'
    return "<ol>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ol>"


def _policy_section(policy: dict[str, Any]) -> str:
    status = str(policy.get("status") or "not_evaluated").upper()
    color = SEV_COLORS["critical"] if status == "FAIL" else "#12b76a"
    thresholds = policy.get("thresholds") or {}
    actual = policy.get("actual") or {}
    rows = [[sev, thresholds.get(sev), actual.get(sev)] for sev in actual]
    violations = policy.get("violations") or []
    return f"""
    <div class="card"><h2>Release policy gate</h2>
      <p><span class="badge" style="background:{color}">{esc(status)}</span>
      &middot; thresholds: <code>{esc(json.dumps(policy.get('thresholds', {})))}</code></p>
      {_table(["Severity", "Allowed", "Found"], rows)}
      {''.join(f'<p class="fix"><strong>{esc(v.get("severity"))}:</strong> {esc(v.get("message"))}</p>' for v in violations)}
    </div>"""


def _advanced_section(advanced: dict[str, Any], live_checks: list[dict[str, Any]]) -> str:
    if not advanced:
        return ""
    deep_rows = [
        [x.get("activity"), x.get("scheme"), x.get("host"), x.get("browsable"), x.get("auto_verified")]
        for x in advanced.get("deep_links", [])
    ]
    nsc = advanced.get("network_config_detail", {})
    nsc_rows = [
        ["Resources", ", ".join(nsc.get("resources", [])) or "none"],
        ["Trusts user CAs (production)", nsc.get("user_ca_trusted")],
        ["Debug trusts user CAs", nsc.get("debug_user_ca_trusted")],
        ["Cleartext permitted", nsc.get("cleartext_enabled")],
        ["Pin sets", len(nsc.get("pin_sets", []))],
        ["Expired pin sets", len(nsc.get("expired_pins", []))],
    ]
    tracker_rows = [[t.get("category"), t.get("name"), t.get("evidence")] for t in advanced.get("trackers", [])]
    elf_rows = [
        [l.get("name"), l.get("pie"), l.get("nx_stack"), l.get("full_relro"), l.get("canary"), l.get("stripped")]
        for l in advanced.get("elf_hardening", [])
    ]
    cert_rows = [
        [s.get("subject"), s.get("signature_algorithm"), s.get("key_size"), s.get("self_signed"), s.get("expired")]
        for s in (advanced.get("certificate_analysis", {}).get("signers") or [])
    ]
    apkid = advanced.get("apkid", {})
    live_rows = [[c.get("name"), c.get("status"), c.get("detail")] for c in live_checks]
    return f"""
    <div class="card"><h2>Advanced analysis</h2>
      <h3>Deep links and App Links</h3>
      {_table(["Activity", "Scheme", "Host", "Browsable", "autoVerify"], deep_rows, "No deep links declared.")}
      <h3>Network security configuration</h3>
      {_table(["Property", "Value"], nsc_rows)}
      <h3>Trackers and SDKs</h3>
      {_table(["Category", "SDK", "Evidence"], tracker_rows, "No known trackers detected.")}
      <h3>Packer / anti-analysis signals</h3>
      <pre>{esc(json.dumps(apkid, indent=2, ensure_ascii=False))}</pre>
      <h3>Native library hardening</h3>
      {_table(["Library", "PIE", "NX stack", "Full RELRO", "Canary", "Stripped"], elf_rows, "No native libraries found.")}
      <h3>Signing certificate forensics</h3>
      {_table(["Subject", "Algorithm", "Key size", "Self-signed", "Expired"], cert_rows)}
      <h3>High-entropy string candidates</h3>
      <pre>{esc(json.dumps(advanced.get("entropy_secrets", []), indent=2, ensure_ascii=False))}</pre>
      <h3>Live checks</h3>
      {_table(["Check", "Status", "Detail"], live_rows, "Live checks disabled.")}
    </div>"""


def _pki_section(pki: dict[str, Any], cert: dict[str, Any]) -> str:
    if not pki:
        return ""
    summary = pki.get("summary") or {}
    trust = pki.get("trust") or {}
    lab = pki.get("lab") or {}

    def flat(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return value

    summary_rows = [
        ["Status", pki.get("status")],
        ["Signers", summary.get("signer_count")],
        ["Signature schemes", ", ".join(
            part for part in (
                "v1" if summary.get("v1_signature") else "",
                "v2/v3" if summary.get("v2_or_v3_signature") else "",
            ) if part
        ) or "unknown"],
        ["v1 only", summary.get("v1_only")],
        ["Flags", flat(summary.get("flags") or {})],
        ["PKI findings", summary.get("finding_count")],
    ]
    signer_rows = [
        [
            s.get("subject"), s.get("issuer"), s.get("signature_algorithm"),
            f"{s.get('public_key_algorithm') or 'unknown'}/{s.get('key_size') or '?'}",
            s.get("sha256_fingerprint"), ", ".join(s.get("flags") or []) or "none",
        ]
        for s in (pki.get("signers") or [])
    ]
    trust_rows = [
        ["Resource", trust.get("resource")],
        ["Cleartext permitted", trust.get("cleartext_traffic_permitted")],
        ["Pinning configured", trust.get("pinning_configured")],
        ["User CA trusted", trust.get("user_ca_trusted")],
        ["Domains", flat(trust.get("domains") or [])],
    ]
    lab_rows = [
        ["Lab enabled", lab.get("enabled")],
        ["Lab directory", lab.get("directory")],
        ["Local CA present", (lab.get("ca") or {}).get("exists")],
        ["Keystore present", (lab.get("keystore") or {}).get("exists")],
        ["Proxy CA configured", (lab.get("ca") or {}).get("proxy_ca_configured")],
        ["Device installation by platform", (lab.get("device_installation") or {}).get("performed_by_platform")],
        ["Tool availability", flat({
            name: item.get("path") if item.get("available") else "not found"
            for name, item in (lab.get("tools") or {}).items()
        })],
    ]
    known_schemes = [
        name for name, key in (("v1", "v1_signature"), ("v2/v3", "v2_or_v3_signature"))
        if cert.get(key)
    ]
    return f"""
    <div class="card"><h2>PKI / certificate &amp; keystore</h2>
      <p class="meta">{esc(pki.get('notice') or '')}</p>
      <h3>Signing summary</h3>
      {_table(["Property", "Value"], summary_rows)}
      <h3>Signing certificates</h3>
      {_table(["Subject", "Issuer", "Algorithm", "Key", "SHA-256 fingerprint", "Flags"], signer_rows, "No parsed signing certificate.")}
      <h3>TLS trust configuration</h3>
      {_table(["Property", "Value"], trust_rows)}
      <h3>Local lab material</h3>
      {_table(["Property", "Value"], lab_rows)}
      <p class="meta">Signature schemes observed in raw APK metadata: {esc(', '.join(known_schemes) or 'unknown')}. Device CA installation is never performed by this platform. PKI tooling is not a malware or threat detection engine; these findings are informational evidence for manual review only.</p>
    </div>"""


def _chain_section(chains: list[dict[str, Any]], playbook: list[str], compliance: dict[str, Any]) -> str:
    if not chains and not playbook and not compliance:
        return ""
    chain_rows = [[c.get("name"), c.get("severity"), ", ".join(c.get("requires", []))] for c in chains]
    masvs = compliance.get("masvs_v2_categories", {})
    owasp = compliance.get("owasp_mobile_top10", {})
    comp_rows = [[f"MASVS-{k}", v] for k, v in sorted(masvs.items())]
    comp_rows += [[k, v] for k, v in sorted(owasp.items()) if v]
    return f"""
    <div class="card"><h2>Attack chains, playbook and compliance</h2>
      <h3>Attack chains</h3>
      {_table(["Chain", "Severity", "Preconditions"], chain_rows, "No attack chains identified.")}
      <h3>Verification playbook</h3>
      {_ordered_list(playbook)}
      <h3>Compliance coverage</h3>
      {_table(["Category", "Findings"], comp_rows)}
    </div>"""


def _medical_section(medical: dict[str, Any]) -> str:
    if not medical or medical.get("status") in ("disabled", "not_run"):
        return ""
    phi = medical.get("phi_indicators") or []
    perms = medical.get("medical_permissions") or []
    standards = medical.get("standards") or {}
    controls = standards.get("controls") or []
    risk = str(medical.get("risk_level") or "informational").upper()
    rows = [
        ["PHI / clinical indicators", "present" if medical.get("phi_present") else "not detected"],
        ["Direct identifiers", ", ".join(medical.get("direct_identifiers") or []) or "none"],
        ["Medical risk level", risk],
        ["Framework gaps", standards.get("gap_count", 0)],
        ["Review items", standards.get("review_count", 0)],
    ]
    phi_rows = [[p.get("label"), p.get("category"), p.get("count_hint"), p.get("evidence")] for p in phi]
    perm_rows = [[p.get("permission"), p.get("severity"), p.get("reason")] for p in perms]
    control_rows = [
        [c.get("title"), c.get("control"), c.get("status"), ", ".join(c.get("finding_ids") or []) or "review"]
        for c in controls
    ]
    return f"""
    <div class="card"><h2>Medical / PHI analysis</h2>
      <p class="meta">Domain: {esc(medical.get('domain'))} &middot; Mode: {esc(medical.get('phi_mode'))}</p>
      {_table(["Property", "Value"], rows)}
      <h3>Detected indicators (masked evidence)</h3>
      {_table(["Indicator", "Category", "Count", "Evidence"], phi_rows, "No medical indicators detected.")}
      <h3>Health-related permissions</h3>
      {_table(["Permission", "Severity", "Reason"], perm_rows, "No health-related permissions detected.")}
      <h3>Standards and control evidence</h3>
      {_table(["Framework control", "Control ID", "Status", "Mapped findings"], control_rows, "No mapped controls.")}
      <p class="fix"><strong>Scope:</strong> {esc(medical.get('disclaimer'))}</p>
    </div>"""


def _toolchain_section(
    toolchain: list[dict[str, Any]],
    emulator: dict[str, Any],
    patching: dict[str, Any],
) -> str:
    if not toolchain and not emulator and not patching:
        return ""
    tool_rows = [
        [t.get("name"), t.get("category"), "yes" if t.get("available") else "no",
         "yes" if t.get("ran") else "no", "yes" if t.get("invasive") else "no", t.get("detail")]
        for t in toolchain
    ]
    proxy = (emulator.get("proxy") or {}) if isinstance(emulator, dict) else {}
    emu = (emulator.get("emulator") or {}) if isinstance(emulator, dict) else {}
    lab_rows = [
        ["Authorization", emulator.get("authorization") if isinstance(emulator, dict) else ""],
        ["Proxy", f"{proxy.get('type')} @ {proxy.get('endpoint')}" if proxy.get("configured") else "not configured"],
        ["ADB available", emu.get("adb_available")],
        ["Connected devices", ", ".join(emu.get("devices") or []) or "none"],
        ["CA certificate", emulator.get("ca_installation", {}).get("path") if isinstance(emulator, dict) else ""],
        ["Invasive workflows", "allowed" if (isinstance(emulator, dict) and emu.get("invasive_allowed")) else "blocked"],
    ]
    commands = (emulator.get("commands") or []) if isinstance(emulator, dict) else []
    command_rows = [[c.get("name"), c.get("command")] for c in commands]
    patch_steps = (patching.get("steps") or []) if isinstance(patching, dict) else []
    patch_rows = [
        [s.get("name"), s.get("purpose"), s.get("status"),
         "yes" if s.get("available") else "no", s.get("command")]
        for s in patch_steps
    ]
    return f"""
    <div class="card"><h2>Advanced toolchain and interception lab</h2>
      <h3>Tool status</h3>
      {_table(["Tool", "Category", "Available", "Executed", "Invasive", "Detail"], tool_rows)}
      <h3>Emulator / proxy lab</h3>
      {_table(["Property", "Value"], lab_rows)}
      <h3>Generated lab commands</h3>
      {_table(["Step", "Command"], command_rows, "No lab commands generated.")}
      <h3>Patch / instrumentation workflows (planned, not silently executed)</h3>
      {_table(["Workflow", "Purpose", "Status", "Available", "Command"], patch_rows)}
      <p class="fix"><strong>Authorization:</strong> {esc((patching.get('authorization') if isinstance(patching, dict) else '') or (emulator.get('authorization') if isinstance(emulator, dict) else ''))}</p>
    </div>"""


def generate_html_report(record: ScanRecord) -> str:
    data = record.model_dump()
    summary = data.get("summary", {})
    manifest = data.get("manifest", {})
    cert = data.get("certificate", {})
    findings = data.get("findings", []) + data.get("sca_findings", [])
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_rank.get(str(f.get("severity")), 9), str(f.get("title"))))

    sev_counts = "".join(
        f'<div class="stat" style="border-top:4px solid {SEV_COLORS[s]}">'
        f'<div class="stat-num">{summary.get(s, 0)}</div><div class="stat-label">{s.upper()}</div></div>'
        for s in ("critical", "high", "medium", "low", "info")
    )

    finding_html = "\n".join(_finding_block(f, i) for i, f in enumerate(findings, 1)) or (
        '<p class="empty">No findings were produced.</p>'
    )

    components = data.get("components", [])
    comp_rows = "\n".join(
        f"<tr><td>{esc(c.get('name'))}</td><td>{esc(c.get('version') or 'unknown')}</td>"
        f"<td>{esc(c.get('source'))}</td><td><code>{esc(c.get('evidence'))}</code></td></tr>"
        for c in components
    ) or '<tr><td colspan="4" class="empty">No known components detected.</td></tr>'

    dast_checks = data.get("dast_checks", [])
    dast_rows = "\n".join(
        f"<tr><td>{esc(c.get('name'))}</td><td>{_severity_badge(c.get('status','')) if c.get('status') in ('failed','error') else esc(c.get('status'))}</td>"
        f"<td>{esc(c.get('detail'))}</td></tr>"
        for c in dast_checks
    ) or '<tr><td colspan="3" class="empty">DAST was not executed.</td></tr>'

    tools_rows = "\n".join(
        f"<tr><td>{esc(t.get('name'))}</td><td>{'yes' if t.get('available') else 'no'}</td>"
        f"<td>{'yes' if t.get('ran') else 'no'}</td><td>{esc(t.get('detail'))}</td></tr>"
        for t in data.get("tools", [])
    )

    perms = manifest.get("permissions") or []
    comp_summary = []
    for key, label in (("activities", "Activities"), ("services", "Services"), ("receivers", "Receivers"), ("providers", "Providers")):
        items = manifest.get(key) or []
        exported = [i.get("name") for i in items if i.get("exported") is True]
        comp_summary.append(f"{label}: {len(items)} total, {len(exported)} explicitly exported")

    cert_schemes = []
    if cert.get("v1_signature"):
        cert_schemes.append("v1")
    if cert.get("v2_or_v3_signature"):
        cert_schemes.append("v2/v3")
    signer = (cert.get("signers") or [{}])[0]
    score = int(summary.get("risk_score", 0) or 0)
    score_color = SEV_COLORS["critical"] if score >= 70 else SEV_COLORS["high"] if score >= 40 else SEV_COLORS["medium"] if score >= 15 else SEV_COLORS["low"] if score > 0 else SEV_COLORS["info"]

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — {esc(manifest.get('package') or record.filename)}</title>
<style>
:root{{--bg:#f7f8fa;--card:#fff;--text:#101828;--muted:#667085;--line:#e4e7ec}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:32px 20px 80px}}
header.hero{{background:linear-gradient(135deg,#101828,#344054);color:#fff;border-radius:16px;padding:32px;box-shadow:0 8px 24px #10182822}}
header.hero h1{{margin:0 0 6px;font-size:26px}}
header.hero .sub{{opacity:.8}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;margin:20px 0}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}}
.stat{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}}
.stat-num{{font-size:26px;font-weight:700}}
.stat-label{{font-size:11px;color:var(--muted);letter-spacing:.08em}}
h2{{font-size:19px;margin:0 0 16px;border-bottom:1px solid var(--line);padding-bottom:8px}}
h3{{font-size:15px;margin:0}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}}
code,pre{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}}
pre{{background:#f2f4f7;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;max-height:280px}}
.finding{{border:1px solid var(--line);border-left:5px solid var(--muted);border-radius:10px;padding:16px 18px;margin:14px 0;background:#fff}}
.finding-head{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.num{{background:#f2f4f7;border-radius:6px;padding:2px 8px;font-weight:700;color:var(--muted)}}
.badge{{color:#fff;border-radius:999px;padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:.06em}}
.meta{{color:var(--muted);font-size:12px;margin:4px 0 10px}}
.fix{{background:#ecfdf3;border-left:3px solid #12b76a;padding:10px 12px;border-radius:6px}}
.refs{{font-size:12px;color:var(--muted);word-break:break-all}}
.refs a{{color:#1570ef}}
.empty{{color:var(--muted);font-style:italic}}
.score-bar{{height:12px;background:#e4e7ec;border-radius:99px;overflow:hidden;margin-top:10px}}
.score-fill{{height:100%;width:{score}%;background:{score_color}}}
.kv{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 20px}}
.kv div{{border-bottom:1px dashed var(--line);padding:5px 0}}
.kv span{{color:var(--muted);display:inline-block;min-width:130px}}
footer{{color:var(--muted);font-size:12px;text-align:center;margin-top:32px}}
@media print{{body{{background:#fff}}.card,header.hero{{box-shadow:none;break-inside:avoid}}}}
</style></head><body><div class="wrap">
<header class="hero">
  <h1>APK Security Assessment Report</h1>
  <div class="sub">{esc(manifest.get('package') or record.filename)} &middot; {esc(manifest.get('version_name') or 'unknown version')} &middot; generated {esc(record.uploaded_at)}</div>
  <div style="margin-top:16px">
    <strong>Risk score: {score}/100 ({esc(summary.get('risk_label'))})</strong>
    <div class="score-bar"><div class="score-fill"></div></div>
  </div>
</header>

<div class="card"><h2>Overview</h2><div class="stats">{sev_counts}</div>
  <p class="meta">Scan ID {esc(record.scan_id)} &middot; SHA-256 <code>{esc(record.sha256)}</code> &middot; {esc(record.size_bytes)} bytes</p>
</div>

{_policy_section(data.get('policy') or {})}
{_medical_section(data.get('medical') or {})}
{_chain_section(data.get('attack_chains') or [], data.get('playbook') or [], data.get('compliance') or {})}
{_advanced_section(data.get('advanced') or {}, data.get('live_checks') or [])}
{_pki_section(data.get('pki') or {}, cert)}

<div class="card"><h2>Application metadata</h2><div class="kv">
  <div><span>Package</span>{esc(manifest.get('package'))}</div>
  <div><span>Version</span>{esc(manifest.get('version_name'))} ({esc(manifest.get('version_code'))})</div>
  <div><span>Min SDK</span>{esc(manifest.get('min_sdk'))}</div>
  <div><span>Target SDK</span>{esc(manifest.get('target_sdk'))}</div>
  <div><span>Debuggable</span>{esc(manifest.get('debuggable'))}</div>
  <div><span>Allow backup</span>{esc(manifest.get('allow_backup'))}</div>
  <div><span>Cleartext traffic</span>{esc(manifest.get('uses_cleartext_traffic'))}</div>
  <div><span>Signature scheme</span>{esc(', '.join(cert_schemes) or 'unknown')}</div>
  <div><span>Signer</span>{esc(signer.get('subject'))}</div>
  <div><span>Valid until</span>{esc(signer.get('valid_until'))}</div>
</div>
<p class="meta">{' &middot; '.join(esc(x) for x in comp_summary)}</p>
<p class="meta"><strong>Permissions ({len(perms)}):</strong> {esc(', '.join(perms))}</p>
</div>

<div class="card"><h2>Findings ({len(findings)})</h2>{finding_html}</div>

<div class="card"><h2>Software composition analysis</h2>
<table><thead><tr><th>Component</th><th>Version</th><th>Source</th><th>Evidence</th></tr></thead><tbody>{comp_rows}</tbody></table>
</div>

<div class="card"><h2>Dynamic analysis (DAST)</h2>
<p class="meta">Status: <strong>{esc(data.get('dast_status'))}</strong> &middot; Device: {esc(data.get('dast_info', {}).get('device_model') or 'n/a')} &middot; Android {esc(data.get('dast_info', {}).get('android_version') or 'n/a')}</p>
<table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>{dast_rows}</tbody></table>
</div>

<div class="card"><h2>Tool integration</h2>
<table><thead><tr><th>Tool</th><th>Available</th><th>Executed</th><th>Detail</th></tr></thead><tbody>{tools_rows}</tbody></table>
</div>

{_toolchain_section(data.get('toolchain') or [], data.get('emulator') or {}, data.get('patching') or {})}

<footer>Generated by APK Pentest Platform v1.0 &middot; For authorized security testing only. Findings are heuristic and require manual verification. Medical/standards sections are evidence mappings, not certifications.</footer>
</div></body></html>"""
