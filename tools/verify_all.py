"""Repeated in-process verification of every implemented feature.

Usage:
    python tools/verify_all.py --iterations 100

Each iteration parses the sample APK, runs SAST/SCA/custom/advanced/PKI/medical
engines, probes the advanced toolchain and lab gates, checks the tool-manager
catalog and install gates, checks DAST's no-device behaviour, evaluates policy
gates, confirms external finding imports are unlimited, generates the HTML
report, SBOM and SARIF exports, and diffs the record against a modified copy.
No network calls or device changes are made (OSV,
live checks, tool hooks, tool installs, proxy changes, browser opening,
local PKI lab writes and invasive workflows are disabled explicitly).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app import auth, config, pki_lab, tool_manager  # noqa: E402
from app.models import Component, DastCheck, Finding, ManifestSummary, ScanRecord, ScaFinding  # noqa: E402
from app.scanner.advanced import analyze_advanced  # noqa: E402
from app.scanner.apk import ApkPackage, find_all  # noqa: E402
from app.scanner.custom import load_custom_rules, run_custom_rules  # noqa: E402
from app.scanner.dast import DastResult, run_dast  # noqa: E402
from app.scanner.exports import cyclonedx_sbom, diff_scans, sarif_report, save_exports  # noqa: E402
from app.scanner.lab import (  # noqa: E402
    apply_proxy,
    emulator_status,
    open_mobsf_browser,
    run_patch_step,
)
from app.scanner.live import run_live_checks  # noqa: E402
from app.scanner.medical import analyze_medical  # noqa: E402
from app.scanner.pki import analyze_pki  # noqa: E402
from app.scanner.policy import evaluate_policy  # noqa: E402
from app.scanner.reporting import generate_html_report  # noqa: E402
from app.scanner.rules import is_benign_pki_string  # noqa: E402
from app.scanner.sast import SastContext, run_sast  # noqa: E402
from app.scanner.sca import run_sca  # noqa: E402
from app.scanner.toolchain import (  # noqa: E402
    _findings_from_payload,
    probe_toolchain,
    run_toolchain,
)


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def verify_iteration(index: int, apk_path: Path, work: Path) -> list[str]:
    failures: list[str] = []
    apk = ApkPackage(apk_path)
    try:
        summary = apk.manifest_summary()
        app_node = next(iter(find_all(apk.manifest, "application")), None)
        strings = apk.all_strings
        network_config = apk.network_security_config()

        sast = run_sast(SastContext(
            apk=apk, manifest=apk.manifest, summary=summary,
            network_config=network_config, app_node=app_node,
        ))
        pki_ctx = SastContext(
            apk=apk, manifest=apk.manifest, summary=summary,
            network_config=network_config, app_node=app_node,
            extra_strings=["keytool", "openssl", "apksigner", "a" * 64],
        )
        require(all(not pki_ctx.containing(token) for token in ("keytool", "openssl", "apksigner")),
                f"iteration {index}: PKI tool strings reached suspicious-string heuristics", failures)
        components, sca_findings, sca_meta = run_sca(strings, apk.names, online=False)
        custom = run_custom_rules(
            load_custom_rules(), strings=strings, summary=summary, apk_names=apk.names,
        )
        live_checks, live_findings = run_live_checks(strings, apk.sha256, enabled=False)
        all_findings = sast + custom + live_findings
        advanced = analyze_advanced(
            apk, summary, strings, apk.certificate,
            live_findings=live_findings, all_findings=all_findings,
        )
        all_findings += advanced.findings

        with patch.multiple(
            config,
            TOOLCHAIN_AUTO=False,
            TOOL_APKHUNT=False,
            TOOL_APKLEAKS=False,
            TOOL_APPSCAN=False,
            TOOL_FINDING_LIMIT=0,
            EMULATOR_AUTO=False,
            ALLOW_INVASIVE=False,
            BROWSER_OPEN_ENABLED=False,
            MOBSF_URL="",
            MOBSF_DYNAMIC_URL="",
            TOOL_MANAGER_ENABLED=False,
            PKI_LAB_ENABLED=False,
            PKI_DIR=work / "pki",
            TOOLS_ROOT=work / "tools",
            ANDROID_SDK_ROOT=work / "tools" / "android-sdk",
            INSTALLED_DB_PATH=work / "installed_tools.db",
            RMS_URL="",
            ZAP_WEB_URL="",
        ):
            toolchain = run_toolchain(apk_path, work, summary, network_config)
            lab_status = emulator_status()
            proxy_guard = apply_proxy("127.0.0.1", 8080)
            patch_guard = run_patch_step("patch-apk.py", apk_path, work, summary.get("package"))
            browser_guard = open_mobsf_browser()
            web_guard = tool_manager.open_web_ui("zaproxy")
            probe = probe_toolchain()
            pki = analyze_pki(apk.certificate, network_config)
            pki_guard = pki_lab.generate_ca()

            bulk_findings = _findings_from_payload(
                {
                    "findings": [
                        {
                            "id": f"verify-{index}",
                            "title": f"Shared verify title {index % 3}",
                            "severity": "low",
                            "evidence": f"evidence-{index}",
                        }
                        for index in range(150)
                    ]
                },
                "Verify",
            )
        require(len(bulk_findings) == 150,
                f"iteration {index}: external finding import is capped", failures)
        require(len(toolchain.tools) >= 16,
                f"iteration {index}: advanced toolchain probe incomplete", failures)
        require(all(not t.get("ran") for t in toolchain.tools),
                f"iteration {index}: tool hooks ran without opt-in", failures)
        require("authorized security testing only" in toolchain.lab.get("authorization", "").lower(),
                f"iteration {index}: lab authorization notice missing", failures)
        require(any(s["name"] == "APatch-root-system-modification"
                    for s in toolchain.patching.get("steps", [])),
                f"iteration {index}: patching plan missing APatch workflow", failures)
        addon = Path(toolchain.lab.get("artifacts", {}).get("mitm_addon", ""))
        require(addon.exists(), f"iteration {index}: mitmproxy addon not generated", failures)
        require(any(c["name"] == "set_android_proxy" for c in toolchain.lab.get("commands", [])),
                f"iteration {index}: lab proxy command missing", failures)
        require(proxy_guard["status"] == "skipped",
                f"iteration {index}: proxy change was not gated", failures)
        require(patch_guard["status"] == "skipped",
                f"iteration {index}: invasive patch was not gated", failures)
        require(browser_guard["status"] == "skipped",
                f"iteration {index}: browser launch was not gated", failures)
        require(web_guard["status"] == "skipped",
                f"iteration {index}: tool web UI launch was not gated", failures)
        require(pki_guard["status"] == "skipped",
                f"iteration {index}: local PKI lab was not gated", failures)
        require(pki["summary"]["finding_count"] == len(pki["findings"]),
                f"iteration {index}: PKI finding count mismatch", failures)
        require(pki["lab"]["device_installation"]["performed_by_platform"] is False,
                f"iteration {index}: PKI platform claims device CA installation", failures)
        require(all(f["severity"] == "info" for f in pki["findings"]),
                f"iteration {index}: PKI finding was treated as a threat", failures)
        require(all("not a malware" in f["description"] for f in pki["findings"]),
                f"iteration {index}: PKI finding lacks non-malware disposition", failures)
        require("not a malware/threat detection engine" in pki["notice"],
                f"iteration {index}: PKI notice lacks tooling disclaimer", failures)
        require(all(is_benign_pki_string(s) for s in ("keytool", "openssl", "apksigner", "a" * 64)),
                f"iteration {index}: benign PKI strings not recognised", failures)
        require(lab_status["emulator_auto"] is False and lab_status["invasive_allowed"] is False,
                f"iteration {index}: lab automation gates not closed during verification", failures)
        require(len(probe) >= 16, f"iteration {index}: tool probe list too short", failures)

        manager_catalog = tool_manager.catalog()
        manager_tools = {t["id"]: t for t in manager_catalog["tools"]}
        require(manager_catalog["enabled"] is False,
                f"iteration {index}: tool manager was enabled during verification", failures)
        require(len(manager_tools) >= 20,
                f"iteration {index}: tool-manager catalog incomplete", failures)
        require(all(tool_manager.safe_url(t["source_url"]) for t in manager_tools.values()),
                f"iteration {index}: tool-manager source outside the allowlist", failures)
        require(not tool_manager.safe_url("https://evil.example/tool.zip"),
                f"iteration {index}: arbitrary tool source was accepted", failures)
        require(all(manager_tools[name]["manual"] for name in ("burp", "zaproxy", "apatch", "keytool", "openssl")),
                f"iteration {index}: manual tools are marked auto-installable", failures)
        require(all(name in manager_tools for name in ("keytool", "openssl", "apksigner")),
                f"iteration {index}: PKI tool catalog entries missing", failures)
        require("pki" in manager_catalog and "device_installation" in manager_catalog["pki"],
                f"iteration {index}: PKI lab status missing from catalog", failures)
        require(all("installable" in t and "install_block_reason" in t for t in manager_tools.values()),
                f"iteration {index}: tool auto-install availability metadata missing", failures)
        require(all(not t["installable"] and t["actions"] == ["verify"]
                    for t in manager_tools.values() if t["manual"]),
                f"iteration {index}: manual tools expose auto-install actions", failures)
        require(all("install" not in t["actions"] for t in manager_tools.values() if t["installed"]),
                f"iteration {index}: installed tools still expose Install", failures)
        if sys.version_info >= (3, 15):
            require(all(not manager_tools[name]["installable"]
                        for name in ("semgrep", "mobsf")),
                    f"iteration {index}: unsupported pip tools remain auto-installable", failures)
        require("authorized security testing only" in manager_catalog["disclaimer"].lower(),
                f"iteration {index}: tool-manager authorization notice missing", failures)
        require("os" in manager_catalog and "source_policy" in manager_catalog,
                f"iteration {index}: tool-manager OS/source policy missing", failures)
        require(manager_catalog["source_policy"].get("transient_502_retries", 0) >= 1,
                f"iteration {index}: tool-manager 502 retry setting missing", failures)
        require("needs" in manager_catalog["emulator"],
                f"iteration {index}: tool-manager emulator needs missing", failures)
        require(all("web_open" in t for t in manager_tools.values()),
                f"iteration {index}: tool-manager web UI metadata missing", failures)
        group_ids = [group["id"] for group in manager_catalog["groups"]]
        require(group_ids == ["decode", "static", "device", "runtime", "dynamic", "proxy", "root"],
                f"iteration {index}: tool workflow groups are not in sequence", failures)
        require(all(t.get("icon") and t.get("group") in group_ids
                    for t in manager_catalog["tools"]),
                f"iteration {index}: tools are missing icons or workflow groups", failures)
        orders = [t["order"] for t in manager_catalog["tools"]]
        require(orders == sorted(orders),
                f"iteration {index}: tool catalog is not ordered by workflow", failures)
        shell_plan = tool_manager.parse_shell_command("apktool install")
        require(shell_plan == {"kind": "job", "tool_id": "apktool", "action": "install"},
                f"iteration {index}: shell command parser did not map install", failures)
        require(tool_manager.parse_shell_command("rm -rf /")["kind"] == "error",
                f"iteration {index}: shell accepted an arbitrary command", failures)
        log_samples = {
            "Downloading official release": "work",
            "Installed apktool 2.9.0": "ok",
            "HTTP 200 · https://api.github.com": "info",
            "WARNING: inventory sync failed": "low",
            "Connection timeout while downloading": "high",
            "ERROR: source host is not allowlisted": "critical",
        }
        for message, expected_level in log_samples.items():
            require(tool_manager.log_level(message) == expected_level,
                    f"iteration {index}: log colour for {message!r} was not {expected_level}", failures)
        coloured_logs = tool_manager.log_html(list(log_samples))
        require(all(f"op-{level}" in coloured_logs for level in set(log_samples.values())),
                f"iteration {index}: coloured job log HTML missing severity classes", failures)
        with patch.multiple(
            config,
            INSTALLED_DB_PATH=work / "installed_tools.db",
            TOOLS_ROOT=work / "tools",
            ANDROID_SDK_ROOT=work / "tools" / "android-sdk",
            TOOL_MANAGER_ENABLED=False,
            BROWSER_OPEN_ENABLED=False,
            MOBSF_URL="",
            MOBSF_DYNAMIC_URL="",
        ):
            manager_job = tool_manager.MANAGER.submit("apktool", "install", "verifier")
            require(manager_job.status == "skipped",
                    f"iteration {index}: tool-manager install was not gated", failures)
            dashboard_page = tool_manager.installed_dashboard_html()
        require("For authorized security testing only" in dashboard_page,
                f"iteration {index}: installed dashboard authorization notice missing", failures)
        require("Installed software dashboard" in dashboard_page,
                f"iteration {index}: installed dashboard title missing", failures)
        require("Tool access" in dashboard_page and 'data-group="decode"' in dashboard_page
                and "tool-card" in dashboard_page and "runToolAction" in dashboard_page,
                f"iteration {index}: grouped tool access missing from installed dashboard", failures)

        all_findings += pki["findings"]
        medical = analyze_medical(
            summary=summary,
            strings=strings,
            findings=all_findings,
            network_config=network_config,
        )
        require(medical["status"] == "enabled",
                f"iteration {index}: medical engine disabled", failures)
        require(medical["phi_present"],
                f"iteration {index}: medical indicators not detected", failures)
        require(medical["risk_level"] == "critical",
                f"iteration {index}: unexpected medical risk {medical['risk_level']}", failures)
        medical_ids = {f["id"] for f in medical["findings"]}
        for expected in ("MED-PHI-CLEARTEXT", "MED-PHI-BACKUP", "MED-TRACKER-PHI"):
            require(expected in medical_ids,
                    f"iteration {index}: missing medical finding {expected}", failures)
        require(medical["standards"]["gap_count"] > 0,
                f"iteration {index}: medical standards mapping empty", failures)
        require("not a certification" in medical["disclaimer"],
                f"iteration {index}: medical disclaimer missing", failures)
        all_findings.extend(medical["findings"])
        all_findings.extend(toolchain.findings)

        ids = {f["id"] for f in all_findings}
        for expected in (
            "SAST-DEBUGGABLE", "SAST-TLS-BYPASS", "SAST-WEAK-CRYPTO",
            "ADV-DEEPLINK-CUSTOM", "ADV-NSC-USER-CA", "ADV-PIN-EXPIRED",
            "ADV-TRACKERS", "ADV-PACKER", "ADV-ELF-HARDENING", "ADV-ANTI-ANALYSIS",
            "CUSTOM-DEBUG-ENDPOINT", "CUSTOM-PREMIUM-SMS", "CHAIN-WEBVIEW-TO-JAVA-RCE-CHAIN",
        ):
            require(expected in ids, f"iteration {index}: missing finding {expected}", failures)
        require(any(fid.startswith("PKI-") for fid in ids),
                f"iteration {index}: PKI analysis produced no findings", failures)
        require(bool(sca_findings), f"iteration {index}: SCA produced no findings", failures)
        require(sca_meta.get("online_lookup") is False, f"iteration {index}: online lookup not disabled", failures)
        require(any(c.get("name") == "WebView-to-Java RCE chain" for c in advanced.attack_chains),
                f"iteration {index}: WebView attack chain missing", failures)
        require(len(advanced.playbook) >= 5, f"iteration {index}: playbook too short", failures)
        require(advanced.compliance.get("controls_assessed", 0) > 0,
                f"iteration {index}: compliance mapping empty", failures)
        require(live_checks and live_checks[0]["status"] == "skipped",
                f"iteration {index}: live checks should be skipped", failures)

        if shutil.which("adb"):
            dast = DastResult(status="skipped", checks=[{
                "name": "device_availability", "status": "skipped",
                "detail": "Verification skipped DAST to avoid installing on a connected device.",
                "evidence": "",
            }])
        else:
            dast = run_dast(apk_path, summary, work, network_config=network_config)
        require(dast.status in ("skipped", "not_run"),
                f"iteration {index}: unexpected DAST status {dast.status}", failures)

        record = ScanRecord(scan_id=f"verify{index:08d}", filename=apk_path.name, sha256=apk.sha256)
        record.manifest = ManifestSummary.model_validate(
            {k: v for k, v in summary.items() if k in ManifestSummary.model_fields}
        )
        record.certificate = apk.certificate
        record.pki = {k: v for k, v in pki.items() if k != "findings"}
        record.findings = [Finding.model_validate(f) for f in all_findings + dast.findings]
        record.components = [Component.model_validate(c) for c in components]
        record.sca_findings = [ScaFinding.model_validate(f) for f in sca_findings]
        record.sca_meta = sca_meta
        record.advanced = {k: v for k, v in advanced.__dict__.items() if k != "findings"}
        record.attack_chains = advanced.attack_chains
        record.playbook = advanced.playbook
        record.compliance = advanced.compliance
        record.toolchain = toolchain.tools
        record.emulator = toolchain.lab
        record.patching = toolchain.patching
        record.medical = {k: v for k, v in medical.items() if k != "findings"}
        record.live_checks = live_checks
        record.custom_rules_applied = [r["id"] for r in load_custom_rules()]
        record.dast_status = dast.status
        record.dast_checks = [DastCheck.model_validate(c) for c in dast.checks]
        record.compute_summary()
        record.policy = evaluate_policy(record)
        with patch.object(config, "POLICY_MEDICAL_GAPS", 0):
            strict_policy = evaluate_policy(record)

        require(record.policy["status"] == "fail", f"iteration {index}: vulnerable sample passed policy", failures)
        require(record.policy["medical_gate"]["enabled"] is False,
                f"iteration {index}: medical gate should be disabled by default", failures)
        require(any(v["severity"] == "medical" for v in strict_policy["violations"]),
                f"iteration {index}: strict medical gate did not fire", failures)
        require(record.summary.total > 45, f"iteration {index}: too few findings", failures)

        html = generate_html_report(record)
        for needle in (
            "Advanced analysis", "Release policy gate", "Attack chains", "Deep links",
            "Medical / PHI analysis", "Advanced toolchain and interception lab",
            "PKI / certificate &amp; keystore",
            "not a malware or threat detection engine",
            "For authorized security testing only",
        ):
            require(needle in html, f"iteration {index}: report missing section {needle}", failures)

        sbom = cyclonedx_sbom(record)
        sarif = sarif_report(record)
        require(sbom["bomFormat"] == "CycloneDX", f"iteration {index}: invalid SBOM", failures)
        require(sarif["version"] == "2.1.0" and sarif["runs"][0]["results"],
                f"iteration {index}: invalid SARIF", failures)
        sbom_props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
        require(sbom_props.get("apkpt:medical:phi_present") == "true",
                f"iteration {index}: SBOM missing medical evidence", failures)
        require("Chromium / MobSF browser" in sbom_props.get("apkpt:toolchain:tools", ""),
                f"iteration {index}: SBOM missing toolchain evidence", failures)
        sarif_props = sarif["runs"][0]["properties"]
        require(sarif_props["medical"]["phi_present"] is True,
                f"iteration {index}: SARIF missing medical evidence", failures)
        require(any(t["name"] == "APKHunt" for t in sarif_props["toolchain"]),
                f"iteration {index}: SARIF missing toolchain evidence", failures)
        json.dumps(sbom)
        json.dumps(sarif)
        exports = save_exports(record.scan_id, record, work / "exports")
        require(Path(exports["sbom"]).exists() and Path(exports["sarif"]).exists(),
                f"iteration {index}: export files not written", failures)

        previous = record.model_copy(deep=True)
        previous.scan_id = f"previous{index:08d}"
        previous.findings = previous.findings[:-1]
        diff = diff_scans(record, previous)
        require(diff["counts"]["new"] == 1, f"iteration {index}: scan diff incorrect", failures)

        token = auth.create_token("admin", ttl_hours=1)
        require(auth.verify_token(token) == "admin", f"iteration {index}: auth token failed", failures)
    finally:
        apk.close()
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--apk", default=str(ROOT / "sample-vulnerable.apk"))
    args = parser.parse_args()

    apk_path = Path(args.apk).resolve()
    if not apk_path.exists():
        print(f"APK not found: {apk_path}")
        return 2

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="apkpt-verify-") as tmp:
        work = Path(tmp)
        for i in range(1, args.iterations + 1):
            failures.extend(verify_iteration(i, apk_path, work))
            if i % 10 == 0 or i == args.iterations:
                print(f"verified {i}/{args.iterations} iterations, failures={len(failures)}")

    if failures:
        print("\nFAILURES:")
        for failure in failures[:50]:
            print(" -", failure)
        if len(failures) > 50:
            print(f" ... and {len(failures) - 50} more")
        return 1
    print(f"\nSUCCESS: all {args.iterations} iterations passed every feature check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
