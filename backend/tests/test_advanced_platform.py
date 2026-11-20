"""Unit tests for the advanced platform features added after v1."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, config, pki_lab, tool_manager  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, ScanRecord  # noqa: E402
from app.scanner import custom as custom_rules_module  # noqa: E402
from app.scanner import sca as sca_module  # noqa: E402
from app.scanner import tools as tools_module  # noqa: E402
from app.scanner.advanced import (  # noqa: E402
    analyze_advanced,
    analyze_entropy,
    parse_elf,
    shannon_entropy,
)
from app.scanner.apk import ApkPackage, find_all  # noqa: E402
from app.scanner.bluetooth import analyze_bluetooth, bluetooth_lab_status  # noqa: E402
from app.scanner.custom import load_custom_rules, run_custom_rules, validate_rule  # noqa: E402
from app.scanner.exports import cyclonedx_sbom, diff_scans, sarif_report  # noqa: E402
from app.scanner.lab import (  # noqa: E402
    adb_command,
    apply_proxy,
    build_emulator_dast_plan,
    build_lab_plan,
    emulator_status,
    launch_emulator,
    open_mobsf_browser,
    run_patch_step,
    stop_emulator,
)
from app.scanner.live import run_live_checks  # noqa: E402
from app.scanner.medical import analyze_medical  # noqa: E402
from app.scanner.pki import analyze_pki  # noqa: E402
from app.scanner.pipeline import _dedupe  # noqa: E402
from app.scanner.policy import evaluate_policy  # noqa: E402
from app.scanner.reporting import generate_html_report  # noqa: E402
from app.scanner.rules import is_benign_pki_string  # noqa: E402
from app.scanner.sast import SastContext, run_sast  # noqa: E402
from app.scanner.toolchain import (  # noqa: E402
    _findings_from_payload,
    probe_toolchain,
    run_toolchain,
)

SAMPLE = ROOT / "sample-vulnerable.apk"


def _build_record(apk: ApkPackage) -> ScanRecord:
    summary = apk.manifest_summary()
    app_node = next(iter(find_all(apk.manifest, "application")), None)
    ctx = SastContext(
        apk=apk, manifest=apk.manifest, summary=summary,
        network_config=apk.network_security_config(), app_node=app_node,
    )
    sast = run_sast(ctx)
    custom = run_custom_rules(
        load_custom_rules(), strings=apk.all_strings, summary=summary, apk_names=apk.names,
    )
    live_checks, live_findings = run_live_checks(apk.all_strings, apk.sha256, enabled=False)
    advanced = analyze_advanced(
        apk, summary, apk.all_strings, apk.certificate,
        live_findings=live_findings, all_findings=sast + custom,
    )
    record = ScanRecord(
        scan_id="testscan00000001",
        filename=SAMPLE.name,
        sha256=apk.sha256,
        advanced={k: v for k, v in advanced.__dict__.items() if k != "findings"},
        attack_chains=advanced.attack_chains,
        playbook=advanced.playbook,
        compliance=advanced.compliance,
        live_checks=live_checks,
    )
    record.findings.extend([Finding.model_validate(f) for f in sast + custom + advanced.findings])
    record.compute_summary()
    record.policy = evaluate_policy(record)
    return record


class FindingLimitTests(unittest.TestCase):
    """The old 100-result cap is gone; distinct findings are never truncated."""

    @staticmethod
    def _payload(count: int) -> dict[str, Any]:
        return {
            "findings": [
                {
                    "id": f"id-{index}",
                    "title": f"Shared title {index % 3}",
                    "severity": "medium",
                    "evidence": f"evidence-{index}",
                    "description": f"description-{index}",
                }
                for index in range(count)
            ]
        }

    def test_payload_import_is_unlimited_by_default(self):
        with patch.object(config, "TOOL_FINDING_LIMIT", 0):
            findings = _findings_from_payload(self._payload(250), "TestTool")
        self.assertEqual(len(findings), 250)
        self.assertEqual(len({f["id"] for f in findings}), 250)

    def test_optional_cap_still_works_when_explicitly_set(self):
        with patch.object(config, "TOOL_FINDING_LIMIT", 7):
            findings = _findings_from_payload(self._payload(250), "TestTool")
        self.assertEqual(len(findings), 7)

    def test_dedupe_preserves_distinct_occurrences(self):
        findings = [
            {
                "id": "SAST-REPEATED",
                "title": "Repeated rule",
                "severity": "medium",
                "description": "same rule",
                "evidence": f"line {index}",
                "location": f"File.java:{index}",
            }
            for index in range(120)
        ]
        self.assertEqual(len(_dedupe(findings)), 120)
        self.assertEqual(len(_dedupe([findings[0], dict(findings[0])])), 1)

    def test_semgrep_results_are_not_capped(self):
        results = [
            {
                "check_id": "rules.repeated",
                "path": f"File{index}.java",
                "start": {"line": index + 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "repeated semgrep rule",
                    "lines": f"value-{index}",
                },
            }
            for index in range(250)
        ]
        log = json.dumps({"results": results})
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            java_source = work / "src"
            java_source.mkdir()
            with patch.multiple(
                tools_module,
                TOOL_SEMGREP=True,
                TOOL_FINDING_LIMIT=0,
            ), patch.object(tools_module, "_which", return_value="semgrep"), patch.object(
                tools_module, "_run", return_value=(0, log),
            ):
                outcome = tools_module.run_semgrep(Path("sample.apk"), work, java_source)
        self.assertEqual(len(outcome.findings), 250)
        self.assertEqual(len({f["id"] for f in outcome.findings}), 250)

    def test_sca_advisories_are_not_capped(self):
        db = {
            "_version": "test",
            "components": [
                {
                    "name": "libtest",
                    "markers": ["libtest-1.0"],
                    "native_libraries": [],
                    "version_patterns": [r"libtest-([0-9.]+)"],
                    "osv_name": "libtest",
                    "ecosystem": "Maven",
                    "vulnerabilities": [
                        {
                            "id": f"TEST-VULN-{index}",
                            "title": f"Advisory {index}",
                            "severity": "medium",
                            "fixed_in": "9.0",
                            "description": "test advisory",
                            "remediation": "upgrade",
                        }
                        for index in range(120)
                    ],
                }
            ],
        }
        with patch.object(sca_module, "load_vuln_db", return_value=db), patch.object(
            sca_module, "TOOL_FINDING_LIMIT", 0,
        ):
            _components, findings, _meta = sca_module.run_sca(
                ["libtest-1.0"], [], online=False,
            )
        self.assertEqual(len(findings), 120)


class PkiTests(unittest.TestCase):
    """Passive certificate analysis and local-only, gated lab material."""

    @staticmethod
    def _certificate() -> dict[str, Any]:
        return {
            "v1_signature": True,
            "v2_or_v3_signature": False,
            "signers": [{
                "subject": "CN=Android Debug,O=Android",
                "issuer": "CN=Android Debug,O=Android",
                "serial_hex": "0x1",
                "valid_from": "2020-01-01T00:00:00+00:00",
                "valid_until": "2021-01-01T00:00:00+00:00",
                "signature_algorithm": "SHA1withRSA",
                "public_key_algorithm": "RSA",
                "key_size": 1024,
                "sha256_fingerprint": "ab" * 32,
                "basic_constraints_ca": True,
                "self_signed": True,
            }],
            "parse_error": None,
        }

    def test_passive_analysis_produces_pki_findings(self):
        network = {
            "resource": "res/xml/network_security_config.xml",
            "cleartext_traffic_permitted": True,
            "pinning_configured": False,
            "trust_user_certs_debug_only": True,
            "domains": [],
        }
        result = analyze_pki(self._certificate(), network)
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("PKI-WEAK_SIGNATURE_ALGORITHM-1", ids)
        self.assertIn("PKI-SMALL_RSA_KEY-1", ids)
        self.assertIn("PKI-EXPIRED-1", ids)
        self.assertIn("PKI-CA_CERTIFICATE_USED_AS_APP_SIGNER-1", ids)
        self.assertIn("PKI-V1-ONLY", ids)
        self.assertIn("PKI-USER-CA-TRUSTED", ids)
        self.assertIn("PKI-CLEARTEXT-PERMITTED", ids)
        self.assertTrue(all(f["category"] == "PKI" for f in result["findings"]))
        self.assertEqual(result["summary"]["signer_count"], 1)
        self.assertEqual(result["summary"]["finding_count"], len(result["findings"]))
        self.assertIn("For authorized security testing only", result["notice"])

    def test_pki_findings_are_informational_only(self):
        result = analyze_pki(self._certificate(), {
            "cleartext_traffic_permitted": True,
            "trust_user_certs_debug_only": True,
        })
        self.assertTrue(result["findings"])
        self.assertTrue(all(f["severity"] == "info" for f in result["findings"]))
        self.assertTrue(all("not a malware" in f["description"] for f in result["findings"]))
        self.assertIn("not a malware", result["notice"])
        self.assertIn("not a malware/threat detection engine", result["notice"])

    def test_policy_never_counts_pki_findings(self):
        record = ScanRecord(scan_id="pkipolicy0000001", filename="pki.apk")
        record.findings = [
            Finding(id="PKI-FORCED-HIGH", title="forced high", severity="high", category="PKI")
        ]
        policy = evaluate_policy(record, thresholds={
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        })
        self.assertEqual(policy["status"], "pass")
        self.assertEqual(policy["actual"]["high"], 0)
        self.assertEqual(policy["pki_findings_excluded"], 1)

    def test_pki_tool_strings_are_excluded_from_sast_heuristics(self):
        apk = ApkPackage(SAMPLE)
        benign = ["keytool", "openssl", "apksigner", "keystore", "a" * 64]
        ctx = SastContext(
            apk=apk, manifest={}, summary={}, network_config=None, app_node=None,
            extra_strings=benign,
        )
        self.assertTrue(all(is_benign_pki_string(s) for s in benign))
        for token in ("keytool", "openssl", "apksigner"):
            self.assertEqual(ctx.containing(token), [])

    def test_report_includes_pki_section(self):
        result = analyze_pki(self._certificate(), None)
        record = ScanRecord(
            scan_id="pkitest000000001",
            filename="pki.apk",
            certificate=self._certificate(),
            pki={k: v for k, v in result.items() if k != "findings"},
        )
        html = generate_html_report(record)
        self.assertIn("PKI / certificate &amp; keystore", html)
        self.assertIn("SHA1withRSA", html)
        self.assertIn("Device CA installation is never performed", html)
        self.assertIn("not a malware or threat detection engine", html)

    def test_lab_gate_and_local_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab_dir = Path(tmp) / "pki"
            with patch.object(config, "PKI_LAB_ENABLED", False), patch.object(config, "PKI_DIR", lab_dir):
                blocked = pki_lab.generate_ca()
            self.assertEqual(blocked["status"], "skipped")
            self.assertIn("APKPT_PKI_LAB", blocked["detail"])
            self.assertFalse(lab_dir.exists())

            with patch.object(config, "PKI_LAB_ENABLED", True), patch.object(config, "PKI_DIR", lab_dir):
                ca = pki_lab.generate_ca("APKPT Unit Test CA", days=30)
                self.assertEqual(ca["status"], "completed")
                self.assertTrue(pki_lab.ca_cert_path().is_file())
                self.assertTrue(pki_lab.ca_key_path().is_file())
                details = ca["ca"]["details"]
                self.assertEqual(details["subject"], "CN=APKPT Unit Test CA,O=APKPT Authorized Test Lab")
                self.assertTrue(details["self_signed"])
                keystore = pki_lab.generate_keystore("unit-lab")
                self.assertEqual(keystore["status"], "completed")
                self.assertTrue(pki_lab.keystore_path().is_file())
                self.assertTrue(keystore["keystore"]["ca_signed"])
                status = pki_lab.status()
                self.assertTrue(status["enabled"])
                self.assertFalse(status["device_installation"]["performed_by_platform"])
                self.assertNotIn("password", status["keystore"])

    def test_pki_api_is_audited_and_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab_dir = Path(tmp) / "pki"
            with patch.object(config, "AUTH_ENABLED", True), \
                 patch.object(config, "AUDIT_LOG", Path(tmp) / "audit.log"), \
                 patch.object(config, "PKI_LAB_ENABLED", True), \
                 patch.object(config, "PKI_DIR", lab_dir):
                with TestClient(app) as client:
                    status = client.get("/api/pki/status")
                    self.assertEqual(status.status_code, 200)
                    self.assertFalse(status.json()["device_installation"]["performed_by_platform"])
                    self.assertEqual(client.post("/api/pki/ca/generate", json={"confirm": True}).status_code, 401)
                    token = auth.create_token("admin", ttl_hours=1)
                    headers = {"Authorization": f"Bearer {token}"}
                    self.assertEqual(client.post(
                        "/api/pki/ca/generate", json={"confirm": False}, headers=headers,
                    ).status_code, 400)
                    generated = client.post(
                        "/api/pki/ca/generate", json={"confirm": True, "common_name": "API Test CA"},
                        headers=headers,
                    )
                    self.assertEqual(generated.status_code, 200)
                    self.assertEqual(generated.json()["status"], "completed")
                    audit = (Path(tmp) / "audit.log").read_text(encoding="utf-8")
                    self.assertIn("pki.ca.generate", audit)


class AdvancedFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not SAMPLE.exists():
            raise unittest.SkipTest("sample-vulnerable.apk not generated")
        cls.apk = ApkPackage(SAMPLE)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.apk.close()

    def test_deep_links_and_network_config(self):
        summary = self.apk.manifest_summary()
        advanced = analyze_advanced(self.apk, summary, self.apk.all_strings, self.apk.certificate)
        schemes = {link["scheme"] for link in advanced.deep_links}
        self.assertIn("insecureapp", schemes)
        self.assertTrue(any(link["auto_verified"] for link in advanced.deep_links))
        self.assertTrue(advanced.network_config_detail["user_ca_trusted"])
        self.assertTrue(advanced.network_config_detail["expired_pins"])

    def test_trackers_packer_and_elf(self):
        summary = self.apk.manifest_summary()
        advanced = analyze_advanced(self.apk, summary, self.apk.all_strings, self.apk.certificate)
        self.assertGreaterEqual(len(advanced.trackers), 2)
        self.assertTrue(advanced.apkid["packers_or_obfuscators"])
        self.assertTrue(advanced.elf_hardening)
        self.assertTrue(advanced.elf_hardening[0]["nx_stack"])

    def test_elf_parser_and_entropy_helpers(self):
        elf = parse_elf((self.apk.read("lib/arm64-v8a/libfoo.so")))
        self.assertEqual(elf.get("class"), "ELF64")
        self.assertTrue(elf.get("pie"))
        self.assertGreater(shannon_entropy("aAbB0123!@#xyzXYZ"), 3.0)

    def test_custom_rules(self):
        rules = load_custom_rules()
        ids = {r["id"] for r in rules}
        self.assertTrue(ids)
        findings = run_custom_rules(
            rules, strings=self.apk.all_strings,
            summary=self.apk.manifest_summary(), apk_names=self.apk.names,
        )
        fids = {f["id"] for f in findings}
        self.assertIn("CUSTOM-DEBUG-ENDPOINT", fids)
        self.assertIn("CUSTOM-PREMIUM-SMS", fids)
        with self.assertRaises(ValueError):
            validate_rule({"id": "bad", "title": "bad", "pattern": "["})

    def test_policy_exports_diff_and_report(self):
        record = _build_record(self.apk)
        self.assertEqual(record.policy["status"], "fail")
        self.assertTrue(any(c["name"] == "WebView-to-Java RCE chain" for c in record.attack_chains))
        html = generate_html_report(record)
        for needle in ("Advanced analysis", "Release policy gate", "Attack chains", "Custom:"):
            self.assertIn(needle, html)
        sbom = cyclonedx_sbom(record)
        sarif = sarif_report(record)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertGreaterEqual(len(sbom["vulnerabilities"]), 0)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreater(sarif["runs"][0]["results"].__len__(), 0)
        with tempfile.TemporaryDirectory() as tmp:
            record.scan_id = "export1"
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps(sbom), encoding="utf-8")
            self.assertTrue(path.exists())
        previous = record.model_copy(deep=True)
        previous.scan_id = "previous"
        previous.findings = previous.findings[:-1]
        diff = diff_scans(record, previous)
        self.assertEqual(diff["counts"]["new"], 1)

    def test_live_checks_disabled(self):
        checks, findings = run_live_checks(self.apk.all_strings, self.apk.sha256, enabled=False)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "skipped")
        self.assertEqual(findings, [])

    def test_auth_token_roundtrip(self):
        token = auth.create_token("admin", ttl_hours=1)
        self.assertEqual(auth.verify_token(token), "admin")
        self.assertIsNone(auth.verify_token(token + "tampered"))

    def test_api_auth_guard_and_rule_crud(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.json"
            with patch.object(config, "AUTH_ENABLED", True), \
                 patch.object(config, "AUDIT_LOG", Path(tmp) / "audit.log"), \
                 patch.object(custom_rules_module, "CUSTOM_RULES_PATH", rules_path):
                with TestClient(app) as client:
                    self.assertEqual(client.get("/api/health").status_code, 200)
                    self.assertEqual(client.get("/health").status_code, 200)
                    self.assertEqual(client.get("/healthz").status_code, 200)
                    self.assertEqual(client.post("/api/rules", json={
                        "id": "API-TEST", "title": "t", "pattern": "t",
                    }).status_code, 401)
                    token = auth.create_token("admin", ttl_hours=1)
                    headers = {"Authorization": f"Bearer {token}"}
                    self.assertEqual(client.post("/api/rules", json={
                        "id": "API-TEST", "title": "t", "pattern": "t",
                    }, headers=headers).status_code, 200)
                    self.assertIn("API-TEST", [r["id"] for r in client.get("/api/rules").json()])
                    self.assertEqual(client.request("DELETE", "/api/rules", json={
                        "rule_id": "API-TEST",
                    }, headers=headers).status_code, 200)
                    self.assertTrue((Path(tmp) / "audit.log").exists())

    def test_medical_analysis_and_policy_gate(self):
        summary = self.apk.manifest_summary()
        network_config = self.apk.network_security_config()
        sast = run_sast(SastContext(
            apk=self.apk, manifest=self.apk.manifest, summary=summary,
            network_config=network_config,
            app_node=next(iter(find_all(self.apk.manifest, "application")), None),
        ))
        medical = analyze_medical(
            summary=summary, strings=self.apk.all_strings, findings=sast,
            network_config=network_config,
        )
        self.assertEqual(medical["status"], "enabled")
        self.assertTrue(medical["phi_present"])
        self.assertEqual(medical["risk_level"], "critical")
        finding_ids = {f["id"] for f in medical["findings"]}
        self.assertIn("MED-PHI-CLEARTEXT", finding_ids)
        self.assertIn("MED-PHI-BACKUP", finding_ids)
        self.assertGreater(medical["standards"]["gap_count"], 0)
        self.assertIn("not a certification", medical["disclaimer"])

        record = _build_record(self.apk)
        record.medical = {k: v for k, v in medical.items() if k != "findings"}
        record.findings.extend([Finding.model_validate(f) for f in medical["findings"]])
        record.compute_summary()
        with patch.object(config, "POLICY_MEDICAL_GAPS", 0):
            policy = evaluate_policy(record)
        self.assertEqual(policy["status"], "fail")
        self.assertTrue(any(v["severity"] == "medical" for v in policy["violations"]))

    def test_toolchain_lab_and_invasive_gates(self):
        package = "com.example.insecure.demo"
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with patch.multiple(
                config,
                TOOLCHAIN_AUTO=False,
                TOOL_APKHUNT=False,
                TOOL_APKLEAKS=False,
                TOOL_APPSCAN=False,
                EMULATOR_AUTO=False,
                ALLOW_INVASIVE=False,
                BROWSER_OPEN_ENABLED=False,
                MOBSF_URL="",
                MOBSF_DYNAMIC_URL="",
            ):
                tools = probe_toolchain()
                chain = run_toolchain(
                    SAMPLE, work, {"package": package},
                    {"user_ca_trusted": False, "cleartext_enabled": True, "pin_sets": [{}]},
                )
                lab = build_lab_plan(
                    SAMPLE, work, package, {"user_ca_trusted": False, "cleartext_enabled": True},
                )
                proxy = apply_proxy("127.0.0.1", 8080)
                patch_result = run_patch_step("patch-apk.py", SAMPLE, work, package)
                browser = open_mobsf_browser()
            self.assertGreaterEqual(len(tools), 16)
            self.assertTrue(all(not t["ran"] for t in chain.tools))
            steps = {s["name"]: s for s in chain.patching["steps"]}
            for name in (
                "patch-apk.py", "objection-frida-injection", "manual-smali-patching",
                "APatch-root-system-modification", "ReC-Manager", "RMS-runtime-mobile-security",
                "mod-translate-app",
            ):
                self.assertIn(name, steps)
            self.assertEqual(steps["network-security-config-patch"]["status"], "manual")
            self.assertFalse(chain.patching["executable"])
            self.assertTrue((work / "lab" / "apkpt_mitm_addon.py").exists())
            self.assertTrue(any(c["name"] == "set_android_proxy" for c in chain.lab["commands"]))
            self.assertTrue(any("user CAs" in n for n in chain.lab["network_security_notes"]))
            self.assertEqual(proxy["status"], "skipped")
            self.assertEqual(patch_result["status"], "skipped")
            self.assertEqual(browser["status"], "skipped")
            self.assertIn("authorized security testing only", lab["authorization"].lower())

        with patch.object(config, "MOBSF_URL", "http://127.0.0.1:8000/mobsf"), \
             patch.object(config, "BROWSER_OPEN_ENABLED", False):
            hostile = open_mobsf_browser("http://127.0.0.1:8000.mobsf.example")
        self.assertEqual(hostile["status"], "error")

    def test_report_includes_medical_and_lab_sections(self):
        record = _build_record(self.apk)
        medical = analyze_medical(
            summary=self.apk.manifest_summary(),
            strings=self.apk.all_strings,
            findings=[f.model_dump() for f in record.findings],
            network_config=self.apk.network_security_config(),
        )
        record.medical = {k: v for k, v in medical.items() if k != "findings"}
        record.toolchain = probe_toolchain()
        with tempfile.TemporaryDirectory() as tmp:
            lab = build_lab_plan(
                SAMPLE, Path(tmp), record.manifest.package,
                {"user_ca_trusted": False, "cleartext_enabled": True},
            )
        record.emulator = lab
        record.patching = lab["patching"]
        html = generate_html_report(record)
        for needle in (
            "Medical / PHI analysis", "Advanced toolchain and interception lab",
            "Generated lab commands", "Patch / instrumentation workflows",
            "For authorized security testing only", "not certifications",
        ):
            self.assertIn(needle, html)

    def test_api_health_config_and_lab_endpoints(self):
        with patch.multiple(
            config,
            EMULATOR_AUTO=False,
            ALLOW_INVASIVE=False,
            BROWSER_OPEN_ENABLED=False,
            MOBSF_URL="",
            MOBSF_DYNAMIC_URL="",
            TOOL_FINDING_LIMIT=0,
        ):
            with TestClient(app) as client:
                health = client.get("/api/health").json()
                self.assertIn("medical", health["engines"])
                self.assertIn("toolchain", health["engines"])
                self.assertGreaterEqual(len(health["toolchain"]), 16)
                self.assertEqual(health["limits"]["finding_limit"], 0)
                cfg = client.get("/api/config").json()
                self.assertIn("medical", cfg)
                self.assertIn("lab", cfg)
                self.assertTrue(cfg["limits"]["finding_limit_unlimited"])
                self.assertEqual(client.get("/api/tools/advanced").status_code, 200)
                self.assertEqual(client.get("/api/lab/status").status_code, 200)

    def test_java_runtime_override(self):
        with patch.dict(os.environ, {"APKPT_JAVA_CMD": r"C:\java\bin\java.exe"}):
            data = tool_manager.catalog()
        self.assertEqual(
            data["emulator"]["needs"]["java_runtime"],
            r"Installed: C:\java\bin\java.exe",
        )

    def test_tool_web_ports_are_dedicated_and_opt_in(self):
        with patch.dict(os.environ, {}, clear=False):
            for key in list(config.TOOL_WEB_PORT_ENV.values()) + list(config.TOOL_WEB_URL_ENV.values()):
                os.environ.pop(key, None)
            self.assertEqual(
                config._configured_web_url("APKPT_MOBSF_URL", "APKPT_MOBSF_PORT", "mobsf"), ""
            )
            os.environ["APKPT_MOBSF_PORT"] = "8001"
            self.assertEqual(
                config._configured_web_url("APKPT_MOBSF_URL", "APKPT_MOBSF_PORT", "mobsf"),
                "http://127.0.0.1:8001",
            )
            os.environ["APKPT_MOBSF_URL"] = "http://127.0.0.1:9999"
            self.assertEqual(
                config._configured_web_url("APKPT_MOBSF_URL", "APKPT_MOBSF_PORT", "mobsf"),
                "http://127.0.0.1:9999",
            )
        with patch.dict(os.environ, {"APKPT_MOBSF_PORT": "not-a-port"}):
            with self.assertRaises(ValueError):
                config._tool_port("APKPT_MOBSF_PORT", 8001)

        with patch.object(config, "TOOL_WEB_AUTO_ACTIVE", True):
            for tool_key, url_env, port_env, expected_port in (
                ("mobsf", "APKPT_MOBSF_URL", "APKPT_MOBSF_PORT", 8001),
                ("mobsf_dynamic", "APKPT_MOBSF_DYNAMIC_URL", "APKPT_MOBSF_DYNAMIC_PORT", 8002),
                ("apkhunt", "APKPT_APKHUNT_URL", "APKPT_APKHUNT_PORT", 8003),
                ("rms", "APKPT_RMS_URL", "APKPT_RMS_PORT", 8004),
                ("zaproxy", "APKPT_ZAP_WEB_URL", "APKPT_ZAP_WEB_PORT", 8005),
            ):
                with patch.dict(os.environ, {}, clear=False):
                    for key in (url_env, port_env):
                        os.environ.pop(key, None)
                    self.assertEqual(
                        config._configured_web_url(url_env, port_env, tool_key),
                        f"http://127.0.0.1:{expected_port}",
                    )
                    self.assertEqual(config._configured_web_port(port_env, tool_key), expected_port)

        status = tool_manager.web_ports_status()
        self.assertEqual(status["recommended"]["platform"], 8000)
        self.assertEqual(status["recommended"]["mobsf"], 8001)
        self.assertEqual(status["recommended"]["mobsf_dynamic"], 8002)
        self.assertEqual(status["recommended"]["apkhunt"], 8003)
        self.assertEqual(status["recommended"]["rms"], 8004)
        self.assertEqual(status["recommended"]["zaproxy"], 8005)
        self.assertEqual(len(set(status["recommended"].values())), len(status["recommended"]))
        self.assertIn("auto_enabled", status)
        self.assertIn("auto_active", status)
        self.assertEqual(status["auto_trigger_port"], 8000)
        self.assertIn("web_ports", tool_manager.catalog())

    def test_tool_manager_catalog_sources_and_gates(self):
        data = tool_manager.catalog()
        tools = {t["id"]: t for t in data["tools"]}
        self.assertFalse(data["enabled"])
        self.assertGreaterEqual(len(tools), 20)
        for expected in (
            "apktool", "jadx", "platform-tools", "cmdline-tools", "aapt2",
            "apksigner", "keytool", "openssl",
            "apkleaks", "apkhunt", "objection", "frida-tools", "mitmproxy",
            "semgrep", "mobsf", "patch-apk", "trashdroid", "rms",
            "zaproxy", "burp", "apatch", "recmanager", "chromium",
            "drozer", "androguard", "apkid", "qark",
            "ghidra", "radare2", "class-dump",
            "internalblue", "ubertooth", "nrf-sniffer", "aircrack-ng",
            "bettercap", "kismet", "hcxtools", "wireshark",
            "ipsw", "ios-deploy", "libimobiledevice",
            "binwalk", "unblob", "uefitool", "chipsec", "flashrom",
            "fwupd", "u-boot", "hashcat",
        ):
            self.assertIn(expected, tools)
        self.assertTrue(all(tool_manager.safe_url(t["source_url"]) for t in tools.values()))
        self.assertIn("api.github.com", data["allowed_hosts"])
        self.assertIn("dl.google.com", data["allowed_hosts"])
        self.assertEqual(set(data["allowed_hosts"]), set(tool_manager.ALLOWED_HOSTS))
        self.assertEqual(data["source_policy"]["allowed_hosts"], data["allowed_hosts"])
        self.assertEqual(data["source_policy"]["config_env"], "APKPT_TOOL_ALLOWED_HOSTS")
        self.assertIn("system", data["os"])
        self.assertIn("java_runtime", data["emulator"]["needs"])
        self.assertTrue(all("web_open" in t for t in tools.values()))
        self.assertEqual([group["id"] for group in data["groups"]], [
            "decode", "static", "device", "runtime", "dynamic", "proxy", "root",
        ])
        self.assertTrue(all("icon" in t and t["icon"] for t in tools.values()))
        self.assertTrue(all("group" in t and "order" in t for t in tools.values()))
        orders = [t["order"] for t in data["tools"]]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(tools["recmanager"]["group"], "root")
        self.assertTrue(all(group["count"] > 0 for group in data["groups"]))
        self.assertEqual(set(tool_manager.ALLOWED_HOSTS), set(config.TOOL_ALLOWED_HOSTS))
        self.assertFalse(tool_manager.safe_url("https://evil.example/repo.git"))
        self.assertFalse(tool_manager.safe_url("http://api.github.com/repos"))

        self.assertEqual(tools["apksigner"]["group"], "runtime")
        self.assertIn("pki", data)
        self.assertIn("authorization", data["pki"])
        self.assertIn("device_installation", data["pki"])
        manual = {k: v for k, v in tools.items() if v["manual"]}
        self.assertIn("burp", manual)
        self.assertEqual(manual["burp"]["actions"], ["verify"])
        for pki_tool_id in ("keytool", "openssl"):
            self.assertIn(pki_tool_id, manual)
            self.assertEqual(manual[pki_tool_id]["actions"], ["verify"])
        self.assertTrue(tool_manager.safe_url(tools["keytool"]["source_url"]))
        self.assertTrue(tool_manager.safe_url(tools["openssl"]["source_url"]))
        self.assertTrue(tool_manager.safe_url(tools["apksigner"]["source_url"]))
        self.assertTrue(tools["patch-apk"]["invasive"])
        self.assertIn("pull", tools["apkhunt"]["actions"])
        self.assertNotIn("pull", tools["apktool"]["actions"])
        self.assertTrue(all("installable" in t and "install_block_reason" in t for t in tools.values()))
        self.assertTrue(all(not t["installable"] and t["install_block_reason"] for t in manual.values()))
        self.assertEqual(
            tool_manager._job_outcome({"status": "skipped", "detail": "unsupported"}, "fallback"),
            ("skipped", "unsupported"),
        )
        self.assertEqual(
            tool_manager._job_outcome({"status": "error", "detail": "boom"}, "fallback"),
            ("failed", "boom"),
        )
        self.assertEqual(
            tool_manager._job_outcome({"status": "installed", "version": "1.2"}, "fallback"),
            ("completed", "version 1.2"),
        )
        self.assertEqual(
            tool_manager._job_outcome(
                {"tools": [{"status": "installed"}, {"status": "skipped", "detail": "manual"}]},
                "fallback",
            ),
            ("completed", "1 installed, 1 skipped · manual"),
        )
        self.assertEqual(
            tool_manager._auto_install_block(tool_manager.SPEC_BY_ID["apktool"]),
            "",
        )
        self.assertTrue(tool_manager._auto_install_block(tool_manager.SPEC_BY_ID["burp"]))
        with patch.object(sys, "version_info", (3, 15, 0)):
            semgrep_block = tool_manager._auto_install_block(tool_manager.SPEC_BY_ID["semgrep"])
            self.assertIn("Auto-install is unavailable", semgrep_block)
            for tool_id in ("semgrep", "mobsf", "drozer", "androguard"):
                result = tool_manager._run_tool_action(
                    tool_manager.SPEC_BY_ID[tool_id], "install", lambda _line: None,
                )
                self.assertEqual(result["status"], "skipped")
                self.assertIn("Auto-install is unavailable", result["detail"])
                blocked_tools = {t["id"]: t for t in tool_manager.catalog()["tools"]}
                self.assertFalse(blocked_tools[tool_id]["installable"])
                self.assertEqual(blocked_tools[tool_id]["actions"], ["verify"])
        with patch.object(tool_manager, "_installed_version", return_value=(True, "1.0", "/fake/tool")):
            installed_tools = {t["id"]: t for t in tool_manager.catalog()["tools"]}
            self.assertNotIn("install", installed_tools["platform-tools"]["actions"])
            self.assertIn("update", installed_tools["platform-tools"]["actions"])

        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config,
                TOOL_MANAGER_ENABLED=False,
                TOOLS_ROOT=Path(tmp) / "tools",
                ANDROID_SDK_ROOT=Path(tmp) / "tools" / "android-sdk",
                INSTALLED_DB_PATH=Path(tmp) / "installed_tools.db",
            ):
                job = tool_manager.MANAGER.submit("apktool", "install", "unit-test")
                self.assertEqual(job.status, "skipped")
                self.assertIn("APKPT_TOOL_MANAGER", job.detail)
                self.assertTrue(job.logs)
                with self.assertRaises(ValueError):
                    tool_manager.MANAGER.submit("not-a-tool", "install", "unit-test")
                with self.assertRaises(ValueError):
                    tool_manager.MANAGER.submit("all", "explode", "unit-test")

    def test_obsolete_manager_disabled_jobs_are_archived_and_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config,
                TOOL_MANAGER_ENABLED=True,
                TOOLS_ROOT=Path(tmp) / "tools",
                INSTALLED_DB_PATH=Path(tmp) / "installed_tools.db",
            ):
                manager = tool_manager.JobManager()
                jobs_dir = tool_manager._jobs_dir()
                stale = {
                    "job_id": "stale-unit-job",
                    "tool_id": "apktool",
                    "action": "install",
                    "actor": "unit-test",
                    "status": "skipped",
                    "detail": tool_manager.DISABLED_MANAGER_DETAIL,
                    "started_at": "2026-11-18T18:59:44+00:00",
                    "logs": [f"[18:59:44] {tool_manager.DISABLED_MANAGER_DETAIL}"],
                    "result": {},
                }
                active = {
                    "job_id": "active-unit-job",
                    "tool_id": "apktool",
                    "action": "verify",
                    "actor": "unit-test",
                    "status": "completed",
                    "detail": "tool present",
                    "started_at": "2026-11-19T10:00:00+00:00",
                    "logs": ["[10:00:00] tool present"],
                    "result": {"status": "ok"},
                }
                (jobs_dir / "stale-unit-job.json").write_text(
                    json.dumps(stale), encoding="utf-8",
                )
                (jobs_dir / "active-unit-job.json").write_text(
                    json.dumps(active), encoding="utf-8",
                )

                self.assertEqual(manager.archive_obsolete_jobs(), 1)
                self.assertEqual([p.name for p in jobs_dir.glob("*.json")],
                                 ["active-unit-job.json"])
                self.assertTrue(list((jobs_dir / "archive").glob("*/*.json")))
                self.assertEqual([job.job_id for job in manager.list()],
                                 ["active-unit-job"])

    def test_tool_manager_api_endpoints_are_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config,
                TOOL_MANAGER_ENABLED=False,
                TOOLS_ROOT=Path(tmp) / "tools",
                ANDROID_SDK_ROOT=Path(tmp) / "tools" / "android-sdk",
                INSTALLED_DB_PATH=Path(tmp) / "installed_tools.db",
                BROWSER_OPEN_ENABLED=False,
                MOBSF_URL="",
                MOBSF_DYNAMIC_URL="",
            ), TestClient(app) as client:
                catalog = client.get("/api/tools/catalog")
                self.assertEqual(catalog.status_code, 200)
                self.assertFalse(catalog.json()["enabled"])
                self.assertEqual(client.get("/api/tools/jobs").status_code, 200)
                for path in (
                    "/api/tools/install-all",
                    "/api/tools/update-all",
                    "/api/tools/emulator/install",
                ):
                    response = client.post(path, json={"confirm": True})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["status"], "skipped")
                single = client.post("/api/tools/apktool/install", json={"confirm": True})
                self.assertEqual(single.status_code, 200)
                self.assertEqual(single.json()["status"], "skipped")
                self.assertEqual(client.post("/api/tools/apktool/install", json={"confirm": False}).status_code, 400)
                invalid = client.post("/api/tools/does-not-exist/install", json={"confirm": True})
                self.assertEqual(invalid.status_code, 400)
                self.assertEqual(client.get("/api/tools/jobs/not-a-real-job").status_code, 404)
                installed = client.get("/api/tools/installed")
                self.assertEqual(installed.status_code, 200)
                self.assertEqual(installed.json()["count"], 0)
                self.assertEqual(client.post("/api/tools/installed/sync", json={"confirm": False}).status_code, 400)
                web = client.post("/api/tools/web/apktool", json={"confirm": True})
                self.assertEqual(web.status_code, 200)
                self.assertEqual(web.json()["status"], "skipped")
                mobsf_web = client.post("/api/tools/web/mobsf", json={"confirm": True})
                self.assertEqual(mobsf_web.status_code, 200)
                self.assertIn("installed", mobsf_web.json())
                self.assertIn("Local install check", mobsf_web.json()["detail"])
                shell_help = client.post("/api/tools/shell", json={"command": "help", "confirm": True})
                self.assertEqual(shell_help.status_code, 200)
                self.assertIn("apktool install", shell_help.json()["output"])
                self.assertEqual(shell_help.json()["level"], "info")
                self.assertEqual(client.post("/api/tools/shell", json={"command": "rm -rf /"}).status_code, 400)
                self.assertEqual(client.post(
                    "/api/tools/shell", json={"command": "apktool install", "confirm": False}
                ).status_code, 400)
                dashboard = client.get("/tools/dashboard")
                self.assertEqual(dashboard.status_code, 200)
                self.assertIn("For authorized security testing only", dashboard.text)
                self.assertIn("Installed software dashboard", dashboard.text)
                self.assertIn("Tool access", dashboard.text)
                self.assertIn("Decode &amp; inspect", dashboard.text)
                self.assertIn('data-group="decode"', dashboard.text)
                self.assertIn("tool-card", dashboard.text)
                self.assertIn("runToolAction", dashboard.text)
                self.assertIn("showWhy", dashboard.text)
                self.assertIn("Why no install button", dashboard.text)
                self.assertIn('id="auto-term"', dashboard.text)
                self.assertIn("Live tool job terminal", dashboard.text)
                self.assertIn("showAutoTerm", dashboard.text)
                self.assertIn("closes automatically when the job finishes", dashboard.text)
                main_page = client.get("/")
                self.assertEqual(main_page.status_code, 200)
                self.assertIn("tool-access", main_page.text)
                self.assertIn("tool-card", main_page.text)
                self.assertIn("data-tool-group", main_page.text)
                self.assertIn('id="auto-term"', main_page.text)
                self.assertIn("autoTermShow", main_page.text)
                self.assertIn("drag corner to resize", main_page.text)
                self.assertIn("toolResultMessage", main_page.text)
                self.assertIn("data-tool-why", main_page.text)
                self.assertIn("installable", main_page.text)

    def test_installed_inventory_and_html_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "apktool.bat"
            with patch.multiple(
                config,
                INSTALLED_DB_PATH=root / "installed_tools.db",
                TOOLS_ROOT=root / "tools",
                ANDROID_SDK_ROOT=root / "android-sdk",
                BROWSER_OPEN_ENABLED=False,
                MOBSF_URL="",
                MOBSF_DYNAMIC_URL="",
                RMS_URL="",
                ZAP_WEB_URL="http://127.0.0.1:8080",
            ):
                self.assertEqual(tool_manager.installed_summary()["count"], 0)
                record = tool_manager.record_install(
                    tool_manager.SPEC_BY_ID["apktool"],
                    {"status": "installed", "version": "2.9.0", "path": str(executable)},
                    job_id="test-job-1",
                )
                self.assertIsNotNone(record)
                self.assertEqual(record["executable_path"], str(executable))
                self.assertEqual(record["job_id"], "test-job-1")
                summary = tool_manager.installed_summary()
                self.assertEqual(summary["count"], 1)
                self.assertEqual(summary["tools"][0]["tool_id"], "apktool")
                page = tool_manager.installed_dashboard_html()
                self.assertIn("For authorized security testing only", page)
                self.assertIn("apktool", page)
                self.assertIn("test-job-1", page)
                self.assertNotIn("APKPT_BROWSER_OPEN", page)
                self.assertNotIn("This page lists local tools installed", page)
                self.assertNotIn("Job log colours", page)
                self.assertIn("op-work", page)
                self.assertIn("Tool access", page)
                self.assertIn("Decode &amp; inspect", page)
                self.assertIn('data-group="decode"', page)
                self.assertIn("tool-card", page)
                self.assertIn("runToolAction", page)
                blocked = tool_manager.open_web_ui("zaproxy")
                self.assertEqual(blocked["status"], "skipped")
                self.assertIn("APKPT_BROWSER_OPEN", blocked["detail"])
                mobsf = tool_manager.open_web_ui("mobsf")
                self.assertEqual(mobsf["status"], "skipped")
                self.assertIn("APKPT_MOBSF_URL", mobsf["detail"])

    def test_shell_command_parser_is_allowlisted(self):
        help_plan = tool_manager.parse_shell_command("  help  ")
        self.assertEqual(help_plan["kind"], "message")
        self.assertIn("For authorized security testing only", help_plan["output"])

        install = tool_manager.parse_shell_command("apktool install")
        self.assertEqual(install, {"kind": "job", "tool_id": "apktool", "action": "install"})

        update = tool_manager.parse_shell_command("update adb")
        self.assertEqual(update, {"kind": "job", "tool_id": "platform-tools", "action": "update"})

        batch = tool_manager.parse_shell_command("INSTALL ALL")
        self.assertEqual(batch, {"kind": "job", "tool_id": "all", "action": "install_all"})

        emulator = tool_manager.parse_shell_command("emulator install")
        self.assertEqual(emulator, {"kind": "job", "tool_id": "emulator", "action": "install"})

        web = tool_manager.parse_shell_command("open mobsf")
        self.assertEqual(web, {"kind": "web", "tool_id": "mobsf"})

        for dangerous in ("rm -rf /", "powershell -c whoami", "apktool install && calc", ""):
            self.assertEqual(tool_manager.parse_shell_command(dangerous)["kind"], "error")

    def test_job_log_severity_colours(self):
        samples = {
            "Downloading official release": "work",
            "Installed apktool 2.9.0": "ok",
            "HTTP 200 · https://api.github.com": "info",
            "WARNING: inventory sync failed": "low",
            "Connection timeout while downloading": "high",
            "ERROR: source host is not allowlisted": "critical",
            "No log output.": "dim",
        }
        for message, expected in samples.items():
            self.assertEqual(tool_manager.log_level(message), expected, message)
        rendered = tool_manager.log_html(list(samples))
        for level in set(samples.values()):
            self.assertIn(f"op-{level}", rendered)
        self.assertIn("&lt;script&gt;", tool_manager.log_html(["<script>alert(1)</script>"]))
        self.assertNotIn("<script>", tool_manager.log_html(["<script>alert(1)</script>"]))

    def test_tool_manager_retries_transient_502(self):
        class FakeResponse:
            def __init__(self, status_code: int) -> None:
                self.status_code = status_code
                self.headers: dict[str, str] = {}

            def raise_for_status(self) -> None:
                return None

        class FakeClient:
            def __init__(self, codes: list[int]) -> None:
                self.responses = [FakeResponse(code) for code in codes]
                self.calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def request(self, *_args, **_kwargs):
                self.calls += 1
                return self.responses.pop(0)

        url = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
        with patch.multiple(config, TOOL_MANAGER_RETRIES=3, TOOL_MANAGER_RETRY_DELAY=0), \
                patch.object(tool_manager.time, "sleep", lambda _seconds: None):
            client = FakeClient([502, 200])
            with patch.object(tool_manager, "_client", lambda: client):
                response = tool_manager._request(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(client.calls, 2)

            client = FakeClient([502, 502, 502])
            with patch.object(tool_manager, "_client", lambda: client):
                with self.assertRaises(RuntimeError) as caught:
                    tool_manager._request(url)
                self.assertIn("HTTP 502", str(caught.exception))
                self.assertIn("3 attempt(s)", str(caught.exception))
                self.assertEqual(client.calls, 3)


class PassiveBluetoothAndEmulatorTests(unittest.TestCase):
    """Bluetooth/BLE passive evidence and gated emulator/DAST wiring."""

    def test_bluetooth_findings_are_informational_only(self):
        result = analyze_bluetooth(
            {
                "permissions": [
                    "android.permission.BLUETOOTH_SCAN",
                    "android.permission.ACCESS_FINE_LOCATION",
                ]
            },
            [
                "BluetoothLeScanner", "BluetoothGatt", "createBond",
                "0000180a-0000-1000-8000-00805f9b34fb",
            ],
        )
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("BT-PERMISSIONS", ids)
        self.assertIn("BT-BLE-SURFACE", ids)
        self.assertIn("BT-PAIRING-SURFACE", ids)
        self.assertIn("BT-UUIDS", ids)
        self.assertTrue(all(f["severity"] == "info" for f in result["findings"]))
        self.assertTrue(all(f["category"] == "BLUETOOTH" for f in result["findings"]))
        self.assertTrue(all("not a malware" in f["description"] for f in result["findings"]))
        self.assertIn("not a malware/threat detection engine", result["notice"])
        self.assertFalse(result["lab"]["device_scanning"])
        self.assertFalse(result["lab"]["pairing_or_bonding"])
        self.assertEqual(result["summary"]["finding_count"], len(result["findings"]))

    def test_bluetooth_artifacts_are_excluded_from_heuristics(self):
        artifacts = [
            "bluetoothctl", "hcitool", "nrfutil",
            "550e8400-e29b-41d4-a716-446655440000",
        ]
        self.assertTrue(all(is_benign_pki_string(s) for s in artifacts))
        apk = ApkPackage(SAMPLE)
        ctx = SastContext(
            apk=apk, manifest={}, summary={}, network_config=None,
            app_node=None, extra_strings=artifacts,
        )
        for token in ("bluetoothctl", "hcitool", "nrfutil"):
            self.assertEqual(ctx.containing(token), [])
        with patch("app.scanner.advanced.shannon_entropy", return_value=5.0):
            candidates, _ = analyze_entropy(artifacts)
        self.assertEqual(candidates, [])

    def test_policy_never_counts_passive_findings(self):
        record = ScanRecord(scan_id="btpolicy0000001", filename="bt.apk")
        record.findings = [
            Finding(id="BT-FORCED-HIGH", title="forced high", severity="high", category="BLUETOOTH"),
            Finding(id="PKI-FORCED-HIGH", title="forced high", severity="high", category="PKI"),
        ]
        policy = evaluate_policy(record, thresholds={
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        })
        self.assertEqual(policy["status"], "pass")
        self.assertEqual(policy["actual"]["high"], 0)
        self.assertEqual(policy["pki_findings_excluded"], 1)
        self.assertEqual(policy["bluetooth_findings_excluded"], 1)
        self.assertEqual(policy["passive_findings_excluded"], 2)

    def test_bluetooth_lab_status_is_gated_and_read_only(self):
        with patch.object(config, "BLUETOOTH_LAB_ENABLED", False):
            status = bluetooth_lab_status()
        self.assertFalse(status["enabled"])
        self.assertTrue(all(value is None for value in status["tools"].values()))
        self.assertTrue(status["read_only"])
        self.assertFalse(status["device_scanning"])
        self.assertIn("never scans", status["detail"])

        with patch.object(config, "BLUETOOTH_LAB_ENABLED", True):
            enabled = bluetooth_lab_status()
        self.assertTrue(enabled["enabled"])
        self.assertIn("bluetoothctl", enabled["tools"])

    def test_emulator_actions_require_confirm_and_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config, EMULATOR_AUTO=False, EMULATOR_CMD="",
                ANDROID_SDK_ROOT=str(Path(tmp) / "missing-sdk"),
            ):
                self.assertEqual(launch_emulator(False)["status"], "skipped")
                gated = launch_emulator(True)
                self.assertEqual(gated["status"], "skipped")
                self.assertIn("APKPT_EMULATOR_AUTO", gated["detail"])
                self.assertFalse(gated["performed"])
                self.assertEqual(stop_emulator(True)["status"], "skipped")

            with patch.multiple(
                config, EMULATOR_AUTO=True, EMULATOR_CMD="",
                ANDROID_SDK_ROOT=str(Path(tmp) / "missing-sdk"),
            ):
                missing = launch_emulator(True)
                self.assertEqual(missing["status"], "skipped")
                self.assertIn("not found", missing["detail"])

    def test_emulator_status_exposes_readiness_and_plan(self):
        with patch("app.scanner.lab._run", return_value=(0, "List of devices attached\n")), \
                patch.multiple(
                    config, ADB_CMD="adb", DAST_DEVICE_SERIAL="",
                    DAST_PREFER_EMULATOR=True, EMULATOR_AUTO=False,
                    EMULATOR_AVD="apkpt_test_avd",
                ):
            status = emulator_status()
        self.assertTrue(status["launch_gated"])
        self.assertFalse(status["ready_for_dast"])
        self.assertIsNone(status["dast_serial"])
        self.assertIn("paths", status)
        self.assertEqual(status["paths"]["avd"], "apkpt_test_avd")
        self.assertEqual(
            [step["name"] for step in status["dast_plan"]],
            ["create_avd", "install_dast_tools", "launch_avd", "verify_adb", "run_dast", "teardown"],
        )
        self.assertEqual(status["dast_plan"][2]["status"], "gated")
        self.assertEqual(build_emulator_dast_plan(), status["dast_plan"])

    def test_emulator_selects_attached_emulator_when_no_serial(self):
        devices = "List of devices attached\nemulator-5554\tdevice\n"
        with patch("app.scanner.lab._run", return_value=(0, devices)), \
                patch("app.scanner.lab.shutil.which", return_value="adb"), \
                patch.multiple(
                    config, ADB_CMD="adb", DAST_DEVICE_SERIAL="",
                    DAST_PREFER_EMULATOR=True, EMULATOR_AUTO=False,
                ):
            status = emulator_status()
        self.assertEqual(status["emulator_devices"], ["emulator-5554"])
        self.assertEqual(status["dast_serial"], "emulator-5554")
        self.assertTrue(status["ready_for_dast"])

    def test_new_api_endpoints_are_read_only_and_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config, AUTH_ENABLED=False, AUDIT_LOG=Path(tmp) / "audit.log",
                EMULATOR_AUTO=False, BLUETOOTH_LAB_ENABLED=False,
            ), TestClient(app) as client:
                self.assertEqual(client.get("/api/lab/emulator").status_code, 200)
                plan = client.get("/api/lab/emulator/plan")
                self.assertEqual(plan.status_code, 200)
                self.assertEqual(len(plan.json()["steps"]), 6)
                bt = client.get("/api/bluetooth/status")
                self.assertEqual(bt.status_code, 200)
                self.assertTrue(bt.json()["read_only"])
                self.assertFalse(bt.json()["device_scanning"])
                launched = client.post("/api/lab/emulator/launch", json={"confirm": True})
                self.assertEqual(launched.status_code, 200)
                self.assertEqual(launched.json()["status"], "skipped")
                self.assertFalse(launched.json()["performed"])
                stopped = client.post("/api/lab/emulator/stop", json={"confirm": True})
                self.assertEqual(stopped.status_code, 200)
                self.assertFalse(stopped.json()["performed"])
                health = client.get("/api/health")
                self.assertTrue(health.json()["engines"]["bluetooth"])

    def test_report_and_static_ui_include_bluetooth_disclaimer(self):
        result = analyze_bluetooth(
            {"permissions": ["android.permission.BLUETOOTH_SCAN"]},
            ["BluetoothLeScanner"],
        )
        record = ScanRecord(
            scan_id="bttest00000001", filename="bt.apk",
            bluetooth={k: v for k, v in result.items() if k != "findings"},
        )
        html = generate_html_report(record)
        self.assertIn("Bluetooth / BLE communication surface", html)
        self.assertIn("No radio scan, pairing or device modification", html)
        self.assertIn("not a malware or threat detection engine", html)

        with TestClient(app) as client:
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Bluetooth", page.text)
            self.assertNotIn("APKPT_BROWSER_OPEN", page.text)
            self.assertNotIn("Job log colours", page.text)

    def test_bluetooth_catalog_entries_are_manual(self):
        self.assertEqual(
            [group["id"] for group in tool_manager.TOOL_GROUPS],
            ["decode", "static", "device", "runtime", "dynamic", "proxy", "root"],
        )
        for tool_id in ("bluetoothctl", "hcitool", "nrfutil"):
            spec = tool_manager.SPEC_BY_ID[tool_id]
            self.assertTrue(spec.manual)
            self.assertEqual(tool_manager.tool_group(spec)["id"], "device")

    def test_mobile_and_firmware_tool_catalog_is_manual_and_gated(self):
        with patch.object(sys, "version_info", (3, 14, 0)):
            data = tool_manager.catalog()
        tools = {t["id"]: t for t in data["tools"]}
        manual = {k: v for k, v in tools.items() if v["manual"]}
        host_tools = ("drozer", "androguard", "apkid", "qark")
        for tool_id in host_tools:
            self.assertFalse(tools[tool_id]["manual"])
            self.assertIn(tools[tool_id]["group"], ("dynamic", "static"))
            self.assertTrue({"install", "update"}.intersection(tools[tool_id]["actions"]))
        self.assertEqual(tool_manager.DAST_TOOL_IDS, host_tools)
        self.assertIn("agent", tools["drozer"]["install_note"].lower())

        manual_only = (
            "ghidra", "radare2", "class-dump", "internalblue", "ubertooth",
            "nrf-sniffer", "aircrack-ng", "bettercap", "kismet", "hcxtools",
            "wireshark", "ipsw", "ios-deploy", "libimobiledevice", "binwalk",
            "unblob", "uefitool", "chipsec", "flashrom", "fwupd", "u-boot", "hashcat",
        )
        for tool_id in manual_only:
            self.assertIn(tool_id, manual, f"{tool_id} must be manual/verify-only")
            self.assertEqual(manual[tool_id]["actions"], ["verify"])
            self.assertFalse(manual[tool_id]["installable"])
            self.assertTrue(tool_manager.safe_url(manual[tool_id]["source_url"]))
        for tool_id in ("internalblue", "ubertooth", "aircrack-ng", "bettercap", "chipsec", "flashrom"):
            self.assertTrue(manual[tool_id]["invasive"])
        for tool_id in ("binwalk", "unblob", "uefitool", "chipsec", "flashrom", "fwupd", "u-boot", "hashcat"):
            self.assertEqual(manual[tool_id]["group"], "root")

    def test_dast_toolchain_job_is_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(
                config, AUTH_ENABLED=False, AUDIT_LOG=Path(tmp) / "audit.log",
                TOOL_MANAGER_ENABLED=False,
            ), TestClient(app) as client:
                result = client.post("/api/tools/dast/install", json={"confirm": True})
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["status"], "skipped")
                self.assertIn("APKPT_TOOL_MANAGER", result.json()["detail"])
                self.assertEqual(
                    client.post("/api/tools/dast/verify", json={"confirm": False}).status_code, 400
                )
                self.assertEqual(
                    client.post("/api/tools/dast/bogus", json={"confirm": True}).status_code, 400
                )
        with self.assertRaises(ValueError):
            tool_manager.MANAGER.submit("dast", "pull")
        self.assertEqual(
            tool_manager.parse_shell_command("dast install"),
            {"kind": "job", "tool_id": "dast", "action": "install"},
        )

    def test_adb_resolves_from_sdk_when_not_on_path(self):
        suffix = ".exe" if os.name == "nt" else ""
        with tempfile.TemporaryDirectory() as tmp:
            sdk = Path(tmp) / "android-sdk"
            sdk_adb = sdk / "platform-tools" / f"adb{suffix}"
            sdk_adb.parent.mkdir(parents=True)
            sdk_adb.write_text("stub", encoding="utf-8")

            with patch("app.scanner.lab.shutil.which", return_value=None), \
                    patch.multiple(config, ADB_CMD="adb", ANDROID_SDK_ROOT=sdk):
                resolved = adb_command()
                status = emulator_status()
            self.assertEqual(resolved, [str(sdk_adb)])
            self.assertTrue(status["adb_available"])
            self.assertEqual(status["adb_command"], str(sdk_adb))
            self.assertTrue(status["paths"]["platform_tools_adb_available"])
            self.assertIn(str(sdk_adb), status["paths"]["platform_tools_adb"])

            # An explicitly configured command that exists always wins.
            with patch("app.scanner.lab.shutil.which", return_value=None), \
                    patch.multiple(config, ADB_CMD=str(sdk_adb), ANDROID_SDK_ROOT=sdk):
                self.assertEqual(adb_command(), [str(sdk_adb)])


if __name__ == "__main__":
    unittest.main()
