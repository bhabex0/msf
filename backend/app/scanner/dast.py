"""Dynamic analysis (DAST) driven by adb, with optional Frida instrumentation.

When no device/emulator is connected the engine returns explicit 'skipped'
checks with setup instructions instead of pretending that DAST ran.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from .lab import adb_command, emulator_status, proxy_config
from .rules import excerpt, finding

SENSITIVE_LOG_RE = re.compile(r"(password|passwd|token|secret|api[_-]?key|authorization|credit card)", re.I)


def _component_target(package: str, name: str) -> str:
    """Convert a manifest component name to an `am start -n` target."""
    name = name.strip()
    if "." not in name:
        name = "." + name
    return f"{package}/{name}"


FRIDA_TLS_SCRIPT = r"""
// Logs whenever an app-supplied TrustManager accepts a certificate chain.
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
    console.log('[APKPT] checkServerTrusted called with ' + chain.length + ' cert(s), authType=' + authType);
    return this.checkServerTrusted(chain, authType);
  };
  var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
  HttpsURLConnection.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (v) {
    console.log('[APKPT] custom HostnameVerifier installed: ' + v);
    return this.setHostnameVerifier(v);
  };
});
"""

FRIDA_WEBVIEW_SCRIPT = r"""
Java.perform(function () {
  var WebSettings = Java.use('android.webkit.WebSettings');
  WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
    console.log('[APKPT] WebView.setJavaScriptEnabled(' + enabled + ')');
    return this.setJavaScriptEnabled(enabled);
  };
  var WebView = Java.use('android.webkit.WebView');
  WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, name) {
    console.log('[APKPT] addJavascriptInterface bridge: ' + name);
    return this.addJavascriptInterface(obj, name);
  };
});
"""


@dataclass
class DastResult:
    status: str = "not_run"
    checks: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    def check(self, name: str, status: str, detail: str = "", evidence: str = "") -> None:
        self.checks.append({"name": name, "status": status, "detail": detail, "evidence": evidence[:2000]})


def _adb_cmd(*args: str, serial: str | None = None) -> list[str]:
    cmd = adb_command()
    target = serial or config.DAST_DEVICE_SERIAL
    if target:
        cmd += ["-s", target]
    return cmd + list(args)


def _adb(*args: str, timeout: int = 60, serial: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            _adb_cmd(*args, serial=serial),
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except FileNotFoundError:
        return 127, "adb not found"
    except subprocess.TimeoutExpired:
        return 124, f"adb command timed out after {timeout}s"
    except Exception as exc:
        return 1, str(exc)


def _connected_devices() -> list[str]:
    code, out = _adb("devices")
    if code != 0:
        return []
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def _launcher_activity(summary: dict[str, Any]) -> str | None:
    for act in summary.get("activities", []):
        for filt in act.get("intent_filters", []):
            cats = [str(c) for c in filt.get("categories", [])]
            if any(c.endswith("LAUNCHER") for c in cats) and act.get("name"):
                return act["name"]
    return None


def _deep_link_targets(summary: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (activity, URI) pairs for browsable intent filters."""
    out: list[tuple[str, str]] = []
    for act in summary.get("activities", []):
        name = act.get("name")
        if not name:
            continue
        for flt in act.get("intent_filters", []):
            categories = [str(c) for c in flt.get("categories", [])]
            if not any(c.endswith("BROWSABLE") for c in categories):
                continue
            for data in flt.get("data", []):
                values = {k.split(":")[-1]: v for k, v in data.items()}
                scheme = values.get("scheme")
                if not scheme:
                    continue
                host = values.get("host") or "example.com"
                path = values.get("path") or values.get("pathPrefix") or "/"
                uri = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}?apkpt_test=1"
                if (name, uri) not in out:
                    out.append((name, uri))
    return out[:5]


def _fuzz_targets(summary: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (kind, package-relative component, permission) tuples."""
    out: list[tuple[str, str, str]] = []
    for key, kind in (("activities", "activity"), ("services", "service"), ("receivers", "receiver")):
        for comp in summary.get(key, []):
            name = comp.get("name")
            exported = comp.get("exported")
            filters = comp.get("intent_filters") or []
            if not name or not (exported is True or (exported is None and filters)):
                continue
            out.append((kind, name, str(comp.get("permission") or "")))
    return out[:5]


def _frida_run(package: Path | str, script_path: Path, timeout: int = 25) -> list[str]:
    exe = shutil.which("frida")
    if not exe:
        return []
    try:
        proc = subprocess.run(
            [exe, "-U", "-f", str(package), "-l", str(script_path), "--no-pause"],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return [line.strip() for line in (proc.stdout or "").splitlines() if "[APKPT]" in line][:40]
    except Exception:
        return []


def run_dast(
    apk_path: Path,
    summary: dict[str, Any],
    work_dir: Path,
    network_config: dict[str, Any] | None = None,
) -> DastResult:
    result = DastResult()
    if not config.ENABLE_DAST:
        result.status = "disabled"
        result.check("engine", "skipped", "DAST disabled via APKPT_ENABLE_DAST=0")
        return result

    adb_parts = adb_command()
    if not (shutil.which(adb_parts[0]) or Path(adb_parts[0]).exists()):
        result.status = "skipped"
        result.check(
            "adb_availability",
            "skipped",
            "adb was not found in PATH or under ANDROID_SDK_ROOT/platform-tools. "
            "Install Android SDK platform-tools and add it to PATH.",
        )
        return result

    devices = _connected_devices()
    if not devices:
        result.status = "skipped"
        result.check(
            "device_availability",
            "skipped",
            "No adb device connected. Start an emulator or connect a device with USB debugging enabled.",
        )
        return result
    result.info["devices"] = devices

    # Select an attached emulator when preferred; an explicit serial always wins.
    emulator_devices = [d for d in devices if d.startswith("emulator-")]
    selected_serial = config.DAST_DEVICE_SERIAL or ""
    if not selected_serial and config.DAST_PREFER_EMULATOR and emulator_devices:
        selected_serial = emulator_devices[0]
    if not selected_serial:
        selected_serial = devices[0]
    result.info["selected_serial"] = selected_serial

    def adb(*args: str, timeout: int = 60) -> tuple[int, str]:
        return _adb(*args, timeout=timeout, serial=selected_serial)

    package = summary.get("package")
    if not package:
        result.status = "skipped"
        result.check("package_name", "skipped", "Could not determine package name from the manifest.")
        return result
    result.info["package"] = package

    proxy = proxy_config()
    lab = emulator_status()
    result.info["proxy"] = proxy
    result.info["lab"] = {
        "emulator_available": lab["emulator_available"],
        "emulator_auto": lab["emulator_auto"],
        "invasive_allowed": lab["invasive_allowed"],
        "emulator_devices": lab["emulator_devices"],
        "physical_devices": lab["physical_devices"],
        "avd": lab["avd"],
        "avd_created": lab["paths"]["avd_created"],
        "launch_gated": lab["launch_gated"],
        "dast_plan": lab["dast_plan"],
    }
    result.check(
        "emulator_target", "passed" if emulator_devices else "skipped",
        f"Using adb serial {selected_serial}"
        + (" (emulator)" if selected_serial in emulator_devices else " (physical device)")
        + (f"; {len(emulator_devices)} emulator(s) attached" if emulator_devices else
           "; no emulator attached — launch the local AVD via /api/lab/emulator/launch"),
    )
    if proxy["configured"]:
        tool_commands = {
            "burp": config.BURP_CMD,
            "zap": config.ZAP_CMD,
            "mitmproxy": config.MITMPROXY_CMD,
        }
        listener = tool_commands.get(proxy["type"], "")
        available = bool(listener and (shutil.which(shlex.split(listener)[0]) or Path(shlex.split(listener)[0]).exists())) if listener else False
        result.check(
            "interception_proxy", "passed" if available else "skipped",
            f"{proxy['type']} listener on {proxy['endpoint']}"
            + ("" if available else "; start the proxy from the Lab tab before capturing traffic"),
        )
    else:
        result.check(
            "interception_proxy", "skipped",
            "No proxy configured. Set APKPT_DAST_PROXY=burp|zap|mitmproxy|host:port for HTTPS interception.",
        )

    nsc = network_config or {}
    if nsc.get("user_ca_trusted") is False:
        result.check(
            "nsc_interception", "skipped",
            "Network Security Configuration does not trust user CAs on target SDK 24+. "
            "Use patch-apk.py or a test-only NSC in the authorized lab.",
        )
    elif nsc:
        result.check("nsc_interception", "passed", "Declared NSC permits user CA trust for interception.")

    code, out = adb("shell", "getprop", "ro.build.version.release", timeout=20)
    result.info["android_version"] = out if code == 0 else "unknown"
    code, out = adb("shell", "getprop", "ro.product.model", timeout=20)
    result.info["device_model"] = out if code == 0 else "unknown"

    code, install_log = adb("install", "-r", "-t", str(apk_path), timeout=180)
    if code != 0:
        result.status = "error"
        result.check("install", "failed", f"adb install failed (exit {code})", install_log)
        return result
    result.check("install", "passed", "APK installed on the test device")

    original_proxy = ""
    if proxy["configured"]:
        code, original_proxy = adb("shell", "settings", "get", "global", "http_proxy", timeout=20)
        adb("shell", "settings", "put", "global", "http_proxy", proxy["endpoint"], timeout=20)
        result.check(
            "proxy", "passed",
            f"HTTP proxy set to {proxy['endpoint']} ({proxy['type']}); capture traffic in your authorized proxy",
        )
    else:
        result.check("proxy", "skipped", "No device proxy was applied.")

    if config.CA_CERT_PATH and Path(config.CA_CERT_PATH).exists():
        if config.EMULATOR_AUTO and config.ALLOW_INVASIVE:
            code, ca_log = adb("push", config.CA_CERT_PATH, "/data/local/tmp/apkpt-proxy-ca.crt", timeout=30)
            result.check(
                "proxy_ca", "passed" if code == 0 else "error",
                "CA copied to test device; install into the test trust store per the Lab plan"
                if code == 0 else ca_log[-500:],
            )
        else:
            result.check(
                "proxy_ca", "skipped",
                "CA path configured but installation requires APKPT_EMULATOR_AUTO=1 and APKPT_ALLOW_INVASIVE=1.",
            )
    else:
        result.check(
            "proxy_ca", "skipped",
            "Set APKPT_CA_CERT_PATH to the proxy CA for HTTPS interception evidence.",
        )

    activity = _launcher_activity(summary)
    adb("logcat", "-c", timeout=20)
    if activity:
        launch = _component_target(package, activity)
        code, launch_log = adb("shell", "am", "start", "-n", launch, timeout=40)
        result.check("launch", "passed" if code == 0 else "error", launch_log[:500], launch_log)
    else:
        code, launch_log = adb(
            "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1", timeout=40
        )
        result.check("launch", "passed" if code == 0 else "error", "launched via monkey", launch_log)

    time.sleep(max(2, config.DAST_LAUNCH_WAIT_SECONDS))

    _, logcat = adb("logcat", "-d", "-v", "threadtime", timeout=60)
    result.info["logcat_excerpt"] = logcat[-6000:]
    result.check("logcat_capture", "passed" if logcat else "error", f"captured {len(logcat)} bytes")

    if re.search(r"FATAL EXCEPTION|AndroidRuntime.*Exception", logcat, re.I):
        result.findings.append(
            finding(
                "DAST-CRASH",
                "Application crashed at runtime",
                "high",
                category="DAST",
                description="A fatal exception was observed in logcat after launching the app. Crashes can "
                "indicate unstable parsing code and may be exploitable with crafted input.",
                evidence=excerpt([line for line in logcat.splitlines() if "FATAL" in line or "Exception" in line]),
                remediation="Investigate the stack trace and fix the root cause; add defensive input validation.",
                cwe="CWE-248",
                masvs="MASVS-CODE-2",
                confidence="high",
            )
        )

    cleartext = [line for line in logcat.splitlines() if "http://" in line.lower() and "localhost" not in line.lower()]
    if cleartext:
        result.findings.append(
            finding(
                "DAST-CLEARTEXT-TRAFFIC",
                "Cleartext HTTP traffic observed at runtime",
                "medium",
                category="DAST",
                description="The app emitted or handled plain HTTP URLs at runtime.",
                evidence=excerpt(cleartext),
                remediation="Enforce HTTPS/TLS for all network communication.",
                cwe="CWE-319",
                masvs="MASVS-NETWORK-1",
            )
        )

    sensitive_lines = [line for line in logcat.splitlines() if SENSITIVE_LOG_RE.search(line)]
    if sensitive_lines:
        result.findings.append(
            finding(
                "DAST-SENSITIVE-LOGS",
                "Sensitive-looking data in logcat",
                "low",
                category="DAST",
                description="Logcat output contains lines matching credential/secret keywords.",
                evidence=excerpt(sensitive_lines),
                remediation="Remove sensitive logging from release builds.",
                cwe="CWE-532",
                masvs="MASVS-STORAGE-2",
                confidence="low",
            )
        )

    def component_target(name: str) -> str:
        return _component_target(package, name)

    deep_links = _deep_link_targets(summary)
    for activity_name, uri in deep_links:
        adb("logcat", "-c", timeout=20)
        code, out = adb("shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", uri,
                         component_target(activity_name), timeout=40)
        _, dlog = adb("logcat", "-d", "-v", "threadtime", timeout=40)
        crashed = bool(re.search(r"FATAL EXCEPTION|AndroidRuntime.*Exception", dlog, re.I))
        result.check("deep_link", "failed" if crashed else "passed" if code == 0 else "error",
                     f"{uri} -> exit {code}" + (" (crash)" if crashed else ""), (out + "\n" + dlog)[:1200])
        if crashed:
            result.findings.append(finding(
                "DAST-DEEPLINK-CRASH",
                "Deep link caused a runtime crash",
                "high",
                category="DAST",
                description=f"Launching {uri} against {activity_name} produced a fatal exception. Unvalidated deep-link parameters can be a denial-of-service or injection vector.",
                evidence=excerpt([line for line in dlog.splitlines() if "FATAL" in line or "Exception" in line]),
                remediation="Validate all Intent/data parameters coming from deep links and handle malformed input safely.",
                cwe="CWE-20",
                masvs="MASVS-PLATFORM-2",
                confidence="high",
            ))

    fuzz_targets = _fuzz_targets(summary)
    for kind, comp_name, permission in fuzz_targets:
        adb("logcat", "-c", timeout=20)
        payload = "A" * 4096
        args = ["shell", "am", "start", "-n", component_target(comp_name), "--es", "APKPT_FUZZ", payload]
        if kind == "service":
            args[2] = "startservice"
        elif kind == "receiver":
            args[2] = "broadcast"
        code, out = adb(*args, timeout=40)
        _, flog = adb("logcat", "-d", "-v", "threadtime", timeout=40)
        crashed = bool(re.search(r"FATAL EXCEPTION|AndroidRuntime.*Exception", flog, re.I))
        result.check("intent_fuzz", "failed" if crashed else "passed" if code == 0 else "error",
                     f"{kind} {comp_name} permission={permission or 'none'} exit {code}" + (" (crash)" if crashed else ""),
                     (out + "\n" + flog)[:1200])
        if crashed:
            result.findings.append(finding(
                "DAST-EXPORTED-FUZZ-CRASH",
                "Exported component crashed on hostile Intent extra",
                "high",
                category="DAST",
                description=f"An exported {kind} ({comp_name}) crashed when a large string extra was supplied. This indicates missing input validation on an app entry point.",
                evidence=excerpt([line for line in flog.splitlines() if "FATAL" in line or "Exception" in line]),
                remediation="Validate Intent extras (type, length, format), reject oversized input and require a signature-level permission where possible.",
                cwe="CWE-20",
                masvs="MASVS-PLATFORM-1",
                confidence="high",
            ))

    _, dumpsys = adb("shell", "dumpsys", "package", package, timeout=60)
    result.info["dumpsys_excerpt"] = dumpsys[:6000]
    if "DEBUGGABLE" in dumpsys.upper():
        result.findings.append(
            finding(
                "DAST-DEBUGGABLE-RUNTIME",
                "Running application is debuggable",
                "high",
                category="DAST",
                description="The installed app is flagged DEBUGGABLE at runtime, allowing attachment of a "
                "debugger and extraction of its private data directory.",
                evidence="dumpsys package flags contain DEBUGGABLE",
                remediation="Build release APKs with android:debuggable=\"false\" and R8 stripping.",
                cwe="CWE-489",
                masvs="MASVS-RESILIENCE-2",
                confidence="high",
            )
        )
        code, run_as = adb("shell", "run-as", package, "ls", "-la", timeout=30)
        if code == 0:
            result.findings.append(
                finding(
                    "DAST-DATA-EXTRACTABLE",
                    "Private app data readable via run-as",
                    "high",
                    category="DAST",
                    description="Because the app is debuggable, its private data directory can be read with "
                    "adb shell run-as without root.",
                    evidence=run_as[:1200],
                    remediation="Disable debuggable in release builds and encrypt sensitive data at rest.",
                    cwe="CWE-489",
                    masvs="MASVS-STORAGE-1",
                    confidence="high",
                )
            )

    if config.DAST_FRIDA and shutil.which("frida"):
        work_dir.mkdir(parents=True, exist_ok=True)
        for name, script in (("tls_bypass.js", FRIDA_TLS_SCRIPT), ("webview.js", FRIDA_WEBVIEW_SCRIPT)):
            p = work_dir / name
            p.write_text(script, encoding="utf-8")
            hits = _frida_run(package, p)
            result.check(f"frida_{name}", "passed" if hits else "error", f"{len(hits)} hook events", "\n".join(hits))
            if hits:
                result.findings.append(
                    finding(
                        f"DAST-FRIDA-{name.upper().replace('.', '-')}",
                        f"Frida observed security-relevant API usage ({name})",
                        "medium",
                        category="DAST",
                        description="Runtime hooking observed calls to APIs that are commonly involved in "
                        "TLS or WebView weaknesses.",
                        evidence="\n".join(hits),
                        remediation="Review the captured call sites and remove unsafe configurations.",
                        masvs="MASVS-NETWORK-3",
                        confidence="medium",
                    )
                )
    else:
        result.check("frida", "skipped", "Set APKPT_DAST_FRIDA=1 and install frida-tools to enable hooking.")

    try:
        remote = "/sdcard/apkpt_screen.png"
        code, _ = adb("shell", "screencap", "-p", remote, timeout=30)
        if code == 0:
            local = work_dir / "screenshot.png"
            code, _ = adb("pull", remote, str(local), timeout=30)
            if code == 0 and local.exists():
                result.info["screenshot"] = str(local)
                result.check("screenshot", "passed", "captured runtime screenshot")
    except Exception:
        pass

    if proxy["configured"]:
        if original_proxy and original_proxy.lower() not in ("", "null", "none"):
            adb("shell", "settings", "put", "global", "http_proxy", original_proxy.strip(), timeout=20)
        else:
            adb("shell", "settings", "delete", "global", "http_proxy", timeout=20)

    if config.DAST_UNINSTALL_AFTER:
        adb("uninstall", package, timeout=90)
        result.check("cleanup", "passed", "test app uninstalled from device")

    result.status = "completed"
    return result
