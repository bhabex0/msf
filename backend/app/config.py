"""Central configuration. Every setting can be overridden with an environment variable."""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- paths
BACKEND_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
STORAGE_DIR = Path(os.getenv("APKPT_STORAGE_DIR", str(BACKEND_DIR / "storage")))
SCANS_DIR = STORAGE_DIR / "scans"

# ---------------------------------------------------------------- upload
MAX_UPLOAD_MB = int(os.getenv("APKPT_MAX_UPLOAD_MB", "250"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {".apk"}

# ---------------------------------------------------------------- engines
SCAN_TIMEOUT_SECONDS = int(os.getenv("APKPT_SCAN_TIMEOUT", "900"))

ENABLE_SAST = os.getenv("APKPT_ENABLE_SAST", "1") == "1"
ENABLE_SCA = os.getenv("APKPT_ENABLE_SCA", "1") == "1"
ENABLE_DAST = os.getenv("APKPT_ENABLE_DAST", "1") == "1"

# SCA online lookup against the public OSV.dev API. Failures are ignored.
SCA_ONLINE_LOOKUP = os.getenv("APKPT_SCA_ONLINE", "1") == "1"
SCA_ONLINE_TIMEOUT = float(os.getenv("APKPT_SCA_ONLINE_TIMEOUT", "6"))

# ---------------------------------------------------------------- DAST
DAST_DEVICE_SERIAL = os.getenv("APKPT_DAST_SERIAL", "").strip()
DAST_LAUNCH_WAIT_SECONDS = int(os.getenv("APKPT_DAST_WAIT", "12"))
DAST_FRIDA = os.getenv("APKPT_DAST_FRIDA", "0") == "1"
DAST_PROXY = os.getenv("APKPT_DAST_PROXY", "").strip()
DAST_UNINSTALL_AFTER = os.getenv("APKPT_DAST_UNINSTALL", "1") == "1"
# Prefer an attached emulator serial when more than one adb device is present.
DAST_PREFER_EMULATOR = os.getenv("APKPT_DAST_PREFER_EMULATOR", "1") == "1"

# ---------------------------------------------------------------- tool hooks
TOOL_APKTOOL = os.getenv("APKPT_TOOL_APKTOOL", "1") == "1"
TOOL_JADX = os.getenv("APKPT_TOOL_JADX", "1") == "1"
TOOL_AAPT = os.getenv("APKPT_TOOL_AAPT", "1") == "1"


def _tool_port(env_name: str, default: int) -> int:
    """Read a web-tool port with a clear failure for invalid values."""
    raw = os.getenv(env_name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{env_name} must be an integer port, got {raw!r}") from exc
    if not 1 <= value <= 65535:
        raise ValueError(f"{env_name} must be between 1 and 65535, got {value}")
    return value


# Recommended local ports. The platform itself uses 8000 by default; each web
# tool gets its own port so the dashboard and tool UIs can run simultaneously.
# Setting any APKPT_*_PORT variable also constructs a local URL for that tool.
TOOL_WEB_HOST = os.getenv("APKPT_TOOL_WEB_HOST", "127.0.0.1").strip().rstrip("/")
TOOL_WEB_PORTS = {
    "platform": _tool_port("APKPT_PLATFORM_PORT", 8000),
    "mobsf": _tool_port("APKPT_MOBSF_PORT", 8001),
    "mobsf_dynamic": _tool_port("APKPT_MOBSF_DYNAMIC_PORT", 8002),
    "apkhunt": _tool_port("APKPT_APKHUNT_PORT", 8003),
    "rms": _tool_port("APKPT_RMS_PORT", 8004),
    "zaproxy": _tool_port("APKPT_ZAP_WEB_PORT", 8005),
}
TOOL_WEB_PORT_ENV = {
    "platform": "APKPT_PLATFORM_PORT",
    "mobsf": "APKPT_MOBSF_PORT",
    "mobsf_dynamic": "APKPT_MOBSF_DYNAMIC_PORT",
    "apkhunt": "APKPT_APKHUNT_PORT",
    "rms": "APKPT_RMS_PORT",
    "zaproxy": "APKPT_ZAP_WEB_PORT",
}
TOOL_WEB_URL_ENV = {
    "mobsf": "APKPT_MOBSF_URL",
    "mobsf_dynamic": "APKPT_MOBSF_DYNAMIC_URL",
    "apkhunt": "APKPT_APKHUNT_URL",
    "rms": "APKPT_RMS_URL",
    "zaproxy": "APKPT_ZAP_WEB_URL",
}

# Opt-in: when the platform runs on the trigger port (8000 by default), build
# local URLs for every web tool on its dedicated port automatically.
TOOL_WEB_AUTO = os.getenv("APKPT_TOOL_WEB_AUTO", "0") == "1"
TOOL_WEB_AUTO_TRIGGER_PORT = _tool_port("APKPT_TOOL_WEB_AUTO_TRIGGER_PORT", 8000)
TOOL_WEB_AUTO_ACTIVE = TOOL_WEB_AUTO and TOOL_WEB_PORTS["platform"] == TOOL_WEB_AUTO_TRIGGER_PORT


def _configured_web_url(url_env: str, port_env: str, port_key: str, allow_auto: bool = True) -> str:
    """Use an explicit URL, else build one when its port or auto mode is enabled."""
    explicit = os.getenv(url_env, "").strip().rstrip("/")
    if explicit:
        return explicit
    if os.getenv(port_env, "").strip() or (allow_auto and TOOL_WEB_AUTO_ACTIVE):
        return f"http://{TOOL_WEB_HOST}:{TOOL_WEB_PORTS[port_key]}"
    return ""


def _configured_web_port(port_env: str, port_key: str, allow_auto: bool = True) -> int | None:
    """Return the active port only when the operator opted into it."""
    if os.getenv(port_env, "").strip() or (allow_auto and TOOL_WEB_AUTO_ACTIVE):
        return TOOL_WEB_PORTS[port_key]
    return None


MOBSF_URL = _configured_web_url("APKPT_MOBSF_URL", "APKPT_MOBSF_PORT", "mobsf")
MOBSF_PORT = _configured_web_port("APKPT_MOBSF_PORT", "mobsf")
MOBSF_API_KEY = os.getenv("APKPT_MOBSF_API_KEY", "")
MOBSF_TIMEOUT = int(os.getenv("APKPT_MOBSF_TIMEOUT", "300"))
TOOL_SEMGREP = os.getenv("APKPT_TOOL_SEMGREP", "1") == "1"
SEMGREP_TIMEOUT = int(os.getenv("APKPT_SEMGREP_TIMEOUT", "90"))

# ---------------------------------------------------------------- advanced
ENABLE_ADVANCED = os.getenv("APKPT_ENABLE_ADVANCED", "1") == "1"
ENABLE_LIVE_CHECKS = os.getenv("APKPT_LIVE_CHECKS", "0") == "1"
LIVE_TIMEOUT = float(os.getenv("APKPT_LIVE_TIMEOUT", "6"))
VIRUSTOTAL_API_KEY = os.getenv("APKPT_VIRUSTOTAL_API_KEY", "")
SOURCE_TTL_SECONDS = int(os.getenv("APKPT_SOURCE_TTL", "86400"))
CUSTOM_RULES_PATH = Path(
    os.getenv("APKPT_CUSTOM_RULES", str(DATA_DIR / "custom_rules.json"))
)
LIVE_MAX_ENDPOINTS = int(os.getenv("APKPT_LIVE_MAX_ENDPOINTS", "5"))

# ---------------------------------------------------------------- auth
AUTH_ENABLED = os.getenv("APKPT_AUTH_ENABLED", "0") == "1"
JWT_SECRET = os.getenv("APKPT_JWT_SECRET", "change-me-in-production")
JWT_TTL_HOURS = int(os.getenv("APKPT_JWT_TTL_HOURS", "24"))
ADMIN_USER = os.getenv("APKPT_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("APKPT_ADMIN_PASS", "admin")
API_TOKEN = os.getenv("APKPT_API_TOKEN", "")
AUDIT_LOG = STORAGE_DIR / "audit.log"
POLICY_THRESHOLDS = {
    "critical": int(os.getenv("APKPT_POLICY_CRITICAL", "0")),
    "high": int(os.getenv("APKPT_POLICY_HIGH", "0")),
    "medium": int(os.getenv("APKPT_POLICY_MEDIUM", "10")),
    "low": int(os.getenv("APKPT_POLICY_LOW", "100")),
}
# -1 disables the medical gap gate. 0 means no unresolved medical control gaps.
POLICY_MEDICAL_GAPS = int(os.getenv("APKPT_POLICY_MEDICAL_GAPS", "-1"))

# ---------------------------------------------------------------- medical focus
ENABLE_MEDICAL = os.getenv("APKPT_ENABLE_MEDICAL", "1") == "1"
MEDICAL_DOMAIN = os.getenv("APKPT_MEDICAL_DOMAIN", "healthcare").strip().lower()
MEDICAL_PHI_MODE = os.getenv("APKPT_PHI_MODE", "detect").strip().lower()

# ---------------------------------------------------------------- external toolchain
# Analysis tools are opt-in because they may be licensed, slow or cloud-based.
TOOLCHAIN_AUTO = os.getenv("APKPT_TOOLCHAIN_AUTO", "0") == "1"
TOOLCHAIN_TIMEOUT = int(os.getenv("APKPT_TOOLCHAIN_TIMEOUT", "300"))
TOOL_APKHUNT = os.getenv("APKPT_TOOL_APKHUNT", "1") == "1"
TOOL_APKLEAKS = os.getenv("APKPT_TOOL_APKLEAKS", "1") == "1"
TOOL_APPSCAN = os.getenv("APKPT_TOOL_APPSCAN", "1") == "1"
TOOL_TRASHDROID = os.getenv("APKPT_TOOL_TRASHDROID", "1") == "1"
TOOL_RMS = os.getenv("APKPT_TOOL_RMS", "1") == "1"
TOOL_MITMPROXY = os.getenv("APKPT_TOOL_MITMPROXY", "1") == "1"
TOOL_ZAP = os.getenv("APKPT_TOOL_ZAP", "1") == "1"
TOOL_BURP = os.getenv("APKPT_TOOL_BURP", "1") == "1"
TOOL_RECMANAGER = os.getenv("APKPT_TOOL_RECMANAGER", "1") == "1"

# Finding cap for external-tool imports and SCA advisory matching. 0 means no
# limit, which is the default. Set a positive integer only if a host needs a
# deliberate volume guard; it is not used by the built-in engines.
TOOL_FINDING_LIMIT = max(0, int(os.getenv("APKPT_TOOL_FINDING_LIMIT", "0")))

# Binary overrides. Values are split with shlex.split in toolchain.py.
APKHUNT_CMD = os.getenv("APKPT_APKHUNT_CMD", "apkhunt")
# APKHunt's current release is a local web workbench. These paths are
# deployment-specific; override them to match the instance you are authorised to use.
APKHUNT_URL = _configured_web_url("APKPT_APKHUNT_URL", "APKPT_APKHUNT_PORT", "apkhunt")
APKHUNT_PORT = _configured_web_port("APKPT_APKHUNT_PORT", "apkhunt")
APKHUNT_UPLOAD_PATH = os.getenv("APKPT_APKHUNT_UPLOAD_PATH", "/api/scan/upload")
APKHUNT_REPORT_PATH = os.getenv("APKPT_APKHUNT_REPORT_PATH", "/api/scan/report/{scan_id}")
APKHUNT_API_KEY = os.getenv("APKPT_APKHUNT_API_KEY", "")
APKLEAKS_CMD = os.getenv("APKPT_APKLEAKS_CMD", "apkleaks")
APPSCAN_CMD = os.getenv("APKPT_APPSCAN_CMD", "appscan")
APPSCAN_SERVER = os.getenv("APKPT_APPSCAN_SERVER", "").strip()
APPSCAN_API_KEY = os.getenv("APKPT_APPSCAN_API_KEY", "")
TRASHDROID_CMD = os.getenv("APKPT_TRASHDROID_CMD", "trashdroid")
DROZER_CMD = os.getenv("APKPT_DROZER_CMD", "drozer")
ANDROGUARD_CMD = os.getenv("APKPT_ANDROGUARD_CMD", "androguard")
APKiD_CMD = os.getenv("APKPT_APKID_CMD", "apkid")
QARK_CMD = os.getenv("APKPT_QARK_CMD", "qark")
RMS_CMD = os.getenv("APKPT_RMS_CMD", "rms")
MITMPROXY_CMD = os.getenv("APKPT_MITMPROXY_CMD", "mitmdump")
ZAP_CMD = os.getenv("APKPT_ZAP_CMD", "zap.sh")
BURP_CMD = os.getenv("APKPT_BURP_CMD", "burpsuite")
PATCHAPK_CMD = os.getenv("APKPT_PATCHAPK_CMD", "patch-apk.py")
OBJECTION_CMD = os.getenv("APKPT_OBJECTION_CMD", "objection")
APATCH_CMD = os.getenv("APKPT_APATCH_CMD", "")
RECMANAGER_CMD = os.getenv("APKPT_RECMANAGER_CMD", "")
CHROMIUM_CMD = os.getenv("APKPT_CHROMIUM_CMD", "")
ADB_CMD = os.getenv("APKPT_ADB_CMD", "adb")
APKTOOL_CMD = os.getenv("APKPT_APKTOOL_CMD", "apktool")
JARSIGNER_CMD = os.getenv("APKPT_JARSIGNER_CMD", "jarsigner")
APKSIGNER_CMD = os.getenv("APKPT_APKSIGNER_CMD", "apksigner")
KEYTOOL_CMD = os.getenv("APKPT_KEYTOOL_CMD", "keytool")
OPENSSL_CMD = os.getenv("APKPT_OPENSSL_CMD", "openssl")

# ---------------------------------------------------------------- emulator / lab
# Nothing in this section executes by default. Invasive workflows require both
# APKPT_TOOLCHAIN_AUTO=1 and APKPT_ALLOW_INVASIVE=1 plus an authenticated call.
EMULATOR_AUTO = os.getenv("APKPT_EMULATOR_AUTO", "0") == "1"
ALLOW_INVASIVE = os.getenv("APKPT_ALLOW_INVASIVE", "0") == "1"
EMULATOR_CMD = os.getenv("APKPT_EMULATOR_CMD", "").strip()
EMULATOR_AVD = os.getenv("APKPT_EMULATOR_AVD", "").strip()
JAVA_CMD = os.getenv("APKPT_JAVA_CMD", "").strip()

# ---------------------------------------------------------------- tool manager
# Downloads/installs never start automatically. Each dashboard action creates
# an explicit job; manual/licensed tools are reported rather than downloaded.
TOOL_MANAGER_ENABLED = os.getenv("APKPT_TOOL_MANAGER", "0") == "1"
TOOLS_ROOT = Path(os.getenv("APKPT_TOOLS_DIR", str(STORAGE_DIR / "tools")))
ANDROID_SDK_ROOT = Path(os.getenv("APKPT_ANDROID_SDK_ROOT", str(TOOLS_ROOT / "android-sdk")))
EMULATOR_SYSTEM_IMAGE = os.getenv("APKPT_EMULATOR_SYSTEM_IMAGE", "").strip()
TOOL_MANAGER_TIMEOUT = int(os.getenv("APKPT_TOOL_MANAGER_TIMEOUT", "900"))
TOOL_MANAGER_MAX_WORKERS = int(os.getenv("APKPT_TOOL_MANAGER_WORKERS", "2"))
TOOL_MANAGER_RETRIES = int(os.getenv("APKPT_TOOL_MANAGER_RETRIES", "3"))
TOOL_MANAGER_RETRY_DELAY = float(os.getenv("APKPT_TOOL_MANAGER_RETRY_DELAY", "2"))
INSTALLED_DB_PATH = Path(os.getenv("APKPT_INSTALLED_DB", str(STORAGE_DIR / "installed_tools.db")))
RMS_URL = _configured_web_url("APKPT_RMS_URL", "APKPT_RMS_PORT", "rms")
RMS_PORT = _configured_web_port("APKPT_RMS_PORT", "rms")
ZAP_WEB_URL = _configured_web_url("APKPT_ZAP_WEB_URL", "APKPT_ZAP_WEB_PORT", "zaproxy")
ZAP_WEB_PORT = _configured_web_port("APKPT_ZAP_WEB_PORT", "zaproxy")
TOOL_ALLOWED_HOSTS = {
    host.strip().lower()
    for host in os.getenv(
        "APKPT_TOOL_ALLOWED_HOSTS",
        ",".join((
            "api.github.com", "github.com", "codeload.github.com",
            "objects.githubusercontent.com", "release-assets.githubusercontent.com",
            "raw.githubusercontent.com", "dl.google.com", "developer.android.com",
            "docs.oracle.com", "docs.openssl.org", "www.openssl.org",
            "pypi.org", "files.pythonhosted.org", "zaproxy.org",
            "portswigger.net", "www.chromium.org", "www.bluez.org",
            "www.nordicsemi.com", "developer.nordicsemi.com",
        )),
    ).split(",")
    if host.strip()
}
PROXY_HOST = os.getenv("APKPT_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("APKPT_PROXY_PORT", "8080"))
CA_CERT_PATH = os.getenv("APKPT_CA_CERT_PATH", "")

# ---------------------------------------------------------------- PKI lab
# Local-only lab CA/keystore material. Nothing is installed on a device; any
# later CA deployment remains gated by the invasive/emulator controls above.
PKI_LAB_ENABLED = os.getenv("APKPT_PKI_LAB", "0") == "1"
PKI_DIR = Path(os.getenv("APKPT_PKI_DIR", str(TOOLS_ROOT / "pki")))
PKI_CA_DAYS = max(1, int(os.getenv("APKPT_PKI_CA_DAYS", "365")))
PKI_KEYSTORE_PASSWORD = os.getenv("APKPT_PKI_KEYSTORE_PASSWORD", "changeit")

# ---------------------------------------------------------------- Bluetooth
# Passive/read-only Bluetooth evidence. No radio scan, pairing or bonding is
# ever performed by the platform. The gate only exposes optional local tooling
# status and is off by default.
BLUETOOTH_LAB_ENABLED = os.getenv("APKPT_BLUETOOTH_LAB", "0") == "1"
BLUETOOTHCTL_CMD = os.getenv("APKPT_BLUETOOTHCTL_CMD", "bluetoothctl")
HCITOOL_CMD = os.getenv("APKPT_HCITOOL_CMD", "hcitool")
NRFUTIL_CMD = os.getenv("APKPT_NRFUTIL_CMD", "nrfutil")

# Dynamic analysis runs inside the same MobSF web application by default. A
# dedicated 8002 instance is optional and must be configured explicitly; auto
# mode must not create a dead URL when only one MobSF service is running.
MOBSF_DYNAMIC_URL = (
    _configured_web_url(
        "APKPT_MOBSF_DYNAMIC_URL", "APKPT_MOBSF_DYNAMIC_PORT",
        "mobsf_dynamic", allow_auto=False,
    )
    or MOBSF_URL
)
MOBSF_DYNAMIC_PORT = (
    _configured_web_port("APKPT_MOBSF_DYNAMIC_PORT", "mobsf_dynamic", allow_auto=False)
    or MOBSF_PORT
)
# Explicit endpoint action only: open an authorised MobSF UI in Chromium.
BROWSER_OPEN_ENABLED = os.getenv("APKPT_BROWSER_OPEN", "0") == "1"

# The zero-dependency static dashboard is the active UI. The React source is
# maintained and built, and can be served explicitly with APKPT_WEB_UI=react.
WEB_UI = os.getenv("APKPT_WEB_UI", "static").strip().lower()

# ---------------------------------------------------------------- server
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "APKPT_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]
