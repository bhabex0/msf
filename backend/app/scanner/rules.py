"""Detection signatures and finding construction helpers."""

from __future__ import annotations

import re
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# --- credentials / secrets -------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("AWS Access Key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub Token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("Slack Token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Live Secret Key", "critical", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("Firebase Realtime Database URL", "medium", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com", re.I)),
    ("Private Key Material", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", "low", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Credentials in URL", "high", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@", re.I)),
    (
        "Hardcoded Secret Assignment",
        "medium",
        re.compile(r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", re.I),
    ),
]

# --- weak cryptography -----------------------------------------------------
WEAK_CRYPTO_TOKENS = [
    "Cipher.getInstance(\"DES",
    "Cipher.getInstance(\"RC4",
    "Cipher.getInstance(\"MD5",
    "MessageDigest.getInstance(\"MD5",
    "MessageDigest.getInstance(\"SHA-1",
    "MessageDigest.getInstance(\"SHA1",
    "SecretKeySpec",
]
WEAK_CRYPTO_RE = re.compile(
    r"\b(MD5|SHA-?1|DES|3DES|RC4|ARC4|ECB|Blowfish)\b",
    re.I,
)
STRONG_CRYPTO_RE = re.compile(r"\b(AES/GCM|SHA-?256|SHA-?512|ChaCha20|RSA/OAEP)\b", re.I)

# --- WebView ---------------------------------------------------------------
WEBVIEW_DANGEROUS = [
    ("setJavaScriptEnabled(true)", "JavaScript enabled in WebView"),
    ("addJavascriptInterface", "JavaScript-to-Java bridge exposed"),
    ("setAllowFileAccessFromFileURLs(true)", "File access from file:// URLs allowed"),
    ("setAllowUniversalAccessFromFileURLs(true)", "Universal access from file:// URLs allowed"),
    ("setWebContentsDebuggingEnabled(true)", "WebView remote debugging enabled"),
    ("setAllowContentAccess(true)", "Content access allowed in WebView"),
]

# --- TLS / certificate validation -----------------------------------------
TLS_BYPASS_TOKENS = [
    "checkServerTrusted",
    "X509TrustManager",
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "setDefaultHostnameVerifier",
    "TrustAllX509TrustManager",
    "trustAllCerts",
    "trustAllHosts",
    "hostnameVerifier",
    "org.apache.http.conn.ssl.AllowAllHostnameVerifier",
    "SSLContext.getInstance(\"SSLv3",
]
PINNING_TOKENS = ["CertificatePinner", "pin-set", "OkHttpCertificatePinner", "TrustKit"]

# --- unsafe storage --------------------------------------------------------
UNSAFE_STORAGE_TOKENS = [
    "MODE_WORLD_READABLE",
    "MODE_WORLD_WRITEABLE",
    "getExternalStorageDirectory",
    "getExternalStoragePublicDirectory",
    "Environment.getExternalStorageState",
]
SAFE_STORAGE_TOKENS = ["getInternalFilesDir", "getExternalFilesDir", "EncryptedSharedPreferences", "SQLCipher"]

# --- other code smells -----------------------------------------------------
SQLI_TOKENS = ["rawQuery(", "execSQL(", "SQLiteDatabase", "sqlite3"]
RANDOM_TOKENS = ["java.util.Random", "Math.random()"]
LOGCAT_RE = re.compile(r"\bLog\.[dvewi]\s*\(|System\.out\.print", re.I)
SENSITIVE_LOG_RE = re.compile(r"(password|passwd|token|secret|key|credit|ssn|auth)", re.I)
ROOT_TOKENS = [
    "Superuser.apk",
    "/system/bin/su",
    "/system/xbin/su",
    "test-keys",
    "isRooted",
    "RootBeer",
    "com.noshufou.android.su",
    "su -c",
]
OBFUSCATION_RE = re.compile(r"^(?:com|org|net)\.[a-z0-9_]+\.[a-z0-9_]+\.[A-Z][A-Za-z]{3,}$")

# --- PKI tooling is benign evidence, not malware/threat indicators ----------
PKI_BENIGN_EXACT = {
    "keytool", "keytool.exe", "openssl", "openssl.exe", "libcrypto", "libssl",
    "apksigner", "apksigner.bat", "apksigner.exe", "jarsigner", "jarsigner.exe",
    "zipalign", "zipalign.exe", "pkcs12", "pkcs#12", "keystore", "truststore",
    "x509", "x509certificate", "certificate", "public key", "private key entry",
    "ca certificate", "pki", "public key infrastructure", "cert.rsa", "cert.sf",
    "manifest.mf", "android.debug", "apkpt lab ca", "apkpt lab",
}
PKI_FINGERPRINT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.I)


def is_benign_pki_string(value: str) -> bool:
    """True for exact PKI tool/certificate artifact strings that are not threats."""
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return normalized in PKI_BENIGN_EXACT or bool(PKI_FINGERPRINT_RE.match(normalized))


def finding(
    rule_id: str,
    title: str,
    severity: str,
    *,
    description: str,
    evidence: str = "",
    remediation: str = "",
    location: str | None = None,
    cwe: str | None = None,
    masvs: str | None = None,
    confidence: str = "medium",
    category: str = "SAST",
    references: list[str] | None = None,
) -> dict[str, Any]:
    """Build a serialisable finding dict with a stable identifier."""
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "description": description,
        "evidence": evidence[:2000],
        "remediation": remediation,
        "location": location,
        "cwe": cwe,
        "owasp_masvs": masvs,
        "references": references or [],
    }


def excerpt(matches: list[str], max_items: int = 6, width: int = 160) -> str:
    uniq: list[str] = []
    seen: set[str] = set()
    for m in matches:
        m = m.strip()
        if m and m not in seen:
            seen.add(m)
            uniq.append(m[:width])
        if len(uniq) >= max_items:
            break
    return "\n".join(uniq)
