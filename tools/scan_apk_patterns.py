#!/usr/bin/env python3
"""Pattern-based evidence collector for a decoded Android APK.

Read-only: scans decoded smali/XML/assets for security-relevant indicators and
writes JSON + Markdown evidence. It does not execute the application.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

TEXT_SUFFIXES = {
    ".smali", ".xml", ".properties", ".version", ".json", ".txt", ".md",
    ".textproto", ".mf", ".sf", ".rsa", ".yml", ".yaml", ".ini", ".cfg",
}

PATTERNS: dict[str, dict[str, Any]] = {
    "secret_google_api_key": {
        "severity": "high", "category": "Secrets",
        "regex": r"AIza[0-9A-Za-z_\-]{30,}",
        "note": "Google API key pattern; verify restrictions in the provider console.",
    },
    "secret_firebase_url": {
        "severity": "medium", "category": "Secrets",
        "regex": r"https://[a-z0-9\-]+\.firebaseio\.com|https://[a-z0-9\-]+\.web\.app",
        "note": "Firebase endpoint embedded in the client.",
    },
    "secret_aws_access_key": {
        "severity": "high", "category": "Secrets",
        "regex": r"AKIA[0-9A-Z]{16}",
        "note": "AWS access key identifier pattern.",
    },
    "secret_private_key": {
        "severity": "critical", "category": "Secrets",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "note": "Embedded private key material.",
    },
    "secret_password_literal": {
        "severity": "medium", "category": "Secrets",
        "regex": r"(?i)(password|passwd|pwd|secret|api[_\-]?key|client[_\-]?secret)\s*[\"']?\s*[:=]\s*[\"'][^\"']{4,}[\"']",
        "note": "Hardcoded credential-like literal; manual triage required.",
    },
    "sqli_rawquery": {
        "severity": "high", "category": "SQLi",
        "regex": r"rawQuery\s*\(|execSQL\s*\(|SQLiteDatabase|sqlite3_prepare|sqlcipher",
        "note": "Raw SQLite execution API usage.",
    },
    "sqli_concatenation": {
        "severity": "high", "category": "SQLi",
        "regex": r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^\n]{0,80}(?:\+|\|\||String\.format|StringBuilder)",
        "note": "Possible SQL statement construction with dynamic input.",
    },
    "webview_js_bridge": {
        "severity": "high", "category": "WebView",
        "regex": r"addJavascriptInterface|setJavaScriptEnabled|shouldOverrideUrlLoading|loadUrl\s*\(",
        "note": "WebView exposed/loaded content; review origin and bridge allowlist.",
    },
    "crypto_weak": {
        "severity": "medium", "category": "Cryptography",
        "regex": r"Cipher\.getInstance\s*\([^\n]*(?:DES|MD5|SHA-?1|ECB|RC4|Blowfish)|\bMessageDigest\.getInstance\s*\([^\n]*(?:MD5|SHA-?1)",
        "note": "Weak or deprecated cryptographic primitive.",
    },
    "crypto_hardcoded_key": {
        "severity": "high", "category": "Cryptography",
        "regex": r"SecretKeySpec\s*\(|IvParameterSpec\s*\(|Cipher\.getInstance\s*\(",
        "note": "Key/IV/cipher construction site; verify key source and storage.",
    },
    "network_cleartext": {
        "severity": "high", "category": "Network",
        "regex": r"http://|usesCleartextTraffic|cleartextTrafficPermitted|NetworkSecurityConfig",
        "note": "Cleartext traffic or network security configuration reference.",
    },
    "network_trust_all": {
        "severity": "critical", "category": "Network",
        "regex": r"TrustAllX509TrustManager|checkServerTrusted|verify\s*\([^\n]*X509|AllowAllHostnameVerifier|setHostnameVerifier|onReceivedSslError|SslErrorHandler\.PROCEED",
        "note": "TLS verification override / trust-all pattern.",
    },
    "phi_indicator": {
        "severity": "info", "category": "HIPAA/PHI",
        "regex": r"(?i)(patient|medical|diagnos|prescription|clinical|hipaa|\bphi\b|health\s?record|\bmrn\b|\bssn\b|date\s?of\s?birth|\bdob\b|medication|clinician)",
        "note": "PHI/clinical terminology; review logging, storage and transport.",
    },
    "logging_sensitive": {
        "severity": "medium", "category": "Logging",
        "regex": r"Log\.(?:d|v|i|w|e|wtf)\s*\(",
        "note": "Android log call site; check for PHI/secrets in arguments.",
    },
    "bluetooth": {
        "severity": "info", "category": "Bluetooth",
        "regex": r"(?i)(bluetooth|ble|gatt|BluetoothAdapter|BluetoothLeScanner|BluetoothDevice)",
        "note": "Bluetooth/BLE API usage.",
    },
    "wifi": {
        "severity": "info", "category": "Wi-Fi",
        "regex": r"(?i)(wifi|wifimanager|wifip2p|supplicant|ScanResult|WifiConfiguration)",
        "note": "Wi-Fi API usage.",
    },
    "nfc_usb": {
        "severity": "info", "category": "NFC/USB",
        "regex": r"(?i)(android\.nfc|NfcAdapter|UsbManager|UsbDevice|android\.hardware\.usb)",
        "note": "NFC or USB host API usage.",
    },
    "root_debugger_emulator": {
        "severity": "info", "category": "Runtime hardening",
        "regex": r"(?i)(isDebuggerConnected|Build\.FINGERPRINT|Build\.HARDWARE|Build\.MODEL|Build\.PRODUCT|Build\.TAGS|Superuser|/system/app/Superuser|su\b|Magisk|Xposed|emulator)",
        "note": "Root/debugger/emulator detection indicators (APKiD also reports these).",
    },
    "backup_export": {
        "severity": "high", "category": "Misconfiguration",
        "regex": r"allowBackup=\"true\"|fullBackupContent=|dataExtractionRules=|android:exported=\"true\"",
        "note": "Manifest backup/export configuration; review for PHI exposure.",
    },
    "content_provider": {
        "severity": "medium", "category": "SQLi/Provider",
        "regex": r"content://|ContentProvider|ContentResolver|query\s*\(",
        "note": "Content provider surface; test injection/traversal if exported.",
    },
    "intent_deeplink": {
        "severity": "medium", "category": "IPC",
        "regex": r"BROWSABLE|android\.intent\.action\.VIEW|msauth://|Intent\.ACTION_VIEW|PendingIntent",
        "note": "Deep link / browsable activity / PendingIntent surface.",
    },
}


def scan(decoded: Path, max_per_pattern: int = 40) -> dict[str, Any]:
    files = [
        p for p in decoded.rglob("*")
        if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES and p.stat().st_size < 3_000_000
    ]
    matches: dict[str, list[dict[str, str]]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(decoded)).replace("\\", "/")
        for key, spec in PATTERNS.items():
            found = list(re.finditer(spec["regex"], text))
            if not found:
                continue
            counts[key] += len(found)
            for m in found[:max_per_pattern]:
                line_no = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[line_no - 1][:240] if line_no <= len(text.splitlines()) else m.group(0)[:240]
                matches[key].append({
                    "file": rel,
                    "line": str(line_no),
                    "match": m.group(0)[:180],
                    "snippet": line.strip(),
                })
    return {
        "scanned_files": len(files),
        "patterns": {
            key: {
                **spec,
                "count": counts.get(key, 0),
                "evidence": matches.get(key, []),
            }
            for key, spec in PATTERNS.items()
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# APK pattern scan evidence",
        "",
        f"Scanned text files: **{result['scanned_files']}**",
        "",
        "| Pattern | Category | Severity | Matches | Note |",
        "|---|---|---|---:|---|",
    ]
    for key, item in result["patterns"].items():
        lines.append(
            f"| `{key}` | {item['category']} | {item['severity']} | {item['count']} | {item['note']} |"
        )
    lines += ["", "## Evidence samples", ""]
    for key, item in result["patterns"].items():
        if not item["evidence"]:
            continue
        lines += [f"### {key} ({item['count']} matches)", ""]
        for ev in item["evidence"][:12]:
            lines.append(f"- `{ev['file']}:{ev['line']}` — `{ev['snippet']}`")
        if item["count"] > 12:
            lines.append(f"- _... {item['count'] - 12} more in JSON evidence_")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decoded", required=True, type=Path, help="apktool decoded directory")
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    parser.add_argument("--max-per-pattern", type=int, default=40)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    result = scan(args.decoded, args.max_per_pattern)
    (args.out / "pattern_scan.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (args.out / "pattern_scan.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"scanned={result['scanned_files']} patterns={len(result['patterns'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
