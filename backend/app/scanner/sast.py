"""Static analysis (SAST) rules for Android APKs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .apk import ApkPackage, attr
from .rules import (
    LOGCAT_RE,
    OBFUSCATION_RE,
    PINNING_TOKENS,
    ROOT_TOKENS,
    SAFE_STORAGE_TOKENS,
    SECRET_PATTERNS,
    SENSITIVE_LOG_RE,
    SQLI_TOKENS,
    STRONG_CRYPTO_RE,
    TLS_BYPASS_TOKENS,
    UNSAFE_STORAGE_TOKENS,
    WEBVIEW_DANGEROUS,
    WEAK_CRYPTO_RE,
    WEAK_CRYPTO_TOKENS,
    excerpt,
    finding,
    is_benign_pki_string,
)


@dataclass
class SastContext:
    apk: ApkPackage
    manifest: dict[str, Any]
    summary: dict[str, Any]
    network_config: dict[str, Any] | None
    app_node: dict[str, Any] | None
    extra_strings: list[str] = field(default_factory=list)

    @property
    def all_strings(self) -> list[str]:
        # PKI tool/certificate artifact names are benign local-lab evidence and
        # must not be reported as suspicious or malware-like strings.
        merged = [s for s in self.apk.all_strings if not is_benign_pki_string(s)]
        for s in self.extra_strings:
            if not is_benign_pki_string(s) and s not in merged:
                merged.append(s)
        return merged

    def containing(self, token: str, limit: int = 8, case_sensitive: bool = False) -> list[str]:
        out: list[str] = []
        needle = token if case_sensitive else token.lower()
        for s in self.all_strings:
            hay = s if case_sensitive else s.lower()
            if needle in hay:
                out.append(s)
            if len(out) >= limit:
                break
        return out


Rule = Callable[[SastContext], list[dict[str, Any]]]


# ---------------------------------------------------------------- manifest rules
def rule_debuggable(ctx: SastContext) -> list[dict[str, Any]]:
    if ctx.summary.get("debuggable") is not True:
        return []
    return [
        finding(
            "SAST-DEBUGGABLE",
            "Application is debuggable",
            "high",
            description="android:debuggable=\"true\" allows any attacker with physical access or a malicious app "
            "with the right permissions to attach a debugger, extract data and modify runtime behaviour.",
            evidence="AndroidManifest.xml -> <application android:debuggable=\"true\">",
            remediation="Set android:debuggable=\"false\" in release builds and use a separate debug variant only.",
            location="AndroidManifest.xml",
            cwe="CWE-489",
            masvs="MASVS-RESILIENCE-2",
            confidence="high",
            references=["https://mas.owasp.org/MASTG/0x05i-Testing-Resiliency-Against-Reverse-Engineering/"],
        )
    ]


def rule_backup(ctx: SastContext) -> list[dict[str, Any]]:
    if ctx.summary.get("allow_backup") is not True:
        return []
    rules_xml = attr(ctx.app_node, "fullBackupContent") or attr(ctx.app_node, "dataExtractionRules")
    if rules_xml:
        return []
    return [
        finding(
            "SAST-ALLOW-BACKUP",
            "Unrestricted application backup",
            "medium",
            description="android:allowBackup=\"true\" without backup rules lets data be copied off the device "
            "via adb backup, including SharedPreferences and databases.",
            evidence="AndroidManifest.xml -> <application android:allowBackup=\"true\">",
            remediation="Set android:allowBackup=\"false\" or define explicit include/exclude rules with "
            "android:fullBackupContent / android:dataExtractionRules.",
            location="AndroidManifest.xml",
            cwe="CWE-530",
            masvs="MASVS-STORAGE-2",
            confidence="high",
        )
    ]


def rule_cleartext(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if ctx.summary.get("uses_cleartext_traffic") is True:
        out.append(
            finding(
                "SAST-CLEARTEXT-MANIFEST",
                "Cleartext network traffic permitted",
                "high",
                description="android:usesCleartextTraffic=\"true\" permits unencrypted HTTP traffic, "
                "exposing data to interception and modification.",
                evidence="AndroidManifest.xml -> <application android:usesCleartextTraffic=\"true\">",
                remediation="Remove the attribute (defaults to false for targetSdk >= 28) and use HTTPS everywhere.",
                location="AndroidManifest.xml",
                cwe="CWE-319",
                masvs="MASVS-NETWORK-1",
                confidence="high",
            )
        )
    nsc = ctx.network_config or {}
    if nsc.get("cleartext_traffic_permitted") is True:
        out.append(
            finding(
                "SAST-CLEARTEXT-NSC",
                "Cleartext traffic allowed by network security config",
                "high",
                description="The network security configuration sets cleartextTrafficPermitted=\"true\" globally.",
                evidence=f"Network security config: {nsc.get('resource')}",
                remediation="Restrict cleartext to explicit debug-only domains or remove it entirely.",
                location=str(nsc.get("resource")),
                cwe="CWE-319",
                masvs="MASVS-NETWORK-1",
                confidence="high",
            )
        )
    for domain in nsc.get("domains", []):
        if domain.get("cleartext") is True:
            out.append(
                finding(
                    "SAST-CLEARTEXT-DOMAIN",
                    "Cleartext traffic allowed for a domain",
                    "medium",
                    description="A <domain> entry explicitly permits cleartext traffic.",
                    evidence=str(domain),
                    remediation="Use HTTPS and TLS for this domain.",
                    location=str(nsc.get("resource")),
                    cwe="CWE-319",
                    masvs="MASVS-NETWORK-1",
                )
            )
    urls = []
    for s in ctx.all_strings:
        for url in re.findall(r"http://[A-Za-z0-9.\-:]+[^\s\"']*", s):
            if not url.startswith("http://localhost") and not url.startswith("http://127."):
                urls.append(url[:160])
    if urls:
        out.append(
            finding(
                "SAST-HTTP-URLS",
                "Hardcoded HTTP (non-TLS) endpoints",
                "medium",
                description="The application contains plain HTTP URLs. Traffic to these endpoints can be "
                "read and tampered with by a network attacker.",
                evidence=excerpt(urls),
                remediation="Replace all http:// endpoints with https:// and enforce TLS.",
                cwe="CWE-319",
                masvs="MASVS-NETWORK-1",
                confidence="medium",
            )
        )
    return out


def rule_exported_components(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key, label in (
        ("activities", "activity"),
        ("services", "service"),
        ("receivers", "broadcast receiver"),
        ("providers", "content provider"),
    ):
        exposed: list[str] = []
        unguarded: list[str] = []
        for comp in ctx.summary.get(key, []):
            name = comp.get("name") or "(unnamed)"
            filters = comp.get("intent_filters") or []
            exported = comp.get("exported")
            # Pre-Android 12 components with an intent filter are implicitly exported.
            effectively_exported = exported is True or (exported is None and bool(filters))
            if not effectively_exported:
                continue
            exposed.append(f"{name} (exported={exported}, filters={len(filters)})")
            if not comp.get("permission"):
                unguarded.append(name)
            if comp.get("authorities") and comp.get("grant_uri_permissions"):
                out.append(
                    finding(
                        "SAST-PROVIDER-URI-GRANT",
                        "Content provider grants URI permissions",
                        "high",
                        description="An exported content provider with grantUriPermissions can be tricked into "
                        "granting access to content URIs it can read.",
                        evidence=f"{name}, authorities={comp.get('authorities')}",
                        remediation="Set android:grantUriPermissions=\"false\" unless strictly required and validate "
                        "all incoming URIs with android:grantUriPermissions rules.",
                        location="AndroidManifest.xml",
                        cwe="CWE-926",
                        masvs="MASVS-PLATFORM-1",
                    )
                )
        if exposed:
            sev = "high" if unguarded else "medium"
            out.append(
                finding(
                    f"SAST-EXPORTED-{key.upper()}",
                    f"Exported {label} components",
                    sev,
                    description=f"{len(exposed)} {label}(s) are reachable from other apps"
                    + (f"; {len(unguarded)} have no permission guard." if unguarded else "."),
                    evidence="\n".join(exposed[:10]),
                    remediation="Set android:exported=\"false\" where possible. For components that must be "
                    "exported, protect them with a custom android:permission with protectionLevel=\"signature\" "
                    "and validate all Intent input.",
                    location="AndroidManifest.xml",
                    cwe="CWE-926",
                    masvs="MASVS-PLATFORM-1",
                    confidence="high" if exported is True else "medium",
                    references=["https://developer.android.com/guide/topics/manifest/activity-element#exported"],
                )
            )
    for comp in ctx.summary.get("activities", []):
        if comp.get("exported") is True and comp.get("task_affinity") == "":
            out.append(
                finding(
                    "SAST-TASK-AFFINITY",
                    "Exported activity with empty taskAffinity",
                    "medium",
                    description="An exported activity with an empty taskAffinity is susceptible to task hijacking "
                    "(strandHogg-style attacks).",
                    evidence=str(comp.get("name")),
                    remediation="Use a non-empty, unique taskAffinity and set android:exported=\"false\" if possible.",
                    location="AndroidManifest.xml",
                    cwe="CWE-1021",
                    masvs="MASVS-PLATFORM-1",
                )
            )
    return out


def rule_manifest_misc(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if attr(ctx.app_node, "sharedUserId"):
        out.append(
            finding(
                "SAST-SHARED-USER-ID",
                "Legacy shared UID requested",
                "medium",
                description="android:sharedUserId allows this app to share a Linux UID with other apps signed "
                "with the same key, weakening sandbox isolation.",
                evidence=f"android:sharedUserId=\"{attr(ctx.app_node, 'sharedUserId')}\"",
                remediation="Remove android:sharedUserId and use explicit component-level sharing instead.",
                cwe="CWE-269",
                masvs="MASVS-PLATFORM-1",
            )
        )
    if attr(ctx.app_node, "requestLegacyExternalStorage") is True or str(
        attr(ctx.app_node, "requestLegacyExternalStorage")
    ).lower() == "true":
        out.append(
            finding(
                "SAST-LEGACY-STORAGE",
                "Legacy external storage requested",
                "low",
                description="android:requestLegacyExternalStorage=\"true\" opts out of scoped storage on Android 10.",
                evidence="AndroidManifest.xml -> <application android:requestLegacyExternalStorage=\"true\">",
                remediation="Migrate to scoped storage and remove this flag.",
                cwe="CWE-276",
                masvs="MASVS-STORAGE-2",
            )
        )
    target = ctx.summary.get("target_sdk")
    if target is not None and target < 28:
        out.append(
            finding(
                "SAST-OLD-TARGET-SDK",
                "Outdated target SDK",
                "medium",
                description=f"targetSdkVersion={target} means the app does not benefit from modern platform "
                "security behaviour (e.g. TLS by default, scoped storage, biometric prompts).",
                evidence=f"targetSdkVersion={target}",
                remediation="Raise targetSdkVersion to a currently supported level and re-test behaviour.",
                cwe="CWE-1104",
                masvs="MASVS-CODE-1",
            )
        )
    min_sdk = ctx.summary.get("min_sdk")
    if min_sdk is not None and min_sdk < 21:
        out.append(
            finding(
                "SAST-OLD-MIN-SDK",
                "Very low minimum SDK",
                "low",
                description=f"minSdkVersion={min_sdk} keeps support for OS versions that no longer receive "
                "security patches.",
                evidence=f"minSdkVersion={min_sdk}",
                remediation="Raise minSdkVersion if the user base allows it.",
                cwe="CWE-1104",
                masvs="MASVS-CODE-1",
            )
        )
    return out


# ---------------------------------------------------------------- code rules
def rule_secrets(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    strings = ctx.all_strings
    for name, severity, pattern in SECRET_PATTERNS:
        hits = [s for s in strings if pattern.search(s)]
        if not hits:
            continue
        out.append(
            finding(
                f"SAST-SECRET-{name.upper().replace(' ', '-').replace('_', '-')}",
                f"Possible {name} embedded in the app",
                severity,
                description=f"A string matching the {name} signature was found in the APK. Anything shipped "
                "inside an APK can be extracted by an attacker; secrets must never be client-side.",
                evidence=excerpt(hits),
                remediation="Move the credential to a trusted backend, rotate the exposed credential immediately, "
                "and add a secret-scanner to CI.",
                cwe="CWE-798",
                masvs="MASVS-CODE-1",
                confidence="medium" if severity != "medium" else "low",
                references=["https://mas.owasp.org/MASTG/0x05i-Testing-Resiliency-Against-Reverse-Engineering/"],
            )
        )
    return out


def rule_weak_crypto(ctx: SastContext) -> list[dict[str, Any]]:
    weak = ctx.containing("DES", limit=5) + ctx.containing("RC4", limit=5)
    hits: list[str] = []
    for token in WEAK_CRYPTO_TOKENS:
        hits.extend(ctx.containing(token, limit=4))
    for s in ctx.all_strings:
        if WEAK_CRYPTO_RE.search(s) and not STRONG_CRYPTO_RE.search(s):
            hits.append(s)
    if not hits:
        return []
    strong = any(STRONG_CRYPTO_RE.search(s) for s in ctx.all_strings)
    return [
        finding(
            "SAST-WEAK-CRYPTO",
            "Potential use of weak cryptography",
            "medium" if strong else "high",
            description="References to obsolete or insecure primitives (MD5, SHA-1, DES, RC4, ECB mode) were "
            "found. These can be broken or provide no semantic security.",
            evidence=excerpt(hits),
            remediation="Use AES-256-GCM for symmetric encryption, SHA-256/512 for hashing, and RSA-OAEP or "
            "ECDH for key exchange. Never use ECB mode.",
            cwe="CWE-327",
            masvs="MASVS-CRYPTO-1",
            references=["https://mas.owasp.org/MASTG/0x05d-Testing-Cryptography/"],
        )
    ]


def rule_webview(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for token, label in WEBVIEW_DANGEROUS:
        hits = ctx.containing(token, limit=4)
        if not hits:
            continue
        severity = "high" if ("Interface" in token or "Universal" in token or "debugging" in token) else "medium"
        out.append(
            finding(
                f"SAST-WEBVIEW-{label.upper().replace(' ', '-')[:24]}",
                f"WebView risk: {label}",
                severity,
                description="A dangerous WebView configuration was detected. Combined with untrusted web "
                "content this can lead to JavaScript injection, local file theft or arbitrary code execution.",
                evidence=excerpt(hits),
                remediation="Disable JavaScript unless required, never expose addJavascriptInterface to untrusted "
                "content, disallow file:// access, and disable remote debugging in production.",
                cwe="CWE-749",
                masvs="MASVS-PLATFORM-2",
                location="DEX strings",
            )
        )
    return out


def rule_tls_bypass(ctx: SastContext) -> list[dict[str, Any]]:
    hits: list[str] = []
    for token in TLS_BYPASS_TOKENS:
        hits.extend(ctx.containing(token, limit=4))
    out: list[dict[str, Any]] = []
    if hits:
        out.append(
            finding(
                "SAST-TLS-BYPASS",
                "Potential TLS certificate/hostname validation bypass",
                "critical",
                description="The app appears to implement a permissive TrustManager or hostname verifier. "
                "This defeats TLS and allows man-in-the-middle interception of all 'secure' traffic.",
                evidence=excerpt(hits),
                remediation="Use the platform default TrustManager and hostname verifier. For custom trust, "
                "validate the full chain and hostname explicitly; never return true from checkServerTrusted().",
                cwe="CWE-295",
                masvs="MASVS-NETWORK-3",
                confidence="medium",
                references=["https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/"],
            )
        )
    if not any(ctx.containing(t, limit=1) for t in PINNING_TOKENS) and not (
        ctx.network_config or {}
    ).get("pinning_configured"):
        out.append(
            finding(
                "SAST-NO-PINNING",
                "No certificate pinning detected",
                "info",
                description="No certificate pinning configuration was found. Pinning is defence-in-depth; "
                "evaluate it based on the sensitivity of the traffic.",
                evidence="No <pin-set> in network security config and no CertificatePinner class found.",
                remediation="Consider certificate/public-key pinning for high-value endpoints, with a rotation "
                "strategy and backup pins.",
                cwe="CWE-295",
                masvs="MASVS-NETWORK-4",
                confidence="low",
            )
        )
    return out


def rule_storage(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    unsafe = []
    for token in UNSAFE_STORAGE_TOKENS:
        unsafe.extend(ctx.containing(token, limit=4))
    if unsafe:
        out.append(
            finding(
                "SAST-UNSAFE-STORAGE",
                "Insecure file storage APIs",
                "high",
                description="World-readable/writeable modes or public external storage are used. Other apps "
                "may read or modify sensitive files.",
                evidence=excerpt(unsafe),
                remediation="Store sensitive data in internal storage or EncryptedSharedPreferences with "
                "MODE_PRIVATE. Use scoped storage for media.",
                cwe="CWE-732",
                masvs="MASVS-STORAGE-1",
            )
        )
    if not any(ctx.containing(t, limit=1) for t in SAFE_STORAGE_TOKENS):
        out.append(
            finding(
                "SAST-STORAGE-REVIEW",
                "Sensitive data storage requires manual review",
                "info",
                description="No obvious encrypted-storage API usage was detected. This is a hint only and "
                "requires manual verification.",
                evidence="No EncryptedSharedPreferences / SQLCipher / internal-storage markers found.",
                remediation="Review where credentials, tokens and PII are persisted and encrypt them at rest.",
                cwe="CWE-312",
                masvs="MASVS-STORAGE-1",
                confidence="low",
            )
        )
    return out


def rule_sqli(ctx: SastContext) -> list[dict[str, Any]]:
    hits: list[str] = []
    for token in SQLI_TOKENS:
        hits.extend(ctx.containing(token, limit=4))
    if not hits:
        return []
    concatenated = [s for s in hits if "+" in s or "String.format" in s or "%s" in s]
    return [
        finding(
            "SAST-SQLI",
            "Potential SQL injection in local database queries",
            "medium" if concatenated else "low",
            description="Raw SQLite query APIs are used. If the query is built from user or Intent input, "
            "an attacker can read or modify the app's database.",
            evidence=excerpt(hits),
            remediation="Use parameterized queries with selectionArgs and never concatenate untrusted values "
            "into SQL statements.",
            cwe="CWE-89",
            masvs="MASVS-CODE-2",
            confidence="low" if not concatenated else "medium",
        )
    ]


def rule_weak_random(ctx: SastContext) -> list[dict[str, Any]]:
    hits: list[str] = []
    for token in ["java.util.Random", "Math.random()"]:
        hits.extend(ctx.containing(token, limit=4))
    if not hits:
        return []
    return [
        finding(
            "SAST-WEAK-RANDOM",
            "Non-cryptographic random number generator",
            "medium",
            description="java.util.Random or Math.random() is predictable and must not be used for tokens, "
            "session IDs, keys or nonces.",
            evidence=excerpt(hits),
            remediation="Use java.security.SecureRandom for all security-sensitive randomness.",
            cwe="CWE-338",
            masvs="MASVS-CRYPTO-2",
            confidence="low",
        )
    ]


def rule_logging(ctx: SastContext) -> list[dict[str, Any]]:
    hits: list[str] = []
    for s in ctx.all_strings:
        if LOGCAT_RE.search(s):
            hits.append(s)
    sensitive = [s for s in hits if SENSITIVE_LOG_RE.search(s)]
    if not hits:
        return []
    return [
        finding(
            "SAST-LOGGING",
            "Sensitive information may be written to logs",
            "low" if sensitive else "info",
            description="Logging calls were found"
            + (" near sensitive keywords." if sensitive else "."),
            evidence=excerpt(sensitive or hits),
            remediation="Remove verbose logging from production builds and never log credentials, tokens or PII. "
            "Use R8/ProGuard to strip log statements in release builds.",
            cwe="CWE-532",
            masvs="MASVS-STORAGE-2",
            confidence="low",
        )
    ]


def rule_resilience(ctx: SastContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not any(ctx.containing(t, limit=1) for t in ROOT_TOKENS):
        out.append(
            finding(
                "SAST-NO-ROOT-DETECTION",
                "No root detection detected",
                "info",
                description="No common root-detection markers were found. Root detection is defence-in-depth "
                "and can be bypassed, but its absence increases risk on compromised devices.",
                evidence="No root-detection strings found.",
                remediation="Evaluate risk-based root/tamper detection (e.g. Play Integrity API) for sensitive apps.",
                cwe="CWE-921",
                masvs="MASVS-RESILIENCE-1",
                confidence="low",
            )
        )
    obfuscated = [s for s in ctx.dex_strings[:20000] if OBFUSCATION_RE.match(s)]
    if not obfuscated:
        out.append(
            finding(
                "SAST-NO-OBFUSCATION",
                "No obvious code obfuscation",
                "info",
                description="Class names appear unobfuscated, which lowers the effort required for reverse "
                "engineering and targeted tampering.",
                evidence=f"Descriptive class-name markers: {len(obfuscated)}",
                remediation="Enable R8/ProGuard minification and consider commercial obfuscation for "
                "high-value logic.",
                cwe="CWE-656",
                masvs="MASVS-RESILIENCE-3",
                confidence="low",
            )
        )
    return out


def rule_signing(ctx: SastContext) -> list[dict[str, Any]]:
    cert = ctx.apk.certificate
    out: list[dict[str, Any]] = []
    if not cert.get("v1_signature") and not cert.get("v2_or_v3_signature"):
        out.append(
            finding(
                "SAST-UNSIGNED",
                "APK signature missing or unrecognised",
                "high",
                description="No v1 or v2/v3 signature block was detected. An unsigned APK cannot be verified "
                "and is a distribution/integrity risk.",
                evidence=str(cert),
                remediation="Sign release APKs with a managed, protected signing key using apksigner.",
                cwe="CWE-345",
                masvs="MASVS-CODE-3",
                confidence="medium",
            )
        )
    elif cert.get("v1_signature") and not cert.get("v2_or_v3_signature"):
        out.append(
            finding(
                "SAST-V1-ONLY-SIGNATURE",
                "APK uses v1-only signature scheme",
                "medium",
                description="The APK is signed with JAR signing (v1) but no APK Signature Scheme v2/v3 block "
                "was found. v1 leaves parts of the APK unverified and is subject to known weaknesses.",
                evidence="META-INF signature files present; no 'APK Sig Block 42' marker found.",
                remediation="Sign with apksigner using v2 (and v3 where supported) in addition to v1.",
                cwe="CWE-347",
                masvs="MASVS-CODE-3",
                confidence="medium",
            )
        )
    if len(cert.get("signers", [])) > 1:
        out.append(
            finding(
                "SAST-MULTIPLE-SIGNERS",
                "Multiple signer certificates in APK",
                "low",
                description="More than one signer certificate was found in the META-INF signatures. This may "
                "be legitimate key rotation but needs verification.",
                evidence=f"signers={len(cert['signers'])}",
                remediation="Verify that multiple signers are intentional (e.g. v3 key rotation).",
                cwe="CWE-345",
                masvs="MASVS-CODE-3",
                confidence="low",
            )
        )
    return out


RULES: list[Rule] = [
    rule_debuggable,
    rule_backup,
    rule_cleartext,
    rule_exported_components,
    rule_manifest_misc,
    rule_secrets,
    rule_weak_crypto,
    rule_webview,
    rule_tls_bypass,
    rule_storage,
    rule_sqli,
    rule_weak_random,
    rule_logging,
    rule_resilience,
    rule_signing,
]


def run_sast(ctx: SastContext) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:  # a single rule must never kill the scan
            findings.append(
                finding(
                    f"SAST-RULE-ERROR-{rule.__name__.upper()}",
                    "SAST rule failed to execute",
                    "info",
                    description=f"Rule {rule.__name__} raised an exception.",
                    evidence=str(exc),
                    remediation="Report this as a tool issue.",
                    confidence="high",
                )
            )
    return findings
