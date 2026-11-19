"""Advanced analysis: deep links, NSC hardening, native ELF hardening,
packer/anti-analysis detection, trackers, entropy secrets, certificate
forensics, attack-chain synthesis, playbooks and compliance mapping.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .apk import ApkPackage, attr, find_all, parse_xml_document
from .rules import PKI_FINGERPRINT_RE, excerpt, finding, is_benign_pki_string

# ---------------------------------------------------------------- signatures
TRACKER_SIGNATURES: list[tuple[str, str, tuple[str, ...]]] = [
    ("Google Analytics", "Analytics", ("com.google.android.gms.analytics", "com.google.analytics.tracking")),
    ("Firebase Analytics", "Analytics", ("com.google.firebase.analytics", "firebaseAnalytics")),
    ("Mixpanel", "Analytics", ("com.mixpanel.android",)),
    ("Amplitude", "Analytics", ("com.amplitude.api",)),
    ("Flurry", "Analytics", ("com.flurry.android",)),
    ("Countly", "Analytics", ("ly.count.android",)),
    ("Umeng", "Analytics", ("com.umeng.analytics",)),
    ("New Relic", "Analytics", ("com.newrelic.agent",)),
    ("Datadog", "Analytics", ("com.datadog.android",)),
    ("Google AdMob", "Ads", ("com.google.android.gms.ads",)),
    ("Facebook Ads", "Ads", ("com.facebook.ads",)),
    ("AppLovin", "Ads", ("com.applovin.sdk",)),
    ("Unity Ads", "Ads", ("com.unity3d.ads",)),
    ("Vungle", "Ads", ("com.vungle.warren",)),
    ("AdColony", "Ads", ("com.adcolony.sdk",)),
    ("MoPub", "Ads", ("com.mopub.mobileads",)),
    ("Tencent Ads", "Ads", ("com.tencent.qq.e",)),
    ("Baidu Ads", "Ads", ("com.baidu.mobads",)),
    ("Crashlytics", "Crash Reporting", ("com.crashlytics.android",)),
    ("Sentry", "Crash Reporting", ("io.sentry.android",)),
    ("Bugsnag", "Crash Reporting", ("com.bugsnag.android",)),
    ("ACRA", "Crash Reporting", ("org.acra.",)),
    ("Firebase Crashlytics NDK", "Crash Reporting", ("libcrashlytics",)),
    ("Facebook SDK", "Social", ("com.facebook.login", "com.facebook.share")),
    ("Twitter Kit", "Social", ("com.twitter.sdk.android",)),
    ("LinkedIn SDK", "Social", ("com.linkedin.android",)),
    ("Telegram SDK", "Social", ("org.telegram.",)),
    ("AppsFlyer", "Attribution", ("com.appsflyer.",)),
    ("Adjust", "Attribution", ("com.adjust.sdk",)),
    ("Branch", "Attribution", ("io.branch.referral",)),
    ("Stripe", "Payments", ("com.stripe.android",)),
    ("PayPal", "Payments", ("com.paypal.android", "com.braintreepayments")),
    ("OneSignal", "Messaging", ("com.onesignal.",)),
    ("Firebase Messaging", "Messaging", ("com.google.firebase.messaging",)),
]

PACKER_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("DexGuard", ("dexguard", "Ldexc", "com.secured")),
    ("ProGuard/R8", ("proguard", "-keep class", "r8.main")),
    ("Allatori", ("allatori",)),
    ("Bangcle/SecShell", ("SecShell", "libSecShell.so", "com.secneo", "com.bangcle")),
    ("Qihoo 360", ("libprotectClass.so", "com.qihoo360.protos")),
    ("Ijiami", ("ijiami", "libexec.so", "com.ijiami")),
    ("Liapp", ("libliapp.so", "com.liapp")),
    ("Tencent Shield", ("libtencentloc.so", "com.tencent.mm.protocal")),
]

ANTI_ANALYSIS_TOKENS = [
    "TracerPid", "/proc/self/status", "isDebuggerConnected", "android.os.Debug",
    "ptrace", "frida", "frida-server", "xposed", "substrate", "magisk",
    "ro.debuggable", "Build.FINGERPRINT", "goldfish", "genymotion", "QEMU",
    "sdk.google", "com.qihoo", "antiDebug", "antiEmulator", "isEmulator",
]

ENTROPY_STOPWORDS_RE = re.compile(
    r"^(?:android|java|javax|kotlin|com|org|net|http|https|www|class|interface|"
    r"package|import|boolean|string|integer|layout|drawable|string|style|color|"
    r"activity|service|provider|receiver|permission|fragment|debug|release|"
    r"okhttp|firebase|google|facebook|content|application|mainactivity)$",
    re.I,
)
ENTROPY_ALPHABET_RE = re.compile(r"^[A-Za-z0-9+/_\-=]{20,120}$")


@dataclass
class AdvancedResult:
    deep_links: list[dict[str, Any]] = field(default_factory=list)
    intent_analysis: dict[str, Any] = field(default_factory=dict)
    network_config_detail: dict[str, Any] = field(default_factory=dict)
    trackers: list[dict[str, str]] = field(default_factory=list)
    apkid: dict[str, Any] = field(default_factory=dict)
    elf_hardening: list[dict[str, Any]] = field(default_factory=list)
    entropy_secrets: list[dict[str, Any]] = field(default_factory=list)
    certificate_analysis: dict[str, Any] = field(default_factory=dict)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    playbook: list[str] = field(default_factory=list)
    compliance: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------- helpers
def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _data_value(data: dict[str, str], key: str) -> str | None:
    for k, v in data.items():
        if k.split(":")[-1] == key:
            return v
    return None


# ---------------------------------------------------------------- deep links / intents
def analyze_deep_links(summary: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    links: list[dict[str, Any]] = []
    for key in ("activities", "activity_alias"):
        for act in summary.get(key, []):
            for flt in act.get("intent_filters", []):
                actions = [str(a) for a in flt.get("actions", [])]
                categories = [str(c) for c in flt.get("categories", [])]
                browsable = any(c.endswith("BROWSABLE") for c in categories)
                for data in flt.get("data", []):
                    scheme = _data_value(data, "scheme")
                    if not scheme:
                        continue
                    host = _data_value(data, "host")
                    links.append(
                        {
                            "activity": act.get("name"),
                            "scheme": scheme,
                            "host": host,
                            "browsable": browsable,
                            "auto_verified": bool(flt.get("auto_verify")),
                            "exported": act.get("exported"),
                            "custom_scheme": scheme not in ("http", "https"),
                        }
                    )

    out: list[dict[str, Any]] = []
    for link in links:
        if not link["browsable"]:
            continue
        if link["custom_scheme"]:
            out.append(
                finding(
                    "ADV-DEEPLINK-CUSTOM",
                    "Unverified custom-scheme deep link",
                    "medium",
                    category="ADVANCED",
                    description="A browsable activity accepts a custom URI scheme. Custom schemes are not "
                    "owned by the app and can be registered by a malicious app, enabling intent hijacking "
                    "and parameter injection.",
                    evidence=str(link),
                    remediation="Prefer verified App Links (https + android:autoVerify=\"true\"), validate all "
                    "deep-link parameters, and never perform privileged actions from a deep link alone.",
                    location="AndroidManifest.xml",
                    cwe="CWE-926",
                    masvs="MASVS-PLATFORM-2",
                    references=["https://mas.owasp.org/MASTG/MASTG-TEST-0028/"],
                )
            )
        elif not link["auto_verified"]:
            out.append(
                finding(
                    "ADV-APPLINK-UNVERIFIED",
                    "HTTPS App Link without autoVerify",
                    "medium",
                    category="ADVANCED",
                    description="A browsable activity uses http/https but does not declare "
                    "android:autoVerify=\"true\", so Android cannot verify domain ownership and the link "
                    "may be handled by a malicious app.",
                    evidence=str(link),
                    remediation="Add an intent-filter with android:autoVerify=\"true\" and publish a valid "
                    "assetlinks.json file on every declared host.",
                    location="AndroidManifest.xml",
                    cwe="CWE-923",
                    masvs="MASVS-PLATFORM-2",
                    references=["https://mas.owasp.org/MASTG/MASTG-TEST-0393/"],
                )
            )
    return links, out


def analyze_intents(strings: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    implicit = [
        s for s in strings
        if re.search(r'new\s+Intent\s*\(\s*["\']android\.intent\.action\.', s, re.I)
        or ("Intent.parseUri" in s and "setPackage" not in s)
    ]
    pending = [s for s in strings if "PendingIntent.get" in s]
    exportedset = [s for s in strings if "setExtrasClassLoader" in s or "getParcelableExtra" in s]
    detail = {
        "implicit_intent_markers": len(implicit),
        "pending_intent_markers": len(pending),
        "parcelable_extra_markers": len(exportedset),
    }
    findings: list[dict[str, Any]] = []
    if implicit:
        findings.append(
            finding(
                "ADV-IMPLICIT-INTENT",
                "Implicit intents used",
                "low",
                category="ADVANCED",
                description="Implicit intents can be resolved by any installed app that declares a matching "
                "intent filter. Sensitive data in extras may leak to a malicious receiver.",
                evidence=excerpt(implicit),
                remediation="Use explicit intents with setPackage() or setComponent() for sensitive data and "
                "validate any data returned via startActivityForResult.",
                masvs="MASVS-PLATFORM-2",
                confidence="low",
            )
        )
    if pending:
        findings.append(
            finding(
                "ADV-PENDING-INTENT",
                "PendingIntent creation requires review",
                "low",
                category="ADVANCED",
                description="PendingIntent objects execute with the originating app's identity. Mutable "
                "PendingIntents can be hijacked to modify the wrapped intent.",
                evidence=excerpt(pending),
                remediation="Use immutable flags (FLAG_IMMUTABLE) unless mutability is required, and set an "
                "explicit component.",
                cwe="CWE-926",
                masvs="MASVS-PLATFORM-2",
                confidence="low",
            )
        )
    return detail, findings


# ---------------------------------------------------------------- network security config
def analyze_network_config(apk: ApkPackage) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    detail: dict[str, Any] = {
        "resources": [],
        "user_ca_trusted": False,
        "debug_user_ca_trusted": False,
        "cleartext_enabled": False,
        "pin_sets": [],
        "expired_pins": [],
    }
    findings: list[dict[str, Any]] = []
    for name in apk.names:
        if not (name.startswith("res/xml/") and name.endswith(".xml")):
            continue
        node = parse_xml_document(apk.read(name, 4 * 1024 * 1024))
        if node is None or node.get("tag") not in ("network-security-config", "networkSecurityConfig"):
            continue
        detail["resources"].append(name)
        for n in find_all(node, "base-config"):
            if str(attr(n, "cleartextTrafficPermitted")).lower() == "true":
                detail["cleartext_enabled"] = True
            for cert in find_all(n, "certificates"):
                if str(attr(cert, "src")) == "user":
                    detail["user_ca_trusted"] = True
        for n in find_all(node, "debug-overrides"):
            for cert in find_all(n, "certificates"):
                if str(attr(cert, "src")) == "user":
                    detail["debug_user_ca_trusted"] = True
        for n in find_all(node, "domain-config"):
            if str(attr(n, "cleartextTrafficPermitted")).lower() == "true":
                detail["cleartext_enabled"] = True
        for n in find_all(node, "pin-set"):
            expiration = attr(n, "expiration")
            pins = [attr(p, "digest") for p in find_all(n, "pin")]
            entry = {"expiration": expiration, "pin_count": len(pins), "resource": name}
            detail["pin_sets"].append(entry)
            if expiration:
                try:
                    exp = datetime.fromisoformat(str(expiration).replace("Z", "+00:00"))
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if exp < datetime.now(timezone.utc):
                        detail["expired_pins"].append(entry)
                except Exception:
                    pass
    if detail["user_ca_trusted"]:
        findings.append(
            finding(
                "ADV-NSC-USER-CA",
                "Network security config trusts user-installed CAs",
                "high",
                category="ADVANCED",
                description="base-config trusts user-installed certificate authorities, so any certificate "
                "added to the device trust store can intercept TLS traffic in production.",
                evidence=", ".join(detail["resources"]),
                remediation="Restrict user CAs to <debug-overrides> only, or remove them entirely.",
                location="res/xml/network_security_config.xml",
                cwe="CWE-295",
                masvs="MASVS-NETWORK-3",
            )
        )
    for entry in detail["expired_pins"]:
        findings.append(
            finding(
                "ADV-PIN-EXPIRED",
                "Certificate pin set has expired",
                "medium",
                category="ADVANCED",
                description="An NSC <pin-set> has an expiration date in the past. Once expired, pinning is "
                "silently disabled.",
                evidence=str(entry),
                remediation="Rotate the pin set and schedule regular renewal.",
                masvs="MASVS-NETWORK-4",
            )
        )
    return detail, findings


# ---------------------------------------------------------------- trackers / packers / entropy
def analyze_trackers(strings: list[str], names: list[str]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    joined = "\n".join(strings[:200_000])
    detected: list[dict[str, str]] = []
    for name, category, markers in TRACKER_SIGNATURES:
        hits = [m for m in markers if m in joined or any(m.lower() in n.lower() for n in names)]
        if hits:
            detected.append({"name": name, "category": category, "evidence": ", ".join(hits[:3])})
    findings: list[dict[str, Any]] = []
    if detected:
        by_cat: dict[str, list[str]] = {}
        for t in detected:
            by_cat.setdefault(t["category"], []).append(t["name"])
        findings.append(
            finding(
                "ADV-TRACKERS",
                "Third-party tracking/analytics SDKs detected",
                "info",
                category="ADVANCED",
                description="Third-party SDKs can collect device identifiers and user data. Verify data-minimisation, "
                "privacy-policy disclosure and the SDK versions for known vulnerabilities.",
                evidence="\n".join(f"{k}: {', '.join(v)}" for k, v in by_cat.items()),
                remediation="Inventory all SDKs, remove unused ones, check their privacy manifests and keep them updated.",
                masvs="MASVS-STORAGE-1",
                confidence="high",
            )
        )
    return detected, findings


def analyze_apkid(strings: list[str], names: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    joined = "\n".join(strings[:200_000])
    packers = []
    for name, markers in PACKER_SIGNATURES:
        hits = [m for m in markers if m.lower() in joined.lower() or any(m.lower() in n.lower() for n in names)]
        if hits:
            packers.append({"name": name, "evidence": ", ".join(hits[:3])})
    anti = [t for t in ANTI_ANALYSIS_TOKENS if t.lower() in joined.lower()]
    detail = {"packers_or_obfuscators": packers, "anti_analysis_tokens": anti[:30]}
    findings: list[dict[str, Any]] = []
    if packers:
        findings.append(
            finding(
                "ADV-PACKER",
                "Packer/protector or obfuscator detected",
                "low",
                category="ADVANCED",
                description="Protector/packer markers were found. Packed APKs hide code from static analysis and "
                "can complicate vulnerability assessment; unpacking may be required.",
                evidence="\n".join(f"{p['name']}: {p['evidence']}" for p in packers),
                remediation="Unpack the DEX for analysis (e.g. with a runtime dump) and verify the protection is "
                "not masking malicious behaviour.",
                masvs="MASVS-RESILIENCE-3",
                confidence="medium",
            )
        )
    if anti:
        findings.append(
            finding(
                "ADV-ANTI-ANALYSIS",
                "Anti-analysis / environment-detection markers",
                "low",
                category="ADVANCED",
                description="Strings associated with debugger, emulator, root or hooking detection were found. "
                "These mechanisms can hinder dynamic testing and indicate defensive hardening.",
                evidence=excerpt(anti),
                remediation="Document these checks and ensure they do not weaken genuine security controls.",
                masvs="MASVS-RESILIENCE-1",
                confidence="low",
            )
        )
    return detail, findings


def analyze_entropy(strings: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    for s in strings[:150_000]:
        if is_benign_pki_string(s) or PKI_FINGERPRINT_RE.match(s.strip()):
            continue
        if not ENTROPY_ALPHABET_RE.match(s):
            continue
        if ENTROPY_STOPWORDS_RE.match(s.split(".")[0]):
            continue
        if s.lower() in ("aaaaaaaaaaaaaaaaaaaa", "00000000000000000000"):
            continue
        e = shannon_entropy(s)
        if e >= 4.3 and not s.startswith(("http", "com.", "org.", "net.", "android.")):
            candidates.append({"value": s[:120], "entropy": round(e, 2), "length": len(s)})
    candidates.sort(key=lambda c: c["entropy"], reverse=True)
    candidates = candidates[:8]
    findings: list[dict[str, Any]] = []
    if candidates:
        findings.append(
            finding(
                "ADV-HIGH-ENTROPY",
                "High-entropy string constants",
                "info",
                category="ADVANCED",
                description="High-entropy strings can indicate embedded keys, encrypted payloads or encoded "
                "configuration. Manual review is required to distinguish secrets from harmless data.",
                evidence="\n".join(f"{c['value']} (entropy={c['entropy']})" for c in candidates[:5]),
                remediation="Review each candidate; move any real credential to a backend and rotate it.",
                cwe="CWE-798",
                masvs="MASVS-CODE-1",
                confidence="low",
            )
        )
    return candidates, findings


# ---------------------------------------------------------------- ELF hardening
def parse_elf(data: bytes) -> dict[str, Any]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {}
    cls, enc = data[4], data[5]
    if enc == 1:
        endian = "<"
    elif enc == 2:
        endian = ">"
    else:
        return {}
    try:
        if cls == 1:
            e_type, _, _, _e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHIIIIIHHHHHH", data, 16
            )
            ph_fmt, ph_size = endian + "IIIIIIII", 32
        elif cls == 2:
            e_type, _, _, _e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHIQQQIHHHHHH", data, 16
            )
            ph_fmt, ph_size = endian + "IIQQQQQQ", 56
        else:
            return {}
    except Exception:
        return {}

    result: dict[str, Any] = {
        "class": "ELF32" if cls == 1 else "ELF64",
        "type": "ET_DYN" if e_type == 3 else "ET_EXEC" if e_type == 2 else str(e_type),
        "pie": e_type == 3,
        "nx_stack": None,
        "relro": False,
        "full_relro": False,
        "canary": b"__stack_chk_fail" in data or b"__stack_chk_guard" in data,
        "fortify": any(s in data for s in (b"__memcpy_chk", b"__printf_chk", b"__sprintf_chk")),
        "rpath": False,
        "runpath": False,
        "stripped": True,
    }

    dynamic_blob = b""
    for i in range(min(e_phnum, 128)):
        off = e_phoff + i * e_phentsize
        if off + ph_size > len(data):
            break
        vals = struct.unpack_from(ph_fmt, data, off)
        if cls == 1:
            p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags, _align = vals
        else:
            p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = vals
        if p_type == 0x6474E551:  # PT_GNU_STACK
            result["nx_stack"] = not bool(p_flags & 1)
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            result["relro"] = True
        elif p_type == 2 and p_filesz < 8 * 1024 * 1024:  # PT_DYNAMIC
            dynamic_blob = data[p_offset:p_offset + p_filesz]

    if dynamic_blob:
        entry_fmt, entry_size = (endian + "II", 8) if cls == 1 else (endian + "QQ", 16)
        for off in range(0, len(dynamic_blob) - entry_size + 1, entry_size):
            try:
                tag, val = struct.unpack_from(entry_fmt, dynamic_blob, off)
            except Exception:
                break
            if tag == 0:
                break
            if tag == 15:
                result["rpath"] = True
            elif tag == 29:
                result["runpath"] = True
            elif tag == 24:
                result["full_relro"] = True
            elif tag == 0x6FFFFFFB and (val & 0x2):
                result["full_relro"] = True

    try:
        if e_shnum and e_shentsize:
            sh_fmt = endian + ("IIIIIIIIII" if cls == 1 else "IIQQQQIIQQ")
            sh_size = 40 if cls == 1 else 64
            shstr_off = e_shoff + e_shstrndx * e_shentsize
            if shstr_off + sh_size <= len(data):
                sh = struct.unpack_from(sh_fmt, data, shstr_off)
                names_offset, names_size = sh[4], sh[5]
                names = data[names_offset:names_offset + names_size]
                for i in range(min(e_shnum, 256)):
                    sh = struct.unpack_from(sh_fmt, data, e_shoff + i * e_shentsize)
                    name_off = sh[0]
                    if name_off < len(names):
                        name = names[name_off:names.find(b"\x00", name_off)].decode("utf-8", "replace")
                        if name == ".symtab":
                            result["stripped"] = False
                            break
    except Exception:
        pass
    return result


def analyze_elf_libraries(apk: ApkPackage) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    libs: list[dict[str, Any]] = []
    for name in apk.names:
        if not (name.startswith("lib/") and name.endswith(".so")):
            continue
        parsed = parse_elf(apk.read(name, 20 * 1024 * 1024))
        if not parsed:
            continue
        parsed["name"] = name.rsplit("/", 1)[-1]
        parsed["path"] = name
        libs.append(parsed)
    findings: list[dict[str, Any]] = []
    weak = [lib for lib in libs if lib.get("nx_stack") is False or not lib.get("full_relro") or not lib.get("canary")]
    if weak:
        findings.append(
            finding(
                "ADV-ELF-HARDENING",
                "Native libraries with missing hardening",
                "low",
                category="ADVANCED",
                description="Some bundled native libraries lack NX stack, full RELRO or stack-protector "
                "canaries, increasing the impact of memory-corruption bugs.",
                evidence="\n".join(
                    f"{l['name']}: nx={l.get('nx_stack')}, relro={l.get('full_relro')}, canary={l.get('canary')}"
                    for l in weak[:8]
                ),
                remediation="Rebuild third-party native libraries with -Wl,-z,relro,-z,now -fstack-protector-strong "
                "and prefer updated upstream binaries.",
                cwe="CWE-119",
                masvs="MASVS-CODE-1",
                confidence="medium",
            )
        )
    rpath = [lib for lib in libs if lib.get("rpath") or lib.get("runpath")]
    if rpath:
        findings.append(
            finding(
                "ADV-ELF-RPATH",
                "Native libraries contain RPATH/RUNPATH",
                "medium",
                category="ADVANCED",
                description="An embedded RPATH/RUNPATH can cause dynamic linking from attacker-influenced locations "
                "and is a common indicator of repackaging.",
                evidence="\n".join(l["name"] for l in rpath[:8]),
                remediation="Remove RPATH/RUNPATH from production native libraries.",
                cwe="CWE-426",
                masvs="MASVS-CODE-3",
            )
        )
    return libs, findings


# ---------------------------------------------------------------- certificate forensics
def analyze_certificate(cert: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    analysis: dict[str, Any] = {
        "v1": bool(cert.get("v1_signature")),
        "v2_v3": bool(cert.get("v2_or_v3_signature")),
        "v4": False,
        "janus_risk": bool(cert.get("v1_signature")) and not cert.get("v2_or_v3_signature"),
        "signers": [],
    }
    findings: list[dict[str, Any]] = []
    for s in cert.get("signers", []):
        entry = dict(s)
        alg = str(s.get("signature_algorithm", "")).lower()
        entry["sha1_signature"] = "sha1" in alg
        entry["weak_key"] = isinstance(s.get("key_size"), int) and s["key_size"] < 2048
        entry["debug_certificate"] = "android debug" in str(s.get("subject", "")).lower()
        expired = False
        try:
            na = datetime.fromisoformat(str(s.get("valid_until", "")).replace("Z", "+00:00"))
            if na.tzinfo is None:
                na = na.replace(tzinfo=timezone.utc)
            expired = na < datetime.now(timezone.utc)
        except Exception:
            pass
        entry["expired"] = expired
        analysis["signers"].append(entry)

        if entry["debug_certificate"]:
            findings.append(
                finding(
                    "ADV-DEBUG-CERT",
                    "APK signed with the Android debug certificate",
                    "high",
                    category="ADVANCED",
                    description="A debug certificate is not a valid production identity and its private key is "
                    "well known; an attacker can sign a modified APK with the same identity.",
                    evidence=s.get("subject", ""),
                    remediation="Sign release builds with a protected production key and enforce signature-level "
                    "permissions.",
                    cwe="CWE-345",
                    masvs="MASVS-CODE-3",
                    confidence="high",
                )
            )
        if entry["sha1_signature"]:
            findings.append(
                finding(
                    "ADV-SHA1-CERT",
                    "Certificate chain uses SHA-1 signatures",
                    "medium",
                    category="ADVANCED",
                    description="SHA-1 signatures are deprecated and vulnerable to collision attacks in some "
                    "contexts.",
                    evidence=f"{s.get('subject')}: {s.get('signature_algorithm')}",
                    remediation="Re-sign with a SHA-256 certificate chain.",
                    cwe="CWE-328",
                    masvs="MASVS-CODE-3",
                )
            )
        if entry["weak_key"]:
            findings.append(
                finding(
                    "ADV-WEAK-CERT-KEY",
                    "Signing key is shorter than 2048 bits",
                    "medium",
                    category="ADVANCED",
                    description=f"The signing key size ({s.get('key_size')} bits) is below current recommendations.",
                    evidence=str(s.get("subject")),
                    remediation="Use an RSA key of at least 2048 bits (or a strong EC key).",
                    cwe="CWE-326",
                    masvs="MASVS-CODE-3",
                )
            )
    return analysis, findings


# ---------------------------------------------------------------- chains / playbook / compliance
def synthesize_chains(finding_ids: set[str], advanced: AdvancedResult, live_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []

    def add(name: str, sev: str, need: list[str], description: str, remediation: str) -> None:
        # Prefix matching keeps chains working when a rule id is truncated or
        # extended (e.g. WebView labels are shortened in identifier generation).
        if all(any(fid.startswith(prefix) or prefix.startswith(fid) for fid in finding_ids) for prefix in need):
            chains.append(
                {
                    "name": name,
                    "severity": sev,
                    "requires": need,
                    "description": description,
                    "remediation": remediation,
                }
            )

    add("WebView-to-Java RCE chain", "critical",
        ["SAST-WEBVIEW-JAVASCRIPT-ENABLED", "SAST-WEBVIEW-JAVASCRIPT-TO-JAVA-BRIDGE-EXPOSED"],
        "JavaScript is enabled and a Java bridge is exposed. Loading attacker-controlled HTML can invoke "
        "annotated Java methods.",
        "Disable JavaScript for untrusted content and remove addJavascriptInterface on untrusted pages.")
    add("Debug/backup data exfiltration", "high",
        ["SAST-DEBUGGABLE", "SAST-ALLOW-BACKUP"],
        "A debuggable, backup-enabled app lets an attacker attach a debugger and/or extract its private data "
        "with adb backup / run-as.",
        "Disable debuggable and backup in release builds; encrypt sensitive data at rest.")
    add("Exported provider permission leak", "high",
        ["SAST-EXPORTED-PROVIDERS", "SAST-PROVIDER-URI-GRANT"],
        "An exported content provider with URI grants can be abused to read data belonging to other providers.",
        "Set exported=false, remove grantUriPermissions and validate all URIs.")
    add("Deep-link intent injection", "medium",
        ["ADV-DEEPLINK-CUSTOM", "SAST-EXPORTED-ACTIVITIES"],
        "An exported activity accepts unverified deep links, allowing attackers to supply crafted parameters.",
        "Use verified App Links and treat all deep-link input as untrusted.")
    add("TLS failure plus weak crypto", "high",
        ["SAST-TLS-BYPASS", "SAST-WEAK-CRYPTO"],
        "Certificate validation can be bypassed while weak ciphers are in use, exposing data both in transit "
        "and at rest.",
        "Restore platform TLS validation and migrate to AES-GCM/SHA-256.")
    if any(f["id"] in ("LIVE-FIREBASE-OPEN", "LIVE-S3-OPEN") for f in live_findings):
        chains.append(
            {
                "name": "Exposed backend storage",
                "severity": "critical",
                "requires": ["LIVE-FIREBASE-OPEN", "LIVE-S3-OPEN"],
                "description": "A cloud storage endpoint referenced by the app is publicly readable/writable.",
                "remediation": "Restrict authentication rules immediately and rotate exposed data/credentials.",
            }
        )
    return chains


def build_playbook(summary: dict[str, Any], finding_ids: set[str], chains: list[dict[str, Any]]) -> list[str]:
    package = summary.get("package") or "<package>"
    steps: list[str] = [
        f"Confirm scope and obtain written authorization for {package}; capture the APK SHA-256 before testing.",
        "Decompile with jadx/apktool and review AndroidManifest.xml, network_security_config.xml and DEX strings.",
        "Install the APK on an isolated emulator, run DAST and capture logcat while exercising all entry points.",
        "Configure an intercepting proxy (Burp/ZAP) and verify TLS validation/pinning on every endpoint.",
    ]
    if "SAST-DEBUGGABLE" in finding_ids:
        steps.append(f"Verify runtime debuggability: adb shell dumpsys package {package} | grep DEBUGGABLE, then try adb shell run-as {package} ls.")
    if "SAST-EXPORTED-ACTIVITIES" in finding_ids:
        steps.append(f"Enumerate exported activities with adb shell dumpsys package {package} and launch each with am start -n, supplying hostile Intent extras.")
    if "SAST-EXPORTED-PROVIDERS" in finding_ids:
        steps.append(f"Query each provider with adb shell content query --uri content://<authority> and test path traversal with ..%2f sequences.")
    if any(x.startswith("ADV-DEEPLINK") for x in finding_ids):
        steps.append(f"Test deep links: adb shell am start -a android.intent.action.VIEW -d '<scheme>://host/path?param=payload' {package}.")
    if "SAST-TLS-BYPASS" in finding_ids:
        steps.append("Attempt MITM with a self-signed CA; if accepted, document the exact trust-manager/verifier bypass location.")
    if "SAST-WEAK-CRYPTO" in finding_ids:
        steps.append("Locate weak primitives in decompiled code and demonstrate collisions/reversible encryption with crafted input.")
    if any(x.startswith("PKI-") for x in finding_ids):
        steps.append(
            "Verify the signing identity with apksigner verify --print-certs and keytool -printcert; "
            "compare SHA-256 fingerprints and test user-CA trust only inside the authorized lab."
        )
    if "SAST-SECRET" in "".join(finding_ids):
        steps.append("Rotate every discovered credential and check whether it grants live access (with authorization).")
    for chain in chains[:3]:
        steps.append(f"Validate the '{chain['name']}' attack chain end-to-end and record a proof of concept.")
    steps.append("Re-test after remediation, regenerate the report and archive evidence with timestamps.")
    return steps[:10]


OWASP_TOP10_BY_RULE = {
    "PKI-USER-CA": "M3", "PKI-CLEARTEXT": "M3", "PKI-": "M5",
    "SAST-EXPORTED": "M1", "ADV-DEEPLINK": "M1", "ADV-IMPLICIT": "M1", "ADV-PENDING": "M1",
    "SAST-DEBUGGABLE": "M1", "SAST-TLS": "M3", "SAST-CLEARTEXT": "M3", "ADV-NSC": "M3",
    "SAST-HTTP": "M3", "SAST-SECRET": "M2", "ADV-HIGH-ENTROPY": "M2", "SAST-UNSAFE-STORAGE": "M2",
    "SAST-ALLOW-BACKUP": "M2", "SAST-LOGGING": "M2", "SAST-WEAK-CRYPTO": "M5", "ADV-SHA1": "M5",
    "SAST-WEAK-RANDOM": "M5", "SAST-SQLI": "M7", "SAST-WEBVIEW": "M7", "SAST-V1": "M8",
    "ADV-PACKER": "M8", "ADV-ANTI": "M9", "SAST-NO-OBFUSCATION": "M9", "SCA-": "M6",
    "LIVE-": "M6", "ADV-TRACKERS": "M2", "ADV-ELF": "M8",
}


def build_compliance(findings: list[dict[str, Any]]) -> dict[str, Any]:
    masvs: dict[str, int] = {}
    owasp: dict[str, int] = {f"M{i}": 0 for i in range(1, 11)}
    for f in findings:
        masvs_id = str(f.get("owasp_masvs") or "")
        if masvs_id.startswith("MASVS-"):
            parts = masvs_id.split("-")
            if len(parts) >= 2:
                cat = parts[1]
                masvs[cat] = masvs.get(cat, 0) + 1
        fid = str(f.get("id", ""))
        for prefix, category in OWASP_TOP10_BY_RULE.items():
            if fid.startswith(prefix):
                owasp[category] = owasp.get(category, 0) + 1
                break
    return {
        "masvs_v2_categories": masvs,
        "owasp_mobile_top10": owasp,
        "controls_assessed": len(masvs),
        "total_findings": len(findings),
    }


# ---------------------------------------------------------------- orchestration
def analyze_advanced(
    apk: ApkPackage,
    summary: dict[str, Any],
    strings: list[str],
    certificate: dict[str, Any],
    live_findings: list[dict[str, Any]] | None = None,
    all_findings: list[dict[str, Any]] | None = None,
) -> AdvancedResult:
    result = AdvancedResult()
    deep_links, deep_link_findings = analyze_deep_links(summary)
    result.deep_links = deep_links
    result.findings.extend(deep_link_findings)
    result.intent_analysis, f = analyze_intents(strings)
    result.findings.extend(f)
    result.network_config_detail, f = analyze_network_config(apk)
    result.findings.extend(f)
    result.trackers, f = analyze_trackers(strings, apk.names)
    result.findings.extend(f)
    result.apkid, f = analyze_apkid(strings, apk.names)
    result.findings.extend(f)
    result.entropy_secrets, f = analyze_entropy(strings)
    result.findings.extend(f)
    result.elf_hardening, f = analyze_elf_libraries(apk)
    result.findings.extend(f)
    result.certificate_analysis, f = analyze_certificate(certificate)
    result.findings.extend(f)

    live_findings = live_findings or []
    all_findings = all_findings or []
    ids = {str(x.get("id")) for x in result.findings + live_findings + all_findings}
    result.attack_chains = synthesize_chains(ids, result, live_findings)
    for chain in result.attack_chains:
        result.findings.append(
            finding(
                f"CHAIN-{chain['name'].upper().replace(' ', '-')}",
                f"Attack chain: {chain['name']}",
                chain["severity"],
                category="CHAIN",
                description=chain["description"],
                evidence=", ".join(chain["requires"]),
                remediation=chain["remediation"],
                masvs="MASVS-PLATFORM-1",
                confidence="medium",
            )
        )
    result.playbook = build_playbook(summary, ids, result.attack_chains)
    result.compliance = build_compliance(result.findings + all_findings + live_findings)
    return result
