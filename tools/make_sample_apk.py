"""Create a deliberately vulnerable synthetic APK for smoke-testing the scanner.

Usage: python tools/make_sample_apk.py [output.apk]
No Android SDK required. The generated APK uses a plain-text manifest and a
minimal DEX string table, both of which the built-in parser understands.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.insecure.demo"
    android:versionName="1.0"
    android:versionCode="1">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="27" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:label="Insecure Demo"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true" android:taskAffinity="">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="insecureapp" android:host="open" />
            </intent-filter>
        </activity>
        <activity-alias android:name=".AppLinkActivity" android:targetActivity=".MainActivity" android:exported="true">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="insecure.example.com" />
            </intent-filter>
        </activity-alias>
        <service android:name=".SyncService" android:exported="true" />
        <provider android:name=".DataProvider" android:exported="true"
            android:authorities="com.example.insecure.demo.provider"
            android:grantUriPermissions="true" />
    </application>
</manifest>
"""

NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">insecure.example.com</domain>
        <pin-set expiration="2020-01-01T00:00:00Z">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
"""

DEX_STRINGS = [
    "okhttp3.OkHttpClient",
    "okhttp/3.10.0",
    "com.google.firebase.FirebaseApp",
    "AIzaSyDUMMY1234567890DUMMY1234567890ABC",
    "AKIAIOSFODNN7EXAMPLE",
    "http://api.insecure.example.com/v1/login",
    "password=\"hunter2secret\"",
    "Cipher.getInstance(\"DES/ECB/PKCS5Padding\")",
    "MessageDigest.getInstance(\"MD5\")",
    "webView.getSettings().setJavaScriptEnabled(true)",
    "webView.addJavascriptInterface(bridge, \"JSBridge\")",
    "checkServerTrusted",
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "openFileOutput(name, MODE_WORLD_READABLE)",
    "Environment.getExternalStorageDirectory()",
    "db.rawQuery(\"SELECT * FROM users WHERE id=\" + input, null)",
    "java.util.Random",
    "Log.d(\"Auth\", \"token=\" + token)",
    "org.jsoup.Jsoup",
    "jsoup/1.13.1",
    "com.example.insecure.demo.MainActivity",
    "com.crashlytics.android.Crashlytics",
    "com.facebook.ads.Ad",
    "com.google.firebase.analytics.FirebaseAnalytics",
    "libSecShell.so",
    "TracerPid",
    "isDebuggerConnected",
    "debug.internal.example.com",
    "new Intent(\"android.intent.action.VIEW\")",
    "PendingIntent.getActivity(ctx, 0, intent, 0)",
    "IvParameterSpec(new byte[16])",
    "sendTextMessage(\"9001234567\", null, \"msg\", null, null)",
    "gH8sKp2Qw9Zx7Rm4Tn6Vb3Nj1Ld5Fa0Cy8Eu2Is=",
]


def uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def make_dex(strings: list[str]) -> bytes:
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x24, 0x70)       # header_size
    struct.pack_into("<I", header, 0x28, 0x12345678)  # endian tag
    struct.pack_into("<I", header, 0x38, len(strings))  # string_ids_size
    struct.pack_into("<I", header, 0x3C, 0x70)        # string_ids_off

    offsets = bytearray()
    data = bytearray()
    cursor = 0x70 + 4 * len(strings)  # DEX string offsets are absolute file offsets
    for s in strings:
        raw = s.encode("utf-8")
        offsets += struct.pack("<I", cursor)
        data += uleb128(len(raw)) + raw + b"\x00"
        cursor += len(uleb128(len(raw))) + len(raw) + 1
    blob = bytearray(header) + bytearray(offsets) + bytearray(data)
    struct.pack_into("<I", blob, 0x20, len(blob))  # file_size
    return bytes(blob)


def make_elf() -> bytes:
    """A minimal ELF64 ET_DYN with PT_GNU_STACK/PT_GNU_RELRO for hardening tests."""
    blob = bytearray(64 + 2 * 56)
    blob[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", blob, 16,
                     3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    # PT_GNU_STACK with no execute permission.
    struct.pack_into("<IIQQQQQQ", blob, 64, 0x6474E551, 4, 0, 0, 0, 0, 0, 16)
    # PT_GNU_RELRO.
    struct.pack_into("<IIQQQQQQ", blob, 120, 0x6474E552, 4, 0, 0, 0, 0, 0, 8)
    blob.extend(b"__stack_chk_fail\x00__memcpy_chk\x00")
    return bytes(blob)


def main() -> None:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "sample-vulnerable.apk").resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", MANIFEST)
        zf.writestr("classes.dex", make_dex(DEX_STRINGS))
        zf.writestr("res/xml/network_security_config.xml", NSC)
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x00\x00")
        zf.writestr("lib/arm64-v8a/libfoo.so", make_elf())
    print(f"wrote {target} ({target.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
