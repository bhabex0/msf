"""Unit tests for the core scanner utilities. Run: python -m unittest discover -s backend/tests"""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.scanner.apk import attr, find_all, parse_dex_strings, parse_xml_document  # noqa: E402
from app.scanner.sast import run_sast  # noqa: E402
from app.scanner.sca import _version_lt  # noqa: E402

MANIFEST_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app"
 android:versionName="1.2">
 <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/>
 <application android:debuggable="true" android:allowBackup="true">
  <activity android:name=".MainActivity" android:exported="true">
   <intent-filter><action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
  </activity>
 </application>
</manifest>"""


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def make_minimal_dex(strings: list[str]) -> bytes:
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x38, len(strings))
    struct.pack_into("<I", header, 0x3C, 0x70)
    offsets, data = bytearray(), bytearray()
    cursor = 0x70 + 4 * len(strings)
    for s in strings:
        raw = s.encode()
        offsets += struct.pack("<I", cursor)
        data += uleb(len(raw)) + raw + b"\x00"
        cursor += len(uleb(len(raw))) + len(raw) + 1
    blob = bytearray(header) + offsets + data
    struct.pack_into("<I", blob, 0x20, len(blob))
    return bytes(blob)


class FakeCtx:
    def __init__(self, strings: list[str], summary: dict, app_node: dict, manifest: dict):
        self.dex_strings = strings
        self._strings = strings
        self.summary = summary
        self.app_node = app_node
        self.manifest = manifest
        self.network_config = None

    @property
    def all_strings(self):
        return self._strings

    def containing(self, token, limit=8, case_sensitive=False):
        needle = token if case_sensitive else token.lower()
        return [s for s in self._strings if needle in (s if case_sensitive else s.lower())][:limit]


class ParserTests(unittest.TestCase):
    def test_plain_xml_manifest(self):
        node = parse_xml_document(MANIFEST_XML)
        self.assertIsNotNone(node)
        self.assertEqual(attr(node, "package"), "com.test.app")
        app = find_all(node, "application")[0]
        self.assertEqual(attr(app, "debuggable"), "true")
        self.assertEqual(len(find_all(node, "uses-permission")), 0)

    def test_dex_strings(self):
        expected = ["okhttp3.OkHttpClient", "AKIAIOSFODNN7EXAMPLE", "com.test.app.MainActivity"]
        self.assertEqual(parse_dex_strings(make_minimal_dex(expected)), expected)

    def test_version_compare(self):
        self.assertTrue(_version_lt("3.10.0", "3.12.0"))
        self.assertFalse(_version_lt("4.11.0", "3.12.0"))
        self.assertTrue(_version_lt("1.14.1", "1.14.2"))


class SastTests(unittest.TestCase):
    def test_detects_core_issues(self):
        manifest = parse_xml_document(MANIFEST_XML)
        app = find_all(manifest, "application")[0]
        strings = [
            "http://insecure.example.com/login",
            "AKIAIOSFODNN7EXAMPLE",
            "Cipher.getInstance(\"DES/ECB/PKCS5Padding\")",
            "checkServerTrusted",
            "webView.getSettings().setJavaScriptEnabled(true)",
            "MODE_WORLD_READABLE",
        ]
        ctx = FakeCtx(strings, {
            "debuggable": True,
            "allow_backup": True,
            "uses_cleartext_traffic": None,
            "activities": [{"name": ".MainActivity", "exported": True, "permission": None,
                            "intent_filters": [], "task_affinity": None, "authorities": None,
                            "grant_uri_permissions": False}],
            "services": [], "receivers": [], "providers": [],
            "target_sdk": 27, "min_sdk": 21,
        }, app, manifest)
        ids = {f["id"] for f in run_sast(ctx)}
        self.assertIn("SAST-DEBUGGABLE", ids)
        self.assertIn("SAST-ALLOW-BACKUP", ids)
        self.assertIn("SAST-TLS-BYPASS", ids)
        self.assertIn("SAST-HTTP-URLS", ids)
        self.assertIn("SAST-WEAK-CRYPTO", ids)
        self.assertIn("SAST-EXPORTED-ACTIVITIES", ids)


if __name__ == "__main__":
    unittest.main()
