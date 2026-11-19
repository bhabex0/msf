"""Pure-Python APK inspection.

Implements enough of Android's binary XML (AXML) and DEX formats to extract a
manifest, string constants and signing information without external tools.
If an external tool is available it can enrich (never replace) these results.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------- AXML constants
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_NULL = 0x00

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------- helpers
def boolish(value: Any, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    v = str(value).strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    return default


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while off < len(buf):
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, off


def _len8(buf: bytes, off: int) -> tuple[int, int]:
    b = buf[off]
    if b & 0x80:
        return ((b & 0x7F) << 8) | buf[off + 1], off + 2
    return b, off + 1


def _len16(buf: bytes, off: int) -> tuple[int, int]:
    v = _u16(buf, off)
    if v & 0x8000:
        return ((v & 0x7FFF) << 16) | _u16(buf, off + 2), off + 4
    return v, off + 2


# ---------------------------------------------------------------- string pool
def _parse_string_pool(buf: bytes, off: int, chunk_size: int) -> list[str]:
    header_size = _u16(buf, off + 2)
    string_count = _u32(buf, off + 8)
    flags = _u32(buf, off + 16)
    strings_start = _u32(buf, off + 20)
    utf8 = bool(flags & 0x100)
    if string_count > 200_000:
        string_count = 200_000
    offsets_off = off + header_size
    base = off + strings_start
    strings: list[str] = []
    for i in range(string_count):
        if offsets_off + 4 * (i + 1) > len(buf):
            break
        rel = _u32(buf, offsets_off + 4 * i)
        p = base + rel
        if p >= len(buf):
            strings.append("")
            continue
        try:
            if utf8:
                _, p2 = _len8(buf, p)       # character count (UTF-16 units)
                byte_len, p2 = _len8(buf, p2)
                raw = buf[p2 : p2 + byte_len]
                s = raw.decode("utf-8", "replace")
            else:
                char_len, p2 = _len16(buf, p)
                raw = buf[p2 : p2 + char_len * 2]
                s = raw.decode("utf-16-le", "replace")
        except Exception:
            s = ""
        strings.append(s)
    return strings


# ---------------------------------------------------------------- AXML tree
def _typed_value(buf: bytes, pos: int, strings: list[str]) -> str:
    size = _u16(buf, pos)
    data_type = buf[pos + 3]
    data = _u32(buf, pos + 4)
    if data_type == TYPE_NULL:
        return ""
    if data_type == TYPE_STRING:
        return strings[data] if 0 <= data < len(strings) else ""
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if data_type == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if data_type in (TYPE_INT_DEC,):
        return str(data)
    if data_type == TYPE_INT_HEX:
        return f"0x{data:x}"
    return f"0x{data:08x}" if size >= 8 else str(data)


def parse_axml(data: bytes) -> dict[str, Any] | None:
    """Parse a binary Android XML document into a simple element tree dict."""
    if len(data) < 8 or _u16(data, 0) != RES_XML_TYPE:
        return None
    try:
        strings: list[str] = []
        uri_prefix: dict[str, str] = {}
        stack: list[dict[str, Any]] = []
        root: dict[str, Any] | None = None
        off = _u16(data, 2)  # header size, normally 8
        end = min(_u32(data, 4), len(data))

        while off + 8 <= end:
            ctype = _u16(data, off)
            csize = _u32(data, off + 4)
            if csize < 8 or off + csize > len(data):
                break

            if ctype == RES_STRING_POOL_TYPE:
                strings = _parse_string_pool(data, off, csize)
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                pass
            elif ctype == RES_XML_START_NAMESPACE_TYPE:
                prefix = strings[_u32(data, off + 16)] if _u32(data, off + 16) < len(strings) else ""
                uri = strings[_u32(data, off + 20)] if _u32(data, off + 20) < len(strings) else ""
                uri_prefix[uri] = prefix
            elif ctype == RES_XML_END_NAMESPACE_TYPE:
                pass
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                ns = _u32(data, off + 16)
                name_idx = _u32(data, off + 20)
                tag = strings[name_idx] if 0 <= name_idx < len(strings) else ""
                attr_start = _u16(data, off + 24)
                attr_count = _u16(data, off + 28)
                attrs: dict[str, str] = {}
                ap = off + 16 + attr_start
                for i in range(attr_count):
                    if ap + 20 > off + csize:
                        break
                    ans = _u32(data, ap)
                    aname = _u32(data, ap + 4)
                    raw = _u32(data, ap + 8)
                    local = strings[aname] if 0 <= aname < len(strings) else ""
                    uri = strings[ans] if 0 <= ans < len(strings) else ""
                    prefix = uri_prefix.get(uri, "")
                    key = f"{prefix}:{local}" if prefix else local
                    if raw != 0xFFFFFFFF and 0 <= raw < len(strings):
                        value = strings[raw]
                    else:
                        value = _typed_value(data, ap + 12, strings)
                    attrs[key] = value
                    attrs[local] = value  # convenient unprefixed lookup
                    ap += 20

                node = {"tag": tag, "attrs": attrs, "children": [], "text": ""}
                if stack:
                    stack[-1]["children"].append(node)
                else:
                    root = node
                stack.append(node)
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()
            elif ctype == RES_XML_CDATA_TYPE:
                pass
            off += csize
        return root
    except Exception:
        return None


def _etree_to_node(elem: ET.Element) -> dict[str, Any]:
    attrs: dict[str, str] = {}
    for key, value in elem.attrib.items():
        if key.startswith("{"):
            uri, local = key[1:].split("}", 1)
            prefix = "android" if uri == ANDROID_NS else ""
            attrs[f"{prefix}:{local}" if prefix else local] = value
            attrs[local] = value
        else:
            attrs[key] = value
    return {
        "tag": elem.tag.split("}")[-1],
        "attrs": attrs,
        "children": [_etree_to_node(c) for c in elem],
        "text": (elem.text or "").strip(),
    }


def parse_xml_document(data: bytes) -> dict[str, Any] | None:
    """Accept either binary AXML or plain XML."""
    node = parse_axml(data)
    if node is not None:
        return node
    try:
        text = data.decode("utf-8", "replace")
        return _etree_to_node(ET.fromstring(text))
    except Exception:
        return None


def iter_nodes(node: dict[str, Any] | None) -> Iterator[dict[str, Any]]:
    if not node:
        return
    yield node
    for child in node.get("children", []):
        yield from iter_nodes(child)


def find_all(node: dict[str, Any] | None, tag: str) -> list[dict[str, Any]]:
    return [n for n in iter_nodes(node) if n.get("tag") == tag]


def attr(node: dict[str, Any] | None, name: str, default: Any = None) -> Any:
    if not node:
        return default
    attrs = node.get("attrs", {})
    if name in attrs:
        return attrs[name]
    for k, v in attrs.items():
        if k.split(":")[-1] == name:
            return v
    return default


def node_strings(node: dict[str, Any] | None) -> list[str]:
    out: list[str] = []
    for n in iter_nodes(node):
        out.extend(str(v) for v in n.get("attrs", {}).values())
        if n.get("text"):
            out.append(str(n["text"]))
    return out


# ---------------------------------------------------------------- DEX
def parse_dex_strings(data: bytes, limit: int = 250_000) -> list[str]:
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return []
    try:
        count, off = struct.unpack_from("<II", data, 0x38)
        if off <= 0 or count > limit or off + 4 * count > len(data):
            return []
        strings: list[str] = []
        for i in range(count):
            s_off = _u32(data, off + 4 * i)
            if s_off >= len(data):
                continue
            _, p = _uleb128(data, s_off)
            end = data.find(b"\x00", p)
            if end < 0:
                end = min(len(data), p + 4096)
            raw = data[p:end]
            # MUTF-8 is UTF-8-like for the vast majority of constants.
            s = raw.decode("utf-8", "replace").replace("\u0000", "")
            if s:
                strings.append(s)
        return strings
    except Exception:
        return []


# ---------------------------------------------------------------- APK package
class ApkPackage:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.sha256 = hashlib.sha256()
        with open(self.path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                self.sha256.update(chunk)
        self.sha256 = self.sha256.hexdigest()
        self.size_bytes = self.path.stat().st_size
        self.zf = zipfile.ZipFile(self.path)
        self.names = [n for n in self.zf.namelist() if not n.endswith("/")]
        self.manifest = self._read_manifest()
        self.dex_strings: list[str] = []
        self.resource_strings: list[str] = []
        self.certificate: dict[str, Any] = {}
        self._read_strings()
        self._read_certificate()

    def close(self) -> None:
        self.zf.close()

    def read(self, name: str, max_bytes: int = 40 * 1024 * 1024) -> bytes:
        try:
            info = self.zf.getinfo(name)
            if info.file_size > max_bytes:
                return b""
            return self.zf.read(name)
        except Exception:
            return b""

    def _read_manifest(self) -> dict[str, Any] | None:
        return parse_xml_document(self.read("AndroidManifest.xml"))

    def _read_strings(self) -> None:
        seen: set[str] = set()
        for name in self.names:
            if re.match(r"^classes\d*\.dex$", name):
                for s in parse_dex_strings(self.read(name)):
                    if s not in seen:
                        seen.add(s)
                        self.dex_strings.append(s)
        for name in self.names:
            if name.startswith("res/") and name.endswith(".xml"):
                node = parse_xml_document(self.read(name, 4 * 1024 * 1024))
                for s in node_strings(node):
                    if s not in seen:
                        seen.add(s)
                        self.resource_strings.append(s)
        arsc = self.read("resources.arsc", 20 * 1024 * 1024)
        for m in re.finditer(rb"[\x20-\x7e]{5,}", arsc):
            s = m.group().decode("ascii", "replace")
            if s not in seen:
                seen.add(s)
                self.resource_strings.append(s)

    @property
    def all_strings(self) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for s in self.dex_strings + self.resource_strings + node_strings(self.manifest):
            if s not in seen:
                seen.add(s)
                merged.append(s)
        return merged

    def _read_certificate(self) -> None:
        result: dict[str, Any] = {
            "v1_signature": any(
                n.upper().startswith("META-INF/") and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))
                for n in self.names
            ),
            "v2_or_v3_signature": False,
            "signers": [],
            "parse_error": None,
        }
        try:
            with open(self.path, "rb") as fh:
                data = fh.read()
            result["v2_or_v3_signature"] = b"APK Sig Block 42" in data
        except Exception as exc:
            result["parse_error"] = str(exc)

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.serialization import pkcs7

            for name in self.names:
                if not (name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))):
                    continue
                der = self.read(name, 8 * 1024 * 1024)
                try:
                    certs = pkcs7.load_der_pkcs7_certificates(der)
                except Exception:
                    continue
                for cert in certs[:3]:
                    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
                    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
                    try:
                        sig_alg = getattr(cert.signature_algorithm_oid, "_name", None) or str(cert.signature_algorithm_oid)
                    except Exception:
                        sig_alg = "unknown"
                    try:
                        public_key = cert.public_key()
                        key_size = getattr(public_key, "key_size", None)
                        key_algorithm = type(public_key).__name__.replace("PublicKey", "")
                    except Exception:
                        key_size = None
                        key_algorithm = "unknown"
                    try:
                        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    except Exception:
                        fingerprint = ""
                    try:
                        is_ca = bool(
                            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                        )
                    except Exception:
                        is_ca = False
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    result["signers"].append(
                        {
                            "signature_file": name,
                            "subject": subject,
                            "issuer": issuer,
                            "serial_hex": hex(cert.serial_number),
                            "valid_from": nb.isoformat(),
                            "valid_until": na.isoformat(),
                            "signature_algorithm": str(sig_alg),
                            "public_key_algorithm": key_algorithm,
                            "key_size": key_size,
                            "sha256_fingerprint": fingerprint,
                            "basic_constraints_ca": is_ca,
                            "self_signed": subject == issuer,
                        }
                    )
        except ImportError:
            result["parse_error"] = "cryptography not installed; certificate details unavailable"
        except Exception as exc:
            result["parse_error"] = str(exc)
        self.certificate = result

    def manifest_summary(self) -> dict[str, Any]:
        root = self.manifest
        app = next(iter(find_all(root, "application")), None)
        uses_sdk = next(iter(find_all(root, "uses-sdk")), None)

        def sdk_value(key: str) -> int | None:
            v = attr(uses_sdk, key)
            if v is None:
                return None
            try:
                return int(v, 0) if isinstance(v, str) and v.lower().startswith("0x") else int(v)
            except (TypeError, ValueError):
                return None

        def components(tag: str) -> list[dict[str, Any]]:
            out = []
            for n in find_all(root, tag):
                filters = []
                for f in find_all(n, "intent-filter"):
                    filters.append(
                        {
                            "actions": [attr(a, "name") for a in find_all(f, "action")],
                            "categories": [attr(c, "name") for c in find_all(f, "category")],
                            "data": [dict(d.get("attrs", {})) for d in find_all(f, "data")],
                            "auto_verify": boolish(attr(f, "autoVerify"), False),
                        }
                    )
                out.append(
                    {
                        "name": attr(n, "name"),
                        "exported": boolish(attr(n, "exported")),
                        "permission": attr(n, "permission"),
                        "launch_mode": attr(n, "launchMode"),
                        "task_affinity": attr(n, "taskAffinity"),
                        "authorities": attr(n, "authorities"),
                        "grant_uri_permissions": boolish(attr(n, "grantUriPermissions"), False),
                        "intent_filters": filters,
                    }
                )
            return out

        nsc = attr(app, "networkSecurityConfig") if app else None
        return {
            "package": attr(root, "package"),
            "version_name": attr(root, "versionName"),
            "version_code": attr(root, "versionCode"),
            "min_sdk": sdk_value("minSdkVersion"),
            "target_sdk": sdk_value("targetSdkVersion"),
            "compile_sdk": sdk_value("compileSdkVersion"),
            "debuggable": boolish(attr(app, "debuggable")),
            "allow_backup": boolish(attr(app, "allowBackup")),
            "uses_cleartext_traffic": boolish(attr(app, "usesCleartextTraffic")),
            "network_security_config": nsc,
            "permissions": [
                p for p in (attr(n, "name") for n in find_all(root, "uses-permission")) if p
            ],
            "activities": components("activity") + components("activity-alias"),
            "services": components("service"),
            "receivers": components("receiver"),
            "providers": components("provider"),
        }

    def network_security_config(self) -> dict[str, Any] | None:
        nsc = self.manifest_summary().get("network_security_config")
        if nsc:
            candidate = nsc.split("@")[-1].lstrip("/")
            name = candidate if candidate.endswith(".xml") else f"res/xml/{candidate}.xml"
            matches = [n for n in self.names if n.endswith(name) or n.endswith(candidate)]
        else:
            matches = [n for n in self.names if n.startswith("res/xml/") and n.endswith(".xml")]
        for name in matches[:4]:
            node = parse_xml_document(self.read(name, 4 * 1024 * 1024))
            if node is None:
                continue
            base_cleartext = boolish(attr(node, "cleartextTrafficPermitted"))
            domains = []
            for d in find_all(node, "domain"):
                domains.append(
                    {
                        "config": attr(d, "config"),
                        "cleartext": boolish(attr(d, "cleartextTrafficPermitted")),
                    }
                )
            pin_sets = find_all(node, "pin-set")
            return {
                "resource": name,
                "cleartext_traffic_permitted": base_cleartext,
                "domains": domains,
                "pinning_configured": bool(pin_sets),
                "trust_user_certs_debug_only": boolish(attr(node, "debugOverridable"), True),
            }
        return None
