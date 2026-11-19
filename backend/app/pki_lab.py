"""Local-only PKI lab material management.

This module never installs a CA on a device and never launches a browser or
emulator. It only creates/imports files under ``APKPT_PKI_DIR`` after the
explicit ``APKPT_PKI_LAB=1`` gate is enabled. Device installation remains a
separate, invasive action outside this module.

For authorized security testing only.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import config

AUTHORIZATION_NOTICE = (
    "For authorized security testing only. Lab CA material is local-only; "
    "never install it on a device outside your authorized test scope."
)


def ca_cert_path() -> Path:
    return config.PKI_DIR / "lab-ca.pem"


def ca_key_path() -> Path:
    return config.PKI_DIR / "lab-ca.key"


def keystore_path() -> Path:
    return config.PKI_DIR / "lab-keystore.p12"


def _write_private(data: bytes, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    try:
        os.chmod(target, 0o600)
    except Exception:
        # Windows does not expose POSIX permissions in the same way.
        pass


def _guess_binary(name: str, override: str = "") -> str:
    if override:
        explicit = Path(override)
        if explicit.is_file():
            return str(explicit)
        if os.name == "nt" and not explicit.suffix:
            for suffix in (".exe", ".bat"):
                candidate = Path(str(explicit) + suffix)
                if candidate.is_file():
                    return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    candidates: list[Path] = []
    if os.name == "nt":
        roots = [
            Path(config.JAVA_CMD).parent if config.JAVA_CMD else Path(""),
            Path(os.getenv("ProgramFiles") or "") / "Java",
            Path(os.getenv("ProgramFiles(x86)") or "") / "Java",
            Path(os.getenv("LOCALAPPDATA") or "") / "Programs" / "Eclipse Adoptium",
            Path(os.getenv("LOCALAPPDATA") or "") / "Programs" / "Microsoft",
            Path("C:\\Program Files\\OpenSSL-Win64\\bin"),
            Path("C:\\Program Files\\OpenSSL-Win32\\bin"),
            config.ANDROID_SDK_ROOT / "build-tools",
            config.ANDROID_SDK_ROOT / "platform-tools",
        ]
        for root in roots:
            if not root or not root.is_dir():
                continue
            candidates.extend(sorted(root.glob(f"jdk-*/bin/{name}.exe"), reverse=True))
            candidates.extend(sorted(root.glob(f"jre-*/bin/{name}.exe"), reverse=True))
            candidates.append(root / f"{name}.exe")
            candidates.append(root / f"{name}.bat")
    else:
        candidates.extend(
            Path(p) for p in (f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}/bin/{name}")
        )
        jvm = Path("/usr/lib/jvm")
        if jvm.is_dir():
            candidates.extend(sorted(jvm.glob(f"*/bin/{name}"), reverse=True))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _cert_info(cert: x509.Certificate) -> dict[str, Any]:
    try:
        sig_alg = getattr(cert.signature_algorithm_oid, "_name", None) or str(cert.signature_algorithm_oid)
    except Exception:
        sig_alg = "unknown"
    try:
        key_size = getattr(cert.public_key(), "key_size", None)
    except Exception:
        key_size = None
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "serial_hex": hex(cert.serial_number),
        "valid_from": nb.isoformat(),
        "valid_until": na.isoformat(),
        "signature_algorithm": str(sig_alg),
        "key_size": key_size,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }


def _read_cert(path: Path) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except Exception:
        return None


def _gated() -> dict[str, Any] | None:
    if config.PKI_LAB_ENABLED:
        return None
    return {
        "status": "skipped",
        "detail": "PKI lab is disabled. Set APKPT_PKI_LAB=1 and restart the server, then retry with confirm=true.",
        "authorization": AUTHORIZATION_NOTICE,
    }


def status() -> dict[str, Any]:
    cert = _read_cert(ca_cert_path())
    java_cmd = os.getenv("APKPT_JAVA_CMD", "").strip() or config.JAVA_CMD
    java_keytool = str(Path(java_cmd).parent / "keytool") if java_cmd else ""
    keytool_override = os.getenv("APKPT_KEYTOOL_CMD", "").strip()
    if not keytool_override:
        keytool_override = java_keytool if os.getenv("APKPT_JAVA_CMD", "").strip() else config.KEYTOOL_CMD
    openssl_override = os.getenv("APKPT_OPENSSL_CMD", "").strip() or config.OPENSSL_CMD
    tools = {
        "keytool": _guess_binary("keytool", keytool_override),
        "openssl": _guess_binary("openssl", openssl_override),
        "apksigner": _guess_binary("apksigner", config.APKSIGNER_CMD),
    }
    return {
        "enabled": bool(config.PKI_LAB_ENABLED),
        "directory": str(config.PKI_DIR),
        "authorization": AUTHORIZATION_NOTICE,
        "ca": {
            "path": str(ca_cert_path()),
            "exists": ca_cert_path().exists(),
            "key_path": str(ca_key_path()),
            "key_exists": ca_key_path().exists(),
            "proxy_ca_configured": bool(config.CA_CERT_PATH),
            "proxy_ca_path": config.CA_CERT_PATH or "",
            "details": _cert_info(cert) if cert else None,
        },
        "keystore": {
            "path": str(keystore_path()),
            "exists": keystore_path().exists(),
            "password_configured": bool(config.PKI_KEYSTORE_PASSWORD),
        },
        "tools": {
            name: {"available": bool(path), "path": path}
            for name, path in tools.items()
        },
        "device_installation": {
            "performed_by_platform": False,
            "requires": "APKPT_ALLOW_INVASIVE=1, APKPT_EMULATOR_AUTO=1 and an explicit device action",
            "detail": "This API only manages local lab files; it never modifies a device.",
        },
    }


def generate_ca(common_name: str = "APKPT Lab CA", days: int | None = None, force: bool = False) -> dict[str, Any]:
    blocked = _gated()
    if blocked:
        return blocked
    if ca_cert_path().exists() and not force:
        return {
            "status": "skipped",
            "detail": "A lab CA already exists. Set force=true to replace it.",
            "ca": status()["ca"],
        }

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APKPT Authorized Test Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or "APKPT Lab CA"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    lifetime = config.PKI_CA_DAYS if days is None else max(1, int(days))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=lifetime))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(
        cert.public_bytes(serialization.Encoding.PEM), ca_cert_path(),
    )
    _write_private(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        ca_key_path(),
    )
    return {
        "status": "completed",
        "detail": f"Generated lab CA '{common_name}' valid for {lifetime} day(s).",
        "ca": status()["ca"],
        "authorization": AUTHORIZATION_NOTICE,
    }


def import_ca(pem_text: str = "", path: str = "", force: bool = False) -> dict[str, Any]:
    blocked = _gated()
    if blocked:
        return blocked
    source = (pem_text or "").strip()
    if not source and path:
        try:
            source = Path(path).read_text(encoding="utf-8")
        except Exception as exc:
            return {"status": "failed", "detail": f"could not read CA file: {exc}"}
    if not source:
        return {"status": "failed", "detail": "provide pem_text or path"}
    try:
        cert = x509.load_pem_x509_certificate(source.encode("utf-8"))
    except Exception as exc:
        return {"status": "failed", "detail": f"invalid PEM certificate: {exc}"}
    if ca_cert_path().exists() and not force:
        return {
            "status": "skipped",
            "detail": "A lab CA already exists. Set force=true to replace it.",
            "ca": status()["ca"],
        }
    _write_private(cert.public_bytes(serialization.Encoding.PEM), ca_cert_path())
    return {
        "status": "completed",
        "detail": "Imported lab CA certificate into local PKI storage.",
        "ca": status()["ca"],
        "authorization": AUTHORIZATION_NOTICE,
    }


def generate_keystore(alias: str = "apkpt-lab", password: str | None = None, force: bool = False) -> dict[str, Any]:
    blocked = _gated()
    if blocked:
        return blocked
    if keystore_path().exists() and not force:
        return {
            "status": "skipped",
            "detail": "A lab keystore already exists. Set force=true to replace it.",
            "keystore": status()["keystore"],
        }
    from cryptography.hazmat.primitives.serialization import pkcs12

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _read_cert(ca_cert_path())
    ca_key = None
    if ca_cert and ca_key_path().exists():
        try:
            ca_key = serialization.load_pem_private_key(ca_key_path().read_bytes(), password=None)
        except Exception:
            ca_key = None

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, alias or "apkpt-lab")])
    ca_signed = ca_cert is not None and ca_key is not None
    issuer = ca_cert.subject if ca_signed else subject
    signer = ca_key if ca_signed else leaf_key
    now = dt.datetime.now(dt.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=config.PKI_CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(signer, hashes.SHA256())
    )
    secret = (password or config.PKI_KEYSTORE_PASSWORD or "changeit").encode("utf-8")
    payload = pkcs12.serialize_key_and_certificates(
        (alias or "apkpt-lab").encode("utf-8"), leaf_key, leaf, None,
        serialization.BestAvailableEncryption(secret),
    )
    _write_private(payload, keystore_path())
    detail = "Generated local PKCS#12 lab keystore."
    if ca_signed:
        detail += " Certificate was signed by the local lab CA."
    elif ca_cert is not None:
        detail += " Imported lab CA has no local key; generated a self-signed lab certificate instead."
    else:
        detail += " No lab CA found; generated a self-signed lab certificate."
    return {
        "status": "completed",
        "detail": detail,
        "keystore": {
            **status()["keystore"],
            "ca_signed": ca_signed,
            "certificate": _cert_info(leaf),
        },
        "authorization": AUTHORIZATION_NOTICE,
    }
