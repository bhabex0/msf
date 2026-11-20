"""Passive Bluetooth/BLE evidence gathering for Android packages.

This engine only interprets data already extracted from the APK and read-only
local tool availability. It never pairs, connects, scans with a radio, or
modifies a device. Findings are informational evidence for manual review.

For authorized security testing only. Bluetooth tooling is not a malware,
threat or exploit-detection engine.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from .. import config
from .lab import AUTHORIZATION_NOTICE
from .rules import excerpt, finding

NOTICE = (
    "For authorized security testing only. Bluetooth findings are informational "
    "evidence for manual review, not malware, threat or exploit verdicts and "
    "not certifications. Bluetooth tooling is not a malware/threat detection engine."
)
BT_SEVERITY = "info"
DISPOSITION = "Informational Bluetooth evidence only; not a malware, threat or exploit verdict."

BLE_TOKENS = (
    "BluetoothLeScanner", "BluetoothGatt", "BluetoothGattCallback",
    "BluetoothLeAdvertiser", "ScanFilter", "startScan", "onScanResult",
    "writeCharacteristic", "setCharacteristicNotification",
)
CLASSIC_TOKENS = (
    "BluetoothSocket", "BluetoothServerSocket", "createRfcommSocket",
    "createRfcommSocketToServiceRecord", "BluetoothDevice", "A2DP", "HFP",
    "HEADSET", "HID", "SPP", "RFCOMM",
)
PAIRING_TOKENS = (
    "createBond", "setPin", "setPasskey", "Pairing", "pairDevice",
    "JustWorks", "Secure Connections", "bondState",
)
BT_PERMISSION_TOKENS = (
    "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
    "BLUETOOTH_ADVERTISE", "NEARBY_DEVICES", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)


def bluetooth_finding(rule_id: str, title: str, **kwargs: Any) -> dict[str, Any]:
    """Build an informational, explicitly non-accusatory Bluetooth finding."""
    kwargs.pop("severity", None)
    kwargs["description"] = f"{kwargs.get('description', '')} {DISPOSITION}".strip()
    return finding(rule_id, title, BT_SEVERITY, **kwargs)


def _matches(tokens: tuple[str, ...], values: list[str]) -> list[str]:
    lowered = [str(v) for v in values]
    return [token for token in tokens if any(token.lower() in v.lower() for v in lowered)]


def bluetooth_lab_status() -> dict[str, Any]:
    """Read-only local tooling status. Never touches a radio or a device."""
    enabled = bool(getattr(config, "BLUETOOTH_LAB_ENABLED", False))

    def present(command: str) -> bool | None:
        if not enabled:
            return None
        parts = command.split()
        return bool(parts and (shutil.which(parts[0]) or Path(parts[0]).exists()))

    return {
        "enabled": enabled,
        "notice": AUTHORIZATION_NOTICE,
        "tools": {
            "bluetoothctl": present(config.BLUETOOTHCTL_CMD),
            "hcitool": present(config.HCITOOL_CMD),
            "nrfutil": present(config.NRFUTIL_CMD),
        },
        "read_only": True,
        "device_scanning": False,
        "pairing_or_bonding": False,
        "detail": (
            "Set APKPT_BLUETOOTH_LAB=1 to probe local tool availability. This API "
            "only reports tool presence; it never scans, pairs, bonds, or otherwise "
            "modifies a device."
            if not enabled else
            "This API only reports local tool availability. It never scans, pairs, "
            "bonds, or otherwise modifies a device."
        ),
    }


def analyze_bluetooth(
    summary: dict[str, Any] | None = None,
    strings: list[str] | None = None,
) -> dict[str, Any]:
    """Return structured Bluetooth evidence and info findings from an APK."""
    summary = summary or {}
    values = [str(s) for s in (strings or [])]
    findings: list[dict[str, Any]] = []

    permissions = sorted({
        str(p) for p in summary.get("permissions", [])
        if any(token in str(p).upper() for token in BT_PERMISSION_TOKENS)
    })
    ble = _matches(BLE_TOKENS, values)
    classic = _matches(CLASSIC_TOKENS, values)
    pairing = _matches(PAIRING_TOKENS, values)
    uuids = sorted({u.upper() for u in UUID_RE.findall("\n".join(values))})

    if permissions:
        findings.append(bluetooth_finding(
            "BT-PERMISSIONS",
            "Bluetooth-related permissions declared",
            category="BLUETOOTH",
            description="The manifest declares Bluetooth/BLE permissions. Confirm these are required for the app's intended functionality.",
            evidence=", ".join(permissions[:12]),
            remediation="Remove unused Bluetooth permissions from release builds and scope runtime permission requests to the minimum needed.",
            masvs="MASVS-PLATFORM-1",
            confidence="high",
        ))

    if ble:
        findings.append(bluetooth_finding(
            "BT-BLE-SURFACE",
            "Bluetooth Low Energy APIs observed",
            category="BLUETOOTH",
            description="BLE scanner/GATT APIs were observed in the package strings. Review advertised services and characteristics manually.",
            evidence=excerpt(ble),
            masvs="MASVS-NETWORK-1",
            confidence="medium",
        ))

    if classic:
        findings.append(bluetooth_finding(
            "BT-CLASSIC-SURFACE",
            "Classic Bluetooth APIs observed",
            category="BLUETOOTH",
            description="Classic Bluetooth/RFCOMM APIs were observed. Review pairing and data handling manually.",
            evidence=excerpt(classic),
            masvs="MASVS-NETWORK-1",
            confidence="medium",
        ))

    if pairing:
        findings.append(bluetooth_finding(
            "BT-PAIRING-SURFACE",
            "Bluetooth pairing/bonding APIs observed",
            category="BLUETOOTH",
            description="Pairing or bonding APIs were observed. Confirm strong pairing is used in the authorized test scenario.",
            evidence=excerpt(pairing),
            masvs="MASVS-NETWORK-1",
            confidence="medium",
        ))

    if uuids:
        findings.append(bluetooth_finding(
            "BT-UUIDS",
            "BLE/GATT UUID-like values observed",
            category="BLUETOOTH",
            description="UUID-shaped values were observed and may identify GATT services or characteristics. Interpretation requires manual review.",
            evidence=excerpt(uuids),
            confidence="low",
        ))

    ble_scan_without_permission = bool(ble) and not any(
        p.upper().endswith("BLUETOOTH_SCAN") for p in permissions
    )
    if ble_scan_without_permission:
        findings.append(bluetooth_finding(
            "BT-SCAN-PERMISSION",
            "BLE scan APIs without an explicit BLUETOOTH_SCAN permission",
            category="BLUETOOTH",
            description="BLE scan APIs were seen without an explicit BLUETOOTH_SCAN permission. Older Android versions may rely on location permissions instead.",
            evidence=excerpt(ble[:4]),
            masvs="MASVS-PLATFORM-1",
            confidence="low",
        ))

    return {
        "status": "ok",
        "notice": NOTICE,
        "summary": {
            "permissions": permissions,
            "ble_tokens": ble,
            "classic_tokens": classic,
            "pairing_tokens": pairing,
            "uuids": uuids,
            "finding_count": len(findings),
        },
        "lab": bluetooth_lab_status(),
        "findings": findings,
    }
