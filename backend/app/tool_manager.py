"""Gated, auditable installation and update jobs for authorized test tooling.

Nothing in this module executes automatically. A dashboard action creates an
explicit job, and every download is restricted to an allowlist of official
hosts. Manual/licensed tools are reported as skipped with setup instructions.
"""

from __future__ import annotations

import hashlib
import html
import importlib.metadata
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx

from . import config, installed_db, pki_lab
from .scanner.lab import open_mobsf_browser

# Admin-configurable via APKPT_TOOL_ALLOWED_HOSTS; official hosts are the default.
ALLOWED_HOSTS = set(config.TOOL_ALLOWED_HOSTS)


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    category: str
    method: str
    description: str
    source_url: str
    homepage: str = ""
    repo: str = ""
    asset_pattern: str = ""
    package: str = ""
    command: str = ""
    executable: str = ""
    version_args: tuple[str, ...] = ("--version",)
    sdk_package: str = ""
    install_note: str = ""
    manual: bool = False
    invasive: bool = False


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        id="apktool", name="apktool", category="reverse", method="github_release",
        description="APK resource decoding and rebuilding.",
        source_url="https://github.com/iBotPeaches/Apktool/releases",
        homepage="https://apktool.org/", repo="iBotPeaches/Apktool",
        asset_pattern=r"apktool_[\d.]+\.jar", command="apktool", executable="apktool.jar",
        install_note="Requires a Java runtime on PATH.",
    ),
    ToolSpec(
        id="jadx", name="jadx", category="reverse", method="github_release",
        description="Dex to Java/Kotlin decompiler.",
        source_url="https://github.com/skylot/jadx/releases",
        homepage="https://github.com/skylot/jadx", repo="skylot/jadx",
        asset_pattern=r"jadx-[\d.]+\.zip", command="jadx", executable="jadx",
        install_note="Requires a Java runtime on PATH.",
    ),
    ToolSpec(
        id="platform-tools", name="ADB / platform-tools", category="device",
        method="google_zip", description="adb and fastboot for authorized devices.",
        source_url="https://developer.android.com/tools/releases/platform-tools",
        homepage="https://developer.android.com/tools/releases/platform-tools",
        command="adb", executable="adb",
    ),
    ToolSpec(
        id="cmdline-tools", name="Android cmdline-tools", category="emulator",
        method="google_zip", description="sdkmanager and avdmanager for SDK setup.",
        source_url="https://developer.android.com/studio#command-tools",
        homepage="https://developer.android.com/studio#command-tools",
        command="sdkmanager", executable="sdkmanager",
        install_note="Requires a Java runtime on PATH.",
    ),
    ToolSpec(
        id="aapt2", name="aapt2", category="reverse", method="sdkmanager",
        description="Android asset packaging tool used for manifest inspection.",
        source_url="https://developer.android.com/tools/aapt2",
        homepage="https://developer.android.com/tools/aapt2",
        command="aapt2", executable="aapt2", sdk_package="build-tools;35.0.0",
        install_note="Install Android cmdline-tools first.",
    ),
    ToolSpec(
        id="apksigner", name="apksigner", category="patch", method="sdkmanager",
        description="Verifies and signs APK packages; used for local PKI lab checks.",
        source_url="https://developer.android.com/studio/command-line/apksigner",
        homepage="https://developer.android.com/studio/command-line/apksigner",
        command="apksigner", executable="apksigner", sdk_package="build-tools;35.0.0",
        version_args=("version",),
        install_note="Install Android cmdline-tools first. Use only on authorized test copies.",
    ),
    ToolSpec(
        id="apkleaks", name="APKLeaks", category="static", method="pip",
        description="Scans APK files for URIs, endpoints and secrets.",
        source_url="https://pypi.org/project/apkleaks/",
        homepage="https://github.com/dwisiswant0/apkleaks",
        package="apkleaks", command="apkleaks",
    ),
    ToolSpec(
        id="apkhunt", name="APKHunt", category="static", method="git",
        description="OWASP MASVS Android static-analysis workbench.",
        source_url="https://github.com/Cyber-Buddy/APKHunt.git",
        homepage="https://github.com/Cyber-Buddy/APKHunt",
        install_note="v2+ runs with Docker Compose; start it manually after cloning.",
    ),
    ToolSpec(
        id="objection", name="objection", category="runtime", method="pip",
        description="Runtime mobile security toolkit backed by Frida.",
        source_url="https://pypi.org/project/objection/",
        homepage="https://github.com/sensepost/objection",
        package="objection", command="objection",
    ),
    ToolSpec(
        id="frida-tools", name="Frida tools", category="runtime", method="pip",
        description="Frida CLI and gadget tooling for instrumented test builds.",
        source_url="https://pypi.org/project/frida-tools/",
        homepage="https://frida.re/",
        package="frida-tools", command="frida",
    ),
    ToolSpec(
        id="mitmproxy", name="mitmproxy", category="proxy", method="pip",
        description="Intercepting proxy and mitmdump listener.",
        source_url="https://pypi.org/project/mitmproxy/",
        homepage="https://mitmproxy.org/",
        package="mitmproxy", command="mitmdump",
    ),
    ToolSpec(
        id="semgrep", name="semgrep", category="static", method="pip",
        description="Static rule engine for decompiled Java/Kotlin source.",
        source_url="https://pypi.org/project/semgrep/",
        homepage="https://semgrep.dev/",
        package="semgrep", command="semgrep",
    ),
    ToolSpec(
        id="mobsf", name="MobSF", category="static", method="pip",
        description="Mobile Security Framework server and CLI dependencies.",
        source_url="https://pypi.org/project/mobsf/",
        homepage="https://mobsf.live/",
        package="mobsf", command="mobsf",
        install_note="Native dependencies vary by OS; see the MobSF installation guide.",
    ),
    ToolSpec(
        id="patch-apk", name="patch-apk.py", category="patch", method="git",
        description="Objection/Frida gadget APK patching wrapper.",
        source_url="https://github.com/NickstaDB/patch-apk.git",
        homepage="https://github.com/NickstaDB/patch-apk",
        command="patch-apk.py", invasive=True,
        install_note="Patching changes signatures; use only on authorized copies.",
    ),
    ToolSpec(
        id="trashdroid", name="TrashDroid", category="dynamic", method="git",
        description="Automated Android DAST framework.",
        source_url="https://github.com/Somchandra17/TrashDroid.git",
        homepage="https://github.com/Somchandra17/TrashDroid",
        command="trashdroid",
        install_note="Python dependencies and an authorized device/emulator are required.",
    ),
    ToolSpec(
        id="drozer", name="drozer", category="dynamic", method="pip",
        description="Android IPC attack-surface framework (OWASP MASTG-TOOL-0015).",
        source_url="https://pypi.org/project/drozer/",
        homepage="https://github.com/ReversecLabs/drozer",
        package="drozer", command="drozer",
        install_note=(
            "Installs the host console only. The agent APK is never installed automatically: "
            "install it manually on an owned device/emulator, then connect explicitly. "
            "Windows hosts should use Docker/WSL. On Python 3.15, upstream PyYAML "
            "builds need MSVC build tools; use Python 3.10-3.14 for the pip install."
        ),
    ),
    ToolSpec(
        id="androguard", name="Androguard", category="static", method="pip",
        description="Android reverse-engineering and static-analysis Python toolkit.",
        source_url="https://pypi.org/project/androguard/",
        homepage="https://github.com/androguard/androguard",
        package="androguard", command="androguard",
        install_note="On Python 3.15, upstream PyYAML builds need MSVC build tools; use Python 3.10-3.14.",
    ),
    ToolSpec(
        id="apkid", name="APKiD", category="static", method="pip",
        description="Detects Android packers, obfuscators and compilers (MASTG-TOOL-0009).",
        source_url="https://pypi.org/project/apkid/",
        homepage="https://github.com/rednaga/APKiD",
        package="apkid", command="apkid",
        install_note="A Java runtime is required for DEX analysis.",
    ),
    ToolSpec(
        id="qark", name="QARK", category="static", method="pip",
        description="LinkedIn Android static analyser with proof-of-concept generation.",
        source_url="https://pypi.org/project/qark/",
        homepage="https://github.com/linkedin/qark",
        package="qark", command="qark",
    ),
    ToolSpec(
        id="rms", name="Runtime Mobile Security (RMS)", category="runtime",
        method="git", description="Frida-based runtime manipulation web interface.",
        source_url="https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security.git",
        homepage="https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security",
        command="rms",
        install_note="Node.js/npm is required to install and start RMS.",
    ),
    ToolSpec(
        id="keytool", name="keytool", category="root", method="manual", manual=True,
        description="Java key and certificate management tool for lab keystores.",
        source_url="https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html",
        homepage="https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html",
        command="keytool", version_args=("-version",),
        install_note="Ships with the JDK; install a JDK or set APKPT_JAVA_CMD. Generate lab-only test keys.",
    ),
    ToolSpec(
        id="openssl", name="OpenSSL", category="root", method="manual", manual=True,
        description="Certificate, CSR and keystore tooling for local test PKI.",
        source_url="https://docs.openssl.org/master/man1/openssl/",
        homepage="https://www.openssl.org/",
        command="openssl", version_args=("version",),
        install_note="Install through the OS package manager or official OpenSSL distribution; use lab-only CA material.",
    ),
    ToolSpec(
        id="bluetoothctl", name="bluetoothctl (BlueZ)", category="device", method="manual", manual=True,
        description="Official BlueZ utility for local Bluetooth adapter inspection.",
        source_url="https://www.bluez.org/",
        homepage="https://www.bluez.org/",
        command="bluetoothctl",
        install_note="Install BlueZ through your OS package manager. Read-only inspection only; no scanning, pairing or radio changes.",
    ),
    ToolSpec(
        id="hcitool", name="hcitool (BlueZ)", category="device", method="manual", manual=True,
        description="Official BlueZ HCI utility for local adapter information.",
        source_url="https://www.bluez.org/",
        homepage="https://www.bluez.org/",
        command="hcitool",
        install_note="Deprecated on newer BlueZ releases; use only on authorized lab hardware.",
    ),
    ToolSpec(
        id="nrfutil", name="nRF Util", category="device", method="manual", manual=True,
        description="Nordic Semiconductor CLI for BLE development tooling.",
        source_url="https://www.nordicsemi.com/Products/Development-tools/nRF-Util",
        homepage="https://www.nordicsemi.com/",
        command="nrfutil",
        install_note="Install from the official Nordic Semiconductor distribution; use only with authorized lab hardware.",
    ),
    ToolSpec(
        id="zaproxy", name="OWASP ZAP", category="proxy", method="manual", manual=True,
        description="Intercepting proxy and web scanner.",
        source_url="https://zaproxy.org/download/",
        homepage="https://zaproxy.org/",
        command="zap.sh",
        install_note="Use the official platform installer; auto-install is intentionally disabled.",
    ),
    ToolSpec(
        id="burp", name="Burp Suite", category="proxy", method="manual", manual=True,
        description="Licensed interception proxy.",
        source_url="https://portswigger.net/burp/communitydownload",
        homepage="https://portswigger.net/burp",
        command="burpsuite",
        install_note="License acceptance and installer download must be performed manually.",
    ),
    ToolSpec(
        id="apatch", name="APatch", category="root", method="manual", manual=True,
        description="Root/system modification for owned test devices.",
        source_url="https://github.com/bmax121/APatch",
        homepage="https://github.com/bmax121/APatch",
        invasive=True,
        install_note="Device rooting can brick hardware; perform manually in an authorized lab.",
    ),
    ToolSpec(
        id="recmanager", name="ReC Manager", category="reverse", method="manual", manual=True,
        description="Magisk module/repository manager.",
        source_url="https://github.com/ReCManager/ReCManager",
        homepage="https://github.com/ReCManager/ReCManager",
        invasive=True,
        install_note="Install manually on an authorized rooted test device.",
    ),
    ToolSpec(
        id="chromium", name="Chromium", category="browser", method="manual", manual=True,
        description="Browser used to open a configured MobSF instance.",
        source_url="https://www.chromium.org/getting-involved/download-chromium/",
        homepage="https://www.chromium.org/",
        command="chromium",
        install_note="Install through your OS package manager; set APKPT_CHROMIUM_CMD if needed.",
    ),
    # ---------------------------------------------------------------- reverse engineering
    ToolSpec(
        id="ghidra", name="Ghidra", category="reverse", method="manual", manual=True,
        description="NSA reverse-engineering suite for native and firmware binaries (MASTG-TOOL-0033).",
        source_url="https://github.com/NationalSecurityAgency/ghidra",
        homepage="https://ghidra-sre.org/",
        install_note="Manual install of the official release; requires a JDK. Offline analysis of owned binaries only.",
    ),
    ToolSpec(
        id="radare2", name="radare2 / r2frida", category="reverse", method="manual", manual=True,
        description="Reverse-engineering framework for Android/iOS binaries (MASTG-TOOL-0028/0036).",
        source_url="https://github.com/radareorg/radare2",
        homepage="https://rada.re/",
        install_note="Install from upstream releases. r2frida additionally requires Frida.",
    ),
    ToolSpec(
        id="class-dump", name="class-dump", category="reverse", method="manual", manual=True,
        description="Dumps Objective-C class interfaces from iOS Mach-O binaries.",
        source_url="https://github.com/nygard/class-dump",
        homepage="https://github.com/nygard/class-dump",
        install_note="Install manually; analyse only applications you own or are authorized to test.",
    ),
    # ---------------------------------------------------------------- Bluetooth / BLE / Wi-Fi
    ToolSpec(
        id="internalblue", name="InternalBlue", category="device", method="manual", manual=True,
        invasive=True, description="Broadcom/Cypress Bluetooth firmware experimentation framework (SEEMOO).",
        source_url="https://github.com/seemoo-lab/InternalBlue",
        homepage="https://github.com/seemoo-lab/InternalBlue",
        install_note="Requires compatible Broadcom/Cypress hardware and a lab device. Firmware patching can change radio behaviour; never use on third-party devices.",
    ),
    ToolSpec(
        id="ubertooth", name="Ubertooth One", category="device", method="manual", manual=True,
        invasive=True, description="Open-source 2.4 GHz wireless sniffer for Bluetooth research.",
        source_url="https://github.com/greatscottgadgets/ubertooth",
        homepage="https://ubertooth.readthedocs.io/",
        install_note="Hardware tool; passive monitoring only in an authorized RF lab. The platform never drives it automatically.",
    ),
    ToolSpec(
        id="nrf-sniffer", name="nRF Sniffer for BLE", category="device", method="manual", manual=True,
        description="Nordic Semiconductor BLE packet sniffer for Wireshark.",
        source_url="https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE",
        homepage="https://www.nordicsemi.com/",
        install_note="Install the official Nordic tool and hardware. Passive capture only; never scan or modify devices from this platform.",
    ),
    ToolSpec(
        id="aircrack-ng", name="Aircrack-ng", category="device", method="manual", manual=True,
        invasive=True, description="Wi-Fi security audit suite (monitor, capture, injection, WEP/WPA analysis).",
        source_url="https://github.com/aircrack-ng/aircrack-ng",
        homepage="https://www.aircrack-ng.org/",
        install_note="Manual install for owned RF labs only. Injection/deauthentication can disrupt networks; the platform never runs these workflows.",
    ),
    ToolSpec(
        id="bettercap", name="Bettercap", category="device", method="manual", manual=True,
        invasive=True, description="Wi-Fi, BLE, HID and network reconnaissance/MITM framework (MASTG-TOOL-0076).",
        source_url="https://github.com/bettercap/bettercap",
        homepage="https://www.bettercap.org/",
        install_note="Manual, scoped lab use only. Active radio and MITM modules are never invoked by this platform.",
    ),
    ToolSpec(
        id="kismet", name="Kismet", category="device", method="manual", manual=True,
        description="Passive wireless network detector, sniffer and WIDS.",
        source_url="https://github.com/kismetwireless/kismet",
        homepage="https://www.kismetwireless.net/",
        install_note="Manual install; passive monitoring in authorized environments only.",
    ),
    ToolSpec(
        id="hcxtools", name="hcxtools", category="device", method="manual", manual=True,
        description="Tools converting wireless captures to hash formats for offline auditing.",
        source_url="https://github.com/ZerBea/hcxtools",
        homepage="https://github.com/ZerBea/hcxtools",
        install_note="Manual install; handle captured data as sensitive and stay within scope.",
    ),
    ToolSpec(
        id="wireshark", name="Wireshark / tshark", category="device", method="manual", manual=True,
        description="Packet dissection and capture analysis (MASTG-TOOL-0081).",
        source_url="https://github.com/wireshark/wireshark",
        homepage="https://www.wireshark.org/",
        install_note="Manual install via official installer. Captured traffic may contain sensitive data.",
    ),
    # ---------------------------------------------------------------- iOS device tooling
    ToolSpec(
        id="ipsw", name="ipsw", category="device", method="manual", manual=True,
        description="iOS firmware/ipsw research toolkit (MASTG-TOOL-0105).",
        source_url="https://github.com/blacktop/ipsw",
        homepage="https://github.com/blacktop/ipsw",
        install_note="Manual install; analyse firmware you are authorized to inspect.",
    ),
    ToolSpec(
        id="ios-deploy", name="ios-deploy", category="device", method="manual", manual=True,
        description="Installs and debugs apps on iOS devices over USB (MASTG-TOOL-0054).",
        source_url="https://github.com/ios-control/ios-deploy",
        homepage="https://github.com/ios-control/ios-deploy",
        install_note="Manual, macOS-only. Installing apps changes device state; requires explicit authorization.",
    ),
    ToolSpec(
        id="libimobiledevice", name="libimobiledevice", category="device", method="manual", manual=True,
        description="Cross-platform protocol library for iOS devices (MASTG-TOOL-0126).",
        source_url="https://github.com/libimobiledevice/libimobiledevice",
        homepage="https://libimobiledevice.org/",
        install_note="Manual install through the official distribution; authorized devices only.",
    ),
    # ---------------------------------------------------------------- firmware / bootloader / BIOS
    ToolSpec(
        id="binwalk", name="Binwalk", category="root", method="manual", manual=True,
        description="Firmware image analysis, carving and extraction.",
        source_url="https://github.com/ReFirmLabs/binwalk",
        homepage="https://github.com/ReFirmLabs/binwalk",
        install_note="Manual install. Analyse firmware you own; extraction writes local files only.",
    ),
    ToolSpec(
        id="unblob", name="unblob", category="root", method="manual", manual=True,
        description="Fast firmware extraction engine supporting 100+ formats (ONEKEY).",
        source_url="https://github.com/onekey-sec/unblob",
        homepage="https://github.com/onekey-sec/unblob",
        install_note="Manual install; offline extraction of authorized firmware images only.",
    ),
    ToolSpec(
        id="uefitool", name="UEFITool", category="root", method="manual", manual=True,
        description="UEFI/BIOS firmware image parsing and module extraction.",
        source_url="https://github.com/LongSoft/UEFITool",
        homepage="https://github.com/LongSoft/UEFITool",
        install_note="Manual install; offline analysis only. Never flash modified firmware outside an authorized lab.",
    ),
    ToolSpec(
        id="chipsec", name="CHIPSEC", category="root", method="manual", manual=True,
        invasive=True, description="Platform/firmware security assessment framework (Intel).",
        source_url="https://github.com/chipsec/chipsec",
        homepage="https://chipsec.github.io/",
        install_note="Manual install only. Requires a kernel driver and hardware access; test systems only, never production hosts.",
    ),
    ToolSpec(
        id="flashrom", name="flashrom", category="root", method="manual", manual=True,
        invasive=True, description="Identifies, reads, writes and erases SPI flash chips.",
        source_url="https://github.com/flashrom/flashrom",
        homepage="https://www.flashrom.org/",
        install_note="Manual install. Writing/erasing flash can brick hardware; authorized lab hardware only.",
    ),
    ToolSpec(
        id="fwupd", name="fwupd", category="root", method="manual", manual=True,
        description="Firmware update and integrity baseline tooling (LVFS).",
        source_url="https://github.com/fwupd/fwupd",
        homepage="https://fwupd.org/",
        install_note="Manual install; use read-only version/baseline checks. Do not apply updates from this platform.",
    ),
    ToolSpec(
        id="u-boot", name="U-Boot", category="root", method="manual", manual=True,
        description="Bootloader source and verified-boot tooling for embedded devices.",
        source_url="https://github.com/u-boot/u-boot",
        homepage="https://www.denx.de/wiki/U-Boot",
        install_note="Manual install/build. Inspect bootloader configuration offline; never replace a bootloader from this platform.",
    ),
    ToolSpec(
        id="hashcat", name="Hashcat", category="root", method="manual", manual=True,
        description="Offline password/hash auditing for authorized assessments.",
        source_url="https://github.com/hashcat/hashcat",
        homepage="https://hashcat.net/hashcat/",
        install_note="Manual install; use only on hashes from authorized engagements.",
    ),
)

SPEC_BY_ID = {spec.id: spec for spec in TOOL_SPECS}
MANUAL_IDS = {spec.id for spec in TOOL_SPECS if spec.manual}

# Web UIs are never guessed. Only these admin-configured URLs are launchable.
WEB_URL_SETTINGS = {
    "mobsf": ("MOBSF_URL", "MOBSF_DYNAMIC_URL"),
    "apkhunt": ("APKHUNT_URL",),
    "rms": ("RMS_URL",),
    "zaproxy": ("ZAP_WEB_URL",),
}

# Ordered workflow groups used by both the static dashboard and React source UI.
# Manual/invasive tools are intentionally last so the safe daily path stays first.
TOOL_GROUPS: tuple[dict[str, Any], ...] = (
    {"id": "decode", "order": 1, "icon": "🧩", "title": "Decode & inspect",
     "hint": "Unpack, decompile and inspect the APK", "categories": ("reverse",)},
    {"id": "static", "order": 2, "icon": "🔍", "title": "Static analysis",
     "hint": "Secrets, endpoints, rules and MobSF", "categories": ("static",)},
    {"id": "device", "order": 3, "icon": "🔌", "title": "Device & emulator",
     "hint": "Official Android SDK and adb", "categories": ("device", "emulator")},
    {"id": "runtime", "order": 4, "icon": "⚡", "title": "Runtime & patching",
     "hint": "Frida, instrumentation and authorized patching", "categories": ("runtime", "patch")},
    {"id": "dynamic", "order": 5, "icon": "🤖", "title": "Dynamic testing",
     "hint": "Automated DAST on owned devices", "categories": ("dynamic",)},
    {"id": "proxy", "order": 6, "icon": "🕵️", "title": "Proxy & browser",
     "hint": "Traffic interception and configured web UIs", "categories": ("proxy", "browser")},
    {"id": "root", "order": 7, "icon": "🔓", "title": "Manual / root lab",
     "hint": "Manual only · approval and owned hardware required", "categories": ("root",)},
)

TOOL_GROUP_OVERRIDES = {"recmanager": "root"}

TOOL_ICONS = {
    "apktool": "🧩", "jadx": "📦", "aapt2": "🏷️", "recmanager": "🧱",
    "apkleaks": "🔍", "apkhunt": "🧪", "semgrep": "📐", "mobsf": "🛡️",
    "platform-tools": "🔌", "cmdline-tools": "🛠️", "apksigner": "🔏",
    "frida-tools": "⚡", "objection": "🪝", "rms": "🕹️", "patch-apk": "🩹",
    "trashdroid": "🤖", "mitmproxy": "🕵️", "zaproxy": "🦎", "burp": "🐝",
    "chromium": "🌐", "apatch": "🔓", "keytool": "🗝️", "openssl": "🧾",
    "bluetoothctl": "📡", "hcitool": "📶", "nrfutil": "🔵",
    "drozer": "🕳️", "androguard": "🧬", "apkid": "🏷️", "qark": "🧪",
    "ghidra": "🦾", "radare2": "⚙️", "class-dump": "🍎",
    "internalblue": "🔵", "ubertooth": "📻", "nrf-sniffer": "📡",
    "aircrack-ng": "📶", "bettercap": "🛰️", "kismet": "🛎️",
    "hcxtools": "🔑", "wireshark": "🦈",
    "ipsw": "📱", "ios-deploy": "🧷", "libimobiledevice": "🔗",
    "binwalk": "📦", "unblob": "🧩", "uefitool": "🧱", "chipsec": "🛡️",
    "flashrom": "💾", "fwupd": "⬆️", "u-boot": "🥾", "hashcat": "🔐",
}

def tool_group(spec: ToolSpec) -> dict[str, Any]:
    """Return the ordered workflow group for a tool."""
    override = TOOL_GROUP_OVERRIDES.get(spec.id)
    if override:
        for group in TOOL_GROUPS:
            if group["id"] == override:
                return group
    for group in TOOL_GROUPS:
        if spec.category in group["categories"]:
            return group
    return TOOL_GROUPS[-1]


_ACTIONS = {"install", "update", "pull", "verify"}
_BATCH_ACTIONS = {"install_all", "update_all", "verify_all"}
_EMULATOR_ACTIONS = {"install"}
_DAST_ACTIONS = {"install", "update", "verify"}

# Host-side mobile DAST/SAST CLI tools installed by the dedicated gated job and
# by the emulator setup job. No device, radio or firmware is touched here.
DAST_TOOL_IDS: tuple[str, ...] = ("drozer", "androguard", "apkid", "qark")
DISABLED_MANAGER_DETAIL = (
    "Tool manager is disabled. Set APKPT_TOOL_MANAGER=1 and restart the server."
)


@dataclass
class Job:
    job_id: str
    tool_id: str
    action: str
    actor: str
    status: str = "queued"
    progress: int = 0
    detail: str = ""
    started_at: str = ""
    finished_at: str = ""
    logs: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["job_id"] = self.job_id
        return data


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_obsolete_disabled_job(job: Job) -> bool:
    """Return True for old records produced while the tool manager was off."""
    if str(job.status or "").lower() != "skipped":
        return False
    if DISABLED_MANAGER_DETAIL in str(job.detail or ""):
        return True
    return any(DISABLED_MANAGER_DETAIL in str(line or "") for line in job.logs)


def _job_outcome(result: Any, fallback_detail: str) -> tuple[str, str]:
    """Map a tool result to the persisted job status and user-facing detail."""
    if not isinstance(result, dict):
        return "completed", fallback_detail
    tools = result.get("tools")
    if isinstance(tools, list):
        counts: dict[str, int] = {}
        first_issue = ""
        for item in tools:
            status = str((item or {}).get("status", "unknown")).lower()
            counts[status] = counts.get(status, 0) + 1
            if status in ("skipped", "error", "failed") and not first_issue:
                first_issue = str((item or {}).get("detail", ""))
        failed = sum(counts.get(status, 0) for status in ("error", "failed", "critical"))
        skipped = counts.get("skipped", 0)
        succeeded = sum(
            count for status, count in counts.items()
            if status not in ("skipped", "error", "failed", "critical", "unknown")
        )
        summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
        detail = summary or fallback_detail
        if first_issue:
            detail = f"{detail} · {first_issue}"
        status_out = "failed" if failed else "skipped" if skipped and not succeeded else "completed"
        return status_out, detail[:1000]
    status = str(result.get("status", "")).lower()
    detail = str(result.get("detail") or "")
    if not detail and result.get("version"):
        detail = f"version {result['version']}"
    detail = detail or fallback_detail
    if status in ("error", "failed", "critical"):
        return "failed", detail[:1000]
    if status == "skipped":
        return "skipped", detail[:1000]
    return "completed", detail[:1000]


def _tools_root() -> Path:
    root = Path(config.TOOLS_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _jobs_dir() -> Path:
    path = _tools_root() / "jobs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _meta_path(tool_id: str) -> Path:
    return _tools_root() / "meta" / f"{tool_id}.json"


def _read_meta(tool_id: str) -> dict[str, Any]:
    path = _meta_path(tool_id)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_meta(tool_id: str, data: dict[str, Any]) -> None:
    path = _meta_path(tool_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _configured_web_url(spec: ToolSpec) -> str:
    """Return only an explicitly configured web UI URL for this tool."""
    for name in WEB_URL_SETTINGS.get(spec.id, ()):
        value = str(getattr(config, name, "") or "").strip()
        if value:
            return value
    return ""


def _homepage(spec: ToolSpec) -> str:
    return spec.homepage or spec.source_url


def web_ports_status() -> dict[str, Any]:
    """Expose recommended and effective tool web-UI ports without guessing URLs."""
    return {
        "host": config.TOOL_WEB_HOST,
        "recommended": dict(config.TOOL_WEB_PORTS),
        "port_env": dict(config.TOOL_WEB_PORT_ENV),
        "url_env": dict(config.TOOL_WEB_URL_ENV),
        "auto_enabled": bool(config.TOOL_WEB_AUTO),
        "auto_active": bool(config.TOOL_WEB_AUTO_ACTIVE),
        "auto_trigger_port": config.TOOL_WEB_AUTO_TRIGGER_PORT,
        "configured_urls": {
            "mobsf": config.MOBSF_URL,
            "mobsf_dynamic": config.MOBSF_DYNAMIC_URL,
            "apkhunt": config.APKHUNT_URL,
            "rms": config.RMS_URL,
            "zaproxy": config.ZAP_WEB_URL,
        },
        "note": (
            "Set an APKPT_*_PORT variable to build a local URL on a dedicated port, or enable "
            "APKPT_TOOL_WEB_AUTO=1 with the platform on the trigger port to activate the main tool ports. "
            "MobSF dynamic follows the static MobSF URL unless APKPT_MOBSF_DYNAMIC_PORT/URL is set explicitly. "
            "URLs do not start services. Web UI launching stays gated."
        ),
    }


def _default_system_image() -> str:
    system = platform.system().lower()
    arch = "arm64-v8a" if system == "darwin" and platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    return f"system-images;android-34;google_apis;{arch}"


def _setup_path(spec: ToolSpec, result: dict[str, Any]) -> str:
    """Return the downloaded archive, installer path or managed checkout."""
    meta = _read_meta(spec.id)
    for key in ("archive", "setup_path", "sdk_root"):
        if meta.get(key):
            return str(meta[key])
    path = str(result.get("path") or "")
    if spec.method == "git":
        return path or str(_tools_root() / "repos" / spec.id)
    if spec.method in ("google_zip", "sdkmanager"):
        return str(config.ANDROID_SDK_ROOT)
    if spec.method == "pip":
        return sys.executable
    return path


def record_install(spec: ToolSpec, result: dict[str, Any], job_id: str = "") -> dict[str, Any] | None:
    """Write one installed executable/setup record into the SQLite inventory."""
    if not result.get("path") and result.get("status") != "installed":
        return None
    existing = installed_db.get(spec.id) or {}
    meta = _read_meta(spec.id)
    return installed_db.upsert({
        "tool_id": spec.id,
        "name": spec.name,
        "category": spec.category,
        "method": spec.method,
        "version": str(result.get("version") or meta.get("version") or ""),
        "executable_path": str(result.get("path") or meta.get("path") or ""),
        "setup_path": _setup_path(spec, result),
        "source_url": str(meta.get("source") or spec.source_url),
        "homepage_url": _homepage(spec),
        "web_url": _configured_web_url(spec),
        "job_id": job_id or str(existing.get("job_id") or ""),
        "metadata": {
            "manual": spec.manual,
            "invasive": spec.invasive,
            "install_note": spec.install_note,
            "sha256": meta.get("sha256", ""),
            "source": meta.get("source", ""),
            "snapshot_url": meta.get("snapshot_url", ""),
            "archive": meta.get("archive", ""),
        },
    })


def sync_installed_database() -> int:
    """Backfill the inventory with tools that are already installed."""
    installed_db.ensure()
    added = 0
    for spec in TOOL_SPECS:
        installed, version, path = _installed_version(spec)
        if not installed:
            continue
        if installed_db.get(spec.id):
            continue
        if record_install(
            spec,
            {"status": "installed", "version": version, "path": path},
            job_id="catalog-sync",
        ):
            added += 1
    return added


def tool_install_state(tool_id: str) -> dict[str, Any]:
    """Return the current local install state for a catalog tool."""
    spec = SPEC_BY_ID.get(tool_id)
    if spec is None:
        return {"installed": False, "version": "", "path": ""}
    installed, version, path = _installed_version(spec)
    return {"installed": installed, "version": version, "path": path}


def with_install_state(result: dict[str, Any], tool_id: str) -> dict[str, Any]:
    """Attach a fresh install check to a web-open result for immediate UI feedback."""
    state = tool_install_state(tool_id)
    result.update(state)
    detail = str(result.get("detail") or "")
    if result.get("status") == "skipped" and "URL is not configured" in detail:
        checked = (
            f"installed {state['version']}" if state["installed"] and state["version"]
            else "installed" if state["installed"] else "not installed"
        )
        suffix = f" Local install check: {checked}."
        if suffix.strip() not in detail:
            result["detail"] = f"{detail.rstrip()}{suffix}"
    return result


def open_web_ui(tool_id: str) -> dict[str, Any]:
    """Open a curated tool web UI; MobSF uses the existing gated lab action."""
    if tool_id == "mobsf":
        return with_install_state(open_mobsf_browser(), tool_id)
    spec = SPEC_BY_ID.get(tool_id)
    if spec is None:
        return with_install_state({"status": "error", "detail": f"unknown tool: {tool_id}"}, tool_id)
    url = _configured_web_url(spec)
    if not url:
        return with_install_state({
            "status": "skipped",
            "url": _homepage(spec),
            "detail": f"No web UI is configured for {spec.name}. Use the official source link instead.",
        }, tool_id)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return with_install_state({"status": "error", "detail": "only http(s) web UI URLs are accepted"}, tool_id)
    if not config.BROWSER_OPEN_ENABLED:
        return with_install_state({
            "status": "skipped", "url": url,
            "detail": "Set APKPT_BROWSER_OPEN=1 to allow server-side browser launching.",
        }, tool_id)
    try:
        if config.CHROMIUM_CMD:
            parts = shlex.split(config.CHROMIUM_CMD)
            subprocess.Popen(parts + [url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return with_install_state({"status": "launched", "url": url, "browser": config.CHROMIUM_CMD}, tool_id)
        if webbrowser.open(url):
            return with_install_state({"status": "launched", "url": url, "browser": "system-default"}, tool_id)
        return with_install_state({"status": "skipped", "url": url, "detail": "no browser could be launched"}, tool_id)
    except Exception as exc:
        return with_install_state({"status": "error", "url": url, "detail": f"{type(exc).__name__}: {exc}"}, tool_id)


def installed_inventory(limit: int = 200) -> list[dict[str, Any]]:
    """Return the local installed-software inventory."""
    installed_db.ensure()
    return installed_db.list_tools(limit)


def installed_summary(limit: int = 200) -> dict[str, Any]:
    installed_db.ensure()
    return {
        "database": str(installed_db.db_path()),
        "count": installed_db.count(),
        "tools": installed_db.list_tools(limit),
    }


LOG_LEVEL_CLASSES = ("critical", "high", "low", "info", "work", "ok", "dim")


def log_level(message: str) -> str:
    """Classify a job log line for terminal-style severity colours."""
    text = str(message or "").lower()
    if not text:
        return "dim"
    if any(token in text for token in ("critical", "fatal", "traceback", "error:", "[error]", "exception:")):
        return "critical"
    if any(token in text for token in (
        "warning", "warn:", "already installed", "already cloned", "skipped",
        "manual required", "not found", "unavailable", "retry", "retrying",
    )):
        return "low"
    if any(token in text for token in (
        "failed", "failure", "denied", "refused", "unauthorized", "forbidden",
        "timeout", "timed out", "502", "503", "504", "high",
    )):
        return "high"
    if any(token in text for token in (
        "installed ", "updated ", "completed", "complete", "verified",
        "ready at", "synced", "success", "passed", "job finished",
    )):
        return "ok"
    if re.match(r"^\[\d+/\d+\]", text) or any(token in text for token in (
        "install", "update", "download", "pull", "clon", "running", "process",
        "prepar", "starting", "started", "sync", "git ", "sdkmanager",
    )):
        return "work"
    if any(token in text for token in (
        "info", "http ", "head ", "version", "source", "official", "pypi",
        "github", "repository", "repo", "from ", "→", "$ ",
    )):
        return "info"
    return "dim"


def log_html(lines: list[str] | None, limit: int = 20) -> str:
    """Render escaped job log lines with severity classes for the dashboard."""
    selected = [str(line or "") for line in list(lines or [])[-max(1, limit):]]
    if not selected:
        return '<span class="op-line op-dim">No log output.</span>'
    return "".join(
        f'<span class="op-line op-{log_level(line)}">{html.escape(line)}</span>'
        for line in selected
    )


def installed_dashboard_html() -> str:
    """Render a dependency-free HTML view of installed software and job logs."""
    e = html.escape
    data = catalog()
    records = installed_inventory(200)
    recent_jobs = MANAGER.list(10)

    rows: list[str] = []
    for record in records:
        tool_id = str(record.get("tool_id") or "")
        web_url = str(record.get("web_url") or "")
        source = str(record.get("source_url") or "")
        source_html = (
            f'<a href="{e(source, quote=True)}" target="_blank" rel="noreferrer">{e(source)}</a>'
            if source else "—"
        )
        web_html = (
            f'<a class="btn compact" href="{e(web_url, quote=True)}" target="_blank" rel="noreferrer">Direct link</a> '
            if web_url else ""
        )
        rows.append(
            "<tr>"
            f"<td><strong>{e(str(record.get('name') or tool_id))}</strong>"
            f'<div class="muted mono small">{e(tool_id)}</div></td>'
            f"<td>{e(str(record.get('version') or '—'))}</td>"
            f'<td class="mono wrap">{e(str(record.get("executable_path") or "—"))}</td>'
            f'<td class="mono wrap">{e(str(record.get("setup_path") or "—"))}</td>'
            f"<td>{source_html}</td>"
            f"<td>{web_html}"
            f'<button class="btn compact" type="button" '
            f'onclick="openWeb({e(json.dumps(tool_id), quote=True)})">Open UI (gated)</button></td>'
            f"<td class=\"mono small\">{e(str(record.get('job_id') or '—'))}</td>"
            f"<td class=\"small\">{e(str(record.get('installed_at') or '—'))}</td>"
            "</tr>"
        )
    table = (
        "<div class=\"tw\"><table><thead><tr><th>Tool</th><th>Version</th><th>Executable</th>"
        "<th>Setup / archive</th><th>Official source</th><th>Web UI</th><th>Job</th><th>Installed</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
        if rows else '<div class="empty">No installed tools are recorded yet. Run an install job or sync the catalog.</div>'
    )

    hosts = "".join(
        f'<span class="chip">{e(host)}</span>'
        for host in data.get("allowed_hosts", [])
    )
    needs = data.get("emulator", {}).get("needs", {})
    need_rows = "".join(
        f"<div class=\"kv\"><span>{e(key.replace('_', ' ').title())}</span>"
        f"<span class=\"wrap\">{e(str(value))}</span></div>"
        for key, value in needs.items()
    )
    job_rows = "".join(
        f'<li><strong>{e(str(job.tool_id))}</strong> '
        f'<span class="muted mono small">{e(str(job.action))} · {e(str(job.job_id))}</span> '
        f'<span class="pill {e(str(job.status))}">{e(str(job.status))}</span>'
        f'<pre>{log_html(job.logs, 20)}</pre></li>'
        for job in recent_jobs
    ) or "<li class=\"muted\">No tool jobs yet.</li>"

    os_info = data.get("os", {})
    os_rows = "".join(
        f"<div class=\"kv\"><span>{e(key.title())}</span><span>{e(str(value))}</span></div>"
        for key, value in os_info.items()
    )

    group_filters = [
        '<button class="tool-filter active" type="button" data-group="all" '
        f'onclick="filterTools(\'all\')">▦ All {len(data.get("tools", []))}</button>'
    ]
    tool_sections: list[str] = []
    for group in data.get("groups", []):
        cards: list[str] = []
        for tool in data.get("tools", []):
            if tool.get("group") != group["id"]:
                continue
            tool_id = str(tool.get("id") or "")
            tool_name = str(tool.get("name") or tool_id)
            tool_id_json = e(json.dumps(tool_id), quote=True)
            action_buttons: list[str] = []
            reason = str(tool.get("install_block_reason") or tool.get("install_note") or "Manual installation only.")
            blocked = tool.get("installable") is False
            if blocked:
                manual_label = "Manual" if tool.get("manual") else "Unavailable"
                action_buttons.append(
                    f'<span class="tool-act manual" title="{e(reason, quote=True)}">'
                    f'<span aria-hidden="true">⚠</span>{manual_label}</span>'
                )
                action_buttons.append(
                    f'<button class="tool-act verify" type="button" '
                    f'onclick="runToolAction({tool_id_json}, \'verify\')" '
                    f'title="Verify {e(tool_name, quote=True)}">'
                    '<span aria-hidden="true">✓</span>Verify</button>'
                )
                reason_json = e(json.dumps(reason), quote=True)
                action_buttons.append(
                    f'<button class="tool-act" type="button" onclick="showWhy({reason_json})" '
                    'title="Why no auto-install button?">'
                    '<span aria-hidden="true">ⓘ</span>Why</button>'
                )
            else:
                for action, icon, label in (
                    ("install", "↓", "Install"), ("update", "↻", "Update"),
                    ("pull", "⟲", "Pull"), ("verify", "✓", "Verify"),
                ):
                    if action == "pull" and tool.get("method") != "git":
                        continue
                    if action == "install" and tool.get("installed"):
                        continue
                    action_buttons.append(
                        f'<button class="tool-act {action}" type="button" '
                        f'onclick="runToolAction({tool_id_json}, \'{action}\')" '
                        f'title="{e(label + " " + tool_name, quote=True)}">'
                        f'<span aria-hidden="true">{icon}</span>{label}</button>'
                    )
            if tool.get("web_open"):
                action_buttons.append(
                    f'<button class="tool-act web" type="button" onclick="openWeb({tool_id_json})" '
                    f'title="Open configured web UI for {e(tool_name, quote=True)}">'
                    '<span aria-hidden="true">↗</span>Web UI</button>'
                )
            source_url = str(tool.get("source_url") or "")
            if source_url:
                action_buttons.append(
                    f'<a class="tool-act" href="{e(source_url, quote=True)}" '
                    'target="_blank" rel="noreferrer" '
                    f'title="Official source for {e(tool_name, quote=True)}">'
                    '<span aria-hidden="true">🔗</span>Source</a>'
                )
            tags = [f'<span class="chip">{e(str(tool.get("category") or ""))}</span>']
            if tool.get("manual"):
                tags.append('<span class="pill low">manual</span>')
            elif blocked:
                tags.append('<span class="pill low">unavailable</span>')
            if tool.get("invasive"):
                tags.append('<span class="pill high">invasive</span>')
            search_text = e(
                " ".join(
                    str(tool.get(key) or "")
                    for key in ("name", "id", "category", "description", "group_title")
                ).lower(),
                quote=True,
            )
            card_class = "tool-card invasive" if tool.get("invasive") else "tool-card"
            status_class = "completed" if tool.get("installed") else "skipped"
            status_label = "installed" if tool.get("installed") else "missing"
            cards.append(
                f'<article class="{card_class}" data-search="{search_text}">'
                '<div class="tc-top">'
                f'<span class="tc-icon" aria-hidden="true">{e(str(tool.get("icon") or "•"))}</span>'
                '<div class="tc-title">'
                f'<strong>{e(tool_name)}</strong>'
                f'<small>{e(tool_id)} · v{e(str(tool.get("version") or "—"))}</small>'
                '</div>'
                f'<span class="pill {status_class}">{status_label}</span>'
                '</div>'
                f'<div class="tc-desc">{e(str(tool.get("description") or ""))}</div>'
                f'<div class="tc-meta">{"".join(tags)}</div>'
                f'<div class="tc-actions">{"".join(action_buttons)}</div>'
                '</article>'
            )
        if not cards:
            continue
        group_id = str(group["id"])
        group_id_json = e(json.dumps(group_id), quote=True)
        group_filters.append(
            f'<button class="tool-filter" type="button" data-group="{e(group_id, quote=True)}" '
            f'onclick="filterTools({group_id_json})">'
            f'<span aria-hidden="true">{e(str(group.get("icon") or "•"))}</span> '
            f'{e(str(group.get("title") or ""))} '
            f'<span class="muted">{int(group.get("count") or 0)}</span></button>'
        )
        tool_sections.append(
            f'<section class="tool-group" data-group="{e(group_id, quote=True)}">'
            '<div class="tg-head">'
            f'<span class="tg-icon" aria-hidden="true">{e(str(group.get("icon") or "•"))}</span>'
            '<div class="tg-title">'
            f'<strong>{int(group.get("order") or 0)}. {e(str(group.get("title") or ""))}</strong>'
            f'<small>{e(str(group.get("hint") or ""))}</small>'
            '</div>'
            f'<span class="pill info tg-count">{int(group.get("count") or 0)}</span>'
            '</div>'
            f'<div class="tool-cards">{"".join(cards)}</div>'
            '</section>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Installed tools · APK Pentest Platform</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230ea5e9'/%3E%3Ctext x='32' y='43' text-anchor='middle' font-size='26' font-family='Arial' font-weight='bold' fill='%2304121f'%3EAPK%3C/text%3E%3C/svg%3E">
<style>
:root{{--bg:#0b1120;--panel:#131c31;--panel2:#18243c;--line:#24334f;--text:#e6edf7;--muted:#8b9bb4;--accent:#38bdf8;--work:#39ff14;--normal:#4ade80;--op-info:#60a5fa;--op-low:#facc15;--op-high:#fb923c;--op-critical:#ff6b6b;--glass:rgba(13,23,42,.62);--glass-line:rgba(148,180,220,.16);--glass-hi:rgba(255,255,255,.06);--mono:ui-monospace,SFMono-Regular,Consolas,monospace}}
body{{margin:0;background:radial-gradient(900px 520px at 10% -10%,rgba(56,189,248,.16),transparent 62%),radial-gradient(760px 480px at 92% 4%,rgba(99,102,241,.15),transparent 64%),linear-gradient(180deg,#070b14 0%,#0a1020 55%,#060a12 100%);background-attachment:fixed;color:var(--text);font:12.5px/1.5 Inter,-apple-system,Segoe UI,Roboto,Arial,sans-serif}}
body::before{{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(120,160,210,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(120,160,210,.045) 1px,transparent 1px);background-size:32px 32px;-webkit-mask-image:linear-gradient(to bottom,#000,transparent 80%);mask-image:linear-gradient(to bottom,#000,transparent 80%)}}
.page{{position:relative;z-index:1}}
a{{color:var(--accent)}}.wrap{{word-break:break-word}}.mono{{font-family:ui-monospace,Consolas,monospace}}
.muted{{color:var(--muted)}}.small{{font-size:12px}}.empty{{color:var(--muted);padding:18px;text-align:center}}
.page{{max-width:1400px;margin:0 auto;padding:28px}}.banner{{background:#12283f;border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:12px 0 20px;color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin:18px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card h3{{margin:0 0 12px}}.kv{{display:grid;grid-template-columns:150px 1fr;gap:10px;padding:5px 0;border-bottom:1px dashed var(--line);font-size:12px}}
.kv span:first-child{{color:var(--muted)}}.chips{{display:flex;flex-wrap:wrap;gap:5px}}.chip{{background:#18243c;border:1px solid var(--line);border-radius:99px;padding:3px 9px;font-size:10px}}
.tw{{overflow-x:auto;border:1px solid var(--line);border-radius:10px}}table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-size:10px;text-transform:uppercase;background:#18243c}}
tr:last-child td{{border-bottom:0}}.btn{{display:inline-block;background:#18243c;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 11px;text-decoration:none;cursor:pointer;font:inherit}}
.btn.primary{{background:var(--accent);color:#04121f;border-color:var(--accent)}}.btn.compact{{padding:4px 8px;font-size:11px}}
.tool-access{{margin-top:14px}}.tool-controls{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}}
.tool-controls input{{background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:6px 10px;min-width:210px;font-size:12px}}
.tool-filter{{background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:99px;padding:4px 10px;font-size:11px;cursor:pointer}}
.tool-filter.active{{border-color:var(--accent);color:var(--accent)}}
.tool-groups{{display:flex;flex-direction:column;gap:14px}}.tool-group{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px}}
.tg-head{{display:flex;align-items:center;gap:9px;margin-bottom:10px;padding-bottom:9px;border-bottom:1px solid var(--line)}}
.tg-icon{{width:30px;height:30px;display:grid;place-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:8px;font-size:16px}}
.tg-title{{flex:1;min-width:0}}.tg-title strong{{display:block;font-size:13px}}.tg-title small{{color:var(--muted);font-size:10px}}
.tool-cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:9px}}
.tool-card{{background:#0f1a2d;border:1px solid var(--line);border-radius:9px;padding:10px;min-width:0}}
.tool-card:hover{{border-color:#3d5378}}.tool-card.invasive{{border-left:3px solid var(--op-high)}}
.tc-top{{display:flex;gap:8px;align-items:flex-start}}.tc-icon{{font-size:17px;line-height:1.2}}
.tc-title{{flex:1;min-width:0}}.tc-title strong{{display:block;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tc-title small{{display:block;color:var(--muted);font-size:10px;font-family:ui-monospace,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tc-desc{{color:var(--muted);font-size:11px;line-height:1.4;margin:8px 0;min-height:30px}}
.tc-meta{{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}}.tc-actions{{display:flex;gap:4px;flex-wrap:wrap}}
.tool-act{{display:inline-flex;align-items:center;gap:3px;background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:3px 6px;font-size:10px;line-height:1.2;text-decoration:none;cursor:pointer}}
.tool-act:hover{{border-color:var(--accent);color:var(--accent)}}.tool-act.install{{color:var(--work)}}.tool-act.update{{color:var(--op-info)}}
.tool-act.verify{{color:var(--normal)}}.tool-act.web{{color:var(--accent)}}.tool-act.manual{{color:var(--op-low)}}
.auto-term{{position:fixed;top:16px;right:18px;bottom:16px;width:min(520px,42vw);z-index:70;background:#031309;border:1px solid var(--work);border-radius:12px;box-shadow:0 0 28px #39ff1455,0 16px 48px #000b;display:none;flex-direction:column;overflow:hidden;animation:autoTermIn .18s ease-out}}
.auto-term.open{{display:flex}}
@keyframes autoTermIn{{from{{opacity:0;transform:translateX(18px)}}to{{opacity:1;transform:none}}}}
.at-head{{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 13px;border-bottom:1px solid #1d5b32;background:#062116;color:var(--work)}}
.at-head strong{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.at-dot{{display:inline-block;width:8px;height:8px;margin-right:7px;border-radius:50%;background:var(--work);box-shadow:0 0 10px var(--work);animation:atPulse 1.1s ease-in-out infinite}}
@keyframes atPulse{{50%{{opacity:.35}}}}
.at-head button{{background:transparent;border:0;color:var(--work);font-size:15px;line-height:1;padding:2px 6px;cursor:pointer}}.at-head button:hover{{color:#fff}}
.at-log{{flex:1;min-height:0;margin:0;padding:12px 13px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.55 ui-monospace,Consolas,monospace;color:var(--work);background:#020e08;text-shadow:0 0 6px #39ff1466}}
.at-line{{display:block}}.at-line.op-work{{color:var(--work)}}.at-line.op-ok{{color:var(--normal)}}.at-line.op-info{{color:var(--op-info)}}
.at-line.op-low{{color:var(--op-low)}}.at-line.op-high{{color:var(--op-high)}}.at-line.op-critical{{color:#ff6b6b}}.at-line.op-dim{{color:var(--muted)}}
.at-foot{{padding:8px 13px;border-top:1px solid #1d5b32;background:#062116;color:#9bd8ad;font-size:10px}}
@media(max-width:900px){{.auto-term{{width:calc(100vw - 32px);right:16px}}}}
ul{{padding-left:18px}}li{{margin-bottom:12px}}pre{{background:#0a1425;border:1px solid var(--line);border-radius:8px;padding:8px;max-height:130px;overflow:auto;white-space:pre-wrap;font-size:11px}}
.pill.running,.pill.installing,.pill.updating,.pill.processing{{background:#053e21;color:#39ff14;box-shadow:0 0 8px #39ff1455}}
.pill.completed,.pill.done,.pill.passed,.pill.ok{{background:#065f46;color:#a7f3d0}}
.pill.queued,.pill.info{{background:#12283f;color:#60a5fa}}
.pill.failed,.pill.error,.pill.critical{{background:#7f1d1d;color:#fecaca}}
.pill.high{{background:#7c2d12;color:#fdba74}}.pill.low,.pill.warn,.pill.warning,.pill.skipped{{background:#713f12;color:#fde68a}}
.op-line{{display:block;padding:0 3px;border-left:2px solid transparent}}
.op-critical{{color:#ff6b6b;border-left-color:#ef4444}}.op-high{{color:#fb923c;border-left-color:#f97316}}
.op-low{{color:#facc15;border-left-color:#eab308}}.op-info{{color:#60a5fa;border-left-color:#3b82f6}}
.op-work{{color:#39ff14;border-left-color:#39ff14;text-shadow:0 0 6px #39ff1477}}
.op-ok{{color:#4ade80;border-left-color:#22c55e}}.op-dim{{color:var(--muted)}}
@media(max-width:900px){{.kv{{grid-template-columns:1fr}}}}
.card,.tw{{background:var(--glass);border:1px solid var(--glass-line);border-radius:9px;-webkit-backdrop-filter:blur(12px) saturate(140%);backdrop-filter:blur(12px) saturate(140%);box-shadow:0 10px 30px rgba(0,0,0,.35),inset 0 1px 0 var(--glass-hi)}}
.tool-group{{background:rgba(10,18,32,.7);border-color:var(--glass-line)}}
.tool-card{{background:linear-gradient(160deg,rgba(20,34,58,.72),rgba(9,16,30,.82));border-color:var(--glass-line);box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}}
.tool-card:hover{{border-color:rgba(56,189,248,.45);box-shadow:0 0 14px rgba(56,189,248,.1)}}
.tc-title strong{{font-size:11.5px}}.tc-desc{{font-size:10.5px;min-height:28px}}.tool-act{{font-size:9.5px}}
table{{font-size:11.5px}}th,td{{padding:7px 10px}}th{{font-family:var(--mono);font-size:9px;letter-spacing:.1em}}
.mono,pre{{font-family:var(--mono);font-size:11px}}.small{{font-size:11px}}
.auto-term{{background:rgba(3,15,9,.84);border-color:rgba(57,255,20,.45);box-shadow:0 0 26px rgba(57,255,20,.14),0 18px 48px rgba(0,0,0,.56);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px)}}
.at-log{{font-size:11px}}.at-foot{{font-size:9.5px}}
@supports not ((-webkit-backdrop-filter:blur(1px)) or (backdrop-filter:blur(1px))){{.card,.tw{{background:rgba(12,21,38,.92)}}}}
</style></head><body><div class="page">
<div class="rhead"><div><div class="eyebrow" style="color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:.12em">Local inventory</div>
<h1 style="margin:4px 0 8px">Installed software dashboard</h1>
<div class="muted small">SQLite: <span class="mono">{e(str(installed_db.db_path()))}</span> · {len(records)} recorded tool(s)</div></div>
<div><a class="btn" href="/">← Platform dashboard</a> <button class="btn primary" type="button" onclick="syncDb()">Sync catalog</button> <button class="btn" type="button" onclick="openWeb('mobsf')">Open MobSF</button></div></div>
<div id="message" class="banner" style="display:none"></div>
<div class="auto-term" id="auto-term" role="region" aria-label="Live tool job terminal" aria-live="polite">
  <div class="at-head">
    <span><span class="at-dot" aria-hidden="true"></span><strong id="at-title">tool job</strong> <span class="muted small" id="at-status">running</span></span>
    <button type="button" onclick="hideAutoTerm()" title="Hide live terminal">×</button>
  </div>
  <pre class="at-log" id="at-log"></pre>
  <div class="at-foot">For authorized security testing only · closes automatically when the job finishes</div>
</div>
<div class="grid"><div class="card"><h3>Operating system</h3>{os_rows}</div>
<div class="card"><h3>Source policy</h3><p class="muted small">Official HTTPS hosts only; redirects to other hosts are rejected. Manual/licensed tools are never auto-installed.</p><div class="chips">{hosts}</div></div>
<div class="card"><h3>Emulator needs</h3>{need_rows}</div></div>
<h3>Installed executables and setup files</h3>{table}
<h3 style="margin-top:24px">Tool access <span class="muted small" id="tool-match-count">{len(data.get("tools", []))} tools</span></h3>
<div class="tool-access">
  <div class="tool-controls">
    <input id="tool-search" type="search" placeholder="Find a tool…" aria-label="Find a tool" autocomplete="off" oninput="filterTools()">
    {"".join(group_filters)}
  </div>
  <div class="tool-groups" id="tool-groups">{"".join(tool_sections)}</div>
</div>
<h3 style="margin-top:24px">Recent tool jobs with logs</h3><div class="card"><ul>{job_rows}</ul></div>
</div><script>
async function post(path) {{
  const r = await fetch(path, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{confirm:true}})}});
  let d = {{}}; try {{ d = await r.json() }} catch (e) {{}}
  if (!r.ok) throw new Error(d.detail || ('Request failed (' + r.status + ')'));
  return d;
}}
function show(text, bad, level) {{
  const el = document.getElementById('message');
  const lvl = level || (bad ? 'critical' : 'ok');
  const colors = {{critical:'#ff6b6b', high:'#fb923c', low:'#facc15', info:'#60a5fa', work:'#39ff14', ok:'#a7f3d0'}};
  el.textContent = text; el.style.display = 'block'; el.style.color = colors[lvl] || colors.ok;
}}
function showWhy(reason) {{
  show('Why no install button: ' + (reason || 'Manual installation only.'), false, 'info');
}}
let __atState = null;
function atLevel(status) {{
  const s = String(status || '').toLowerCase();
  if (['completed','done','passed','ok','installed','updated'].includes(s)) return 'ok';
  if (['failed','error','critical'].includes(s)) return 'critical';
  if (['skipped','warn','warning','low'].includes(s)) return 'low';
  return 'info';
}}
function renderAutoTerm() {{
  const log = document.getElementById('at-log'); if (!log) return;
  log.innerHTML = '';
  const items = __atState ? __atState.logs : [];
  if (!items.length) {{
    const s = document.createElement('span'); s.className = 'at-line op-dim';
    s.textContent = 'Waiting for job output…'; log.appendChild(s);
  }} else {{
    items.forEach(item => {{
      const s = document.createElement('span'); s.className = 'at-line op-' + item.level;
      s.textContent = item.text; log.appendChild(s);
    }});
  }}
  log.scrollTop = log.scrollHeight;
}}
function hideAutoTerm() {{
  if (__atState) {{
    if (__atState.timer) clearTimeout(__atState.timer);
    if (__atState.hideTimer) clearTimeout(__atState.hideTimer);
  }}
  __atState = null;
  const el = document.getElementById('auto-term'); if (el) el.classList.remove('open');
}}
function showAutoTerm(label, job) {{
  hideAutoTerm();
  __atState = {{
    id: job.job_id, label: label || job.tool_id || 'tool job',
    status: job.status || 'queued', logs: [], finished: false,
    timer: null, hideTimer: null,
  }};
  const title = document.getElementById('at-title'); if (title) title.textContent = __atState.label;
  const status = document.getElementById('at-status'); if (status) status.textContent = __atState.status;
  const el = document.getElementById('auto-term'); if (el) el.classList.add('open');
  renderAutoTerm();
  pollAutoTerm();
}}
async function pollAutoTerm() {{
  const st = __atState; if (!st || !st.id) return;
  try {{
    const r = await fetch('/api/tools/jobs/' + encodeURIComponent(st.id));
    if (!r.ok) throw new Error('Job poll failed (' + r.status + ')');
    const job = await r.json();
    if (!__atState || __atState.id !== st.id) return;
    st.status = job.status;
    const status = document.getElementById('at-status'); if (status) status.textContent = job.status;
    const logs = job.logs || [];
    if (logs.length > st.logs.length) {{
      logs.slice(st.logs.length).forEach(line => st.logs.push({{ text: String(line), level: 'work' }}));
      renderAutoTerm();
    }}
    if (['completed','failed','skipped'].includes(job.status)) {{
      if (!st.finished) {{
        st.finished = true;
        st.logs.push({{ text: '[' + job.status + '] ' + (job.detail || ''), level: atLevel(job.status) }});
        renderAutoTerm();
        st.hideTimer = setTimeout(() => {{ hideAutoTerm(); location.reload(); }}, 3000);
      }}
      return;
    }}
    st.timer = setTimeout(pollAutoTerm, 700);
  }} catch (e) {{
    if (!__atState || __atState.id !== st.id) return;
    st.logs.push({{ text: 'poll error: ' + e.message, level: 'critical' }});
    renderAutoTerm();
    st.hideTimer = setTimeout(hideAutoTerm, 3000);
  }}
}}
document.addEventListener('keydown', function(e) {{ if (e.key === 'Escape' && __atState) hideAutoTerm(); }});
async function openWeb(id) {{
  try {{
    const r = await post('/api/tools/web/' + encodeURIComponent(id));
    const lvl = r.status === 'error' ? 'critical' : r.status === 'skipped' ? 'low' : 'ok';
    const install = typeof r.installed === 'boolean' ? (r.installed ? 'installed' : 'not installed') + ' · ' : '';
    show((r.status || 'done') + ': ' + install + (r.detail || r.url || 'ok'), false, lvl);
  }} catch (e) {{ show(e.message, true); }}
}}
async function syncDb() {{
  try {{ const r = await post('/api/tools/installed/sync'); show('Inventory synced: ' + (r.added || 0) + ' new record(s).', false); setTimeout(() => location.reload(), 400); }}
  catch (e) {{ show(e.message, true); }}
}}
function filterTools(group) {{
  if (group) window.__toolGroup = group;
  const selected = window.__toolGroup || 'all';
  const input = document.getElementById('tool-search');
  const q = (input ? input.value : '').toLowerCase();
  document.querySelectorAll('.tool-filter').forEach(btn => btn.classList.toggle('active', btn.dataset.group === selected));
  let total = 0;
  document.querySelectorAll('.tool-group').forEach(section => {{
    const inGroup = selected === 'all' || section.dataset.group === selected;
    let visible = 0;
    section.querySelectorAll('.tool-card').forEach(card => {{
      const hit = (card.dataset.search || '').includes(q);
      const showCard = inGroup && hit;
      card.style.display = showCard ? '' : 'none';
      if (showCard) visible += 1;
    }});
    section.style.display = visible ? '' : 'none';
    const badge = section.querySelector('.tg-count');
    if (badge) badge.textContent = visible;
    total += visible;
  }});
  const count = document.getElementById('tool-match-count');
  if (count) count.textContent = total + ' shown';
}}
async function runToolAction(id, action) {{
  try {{
    const r = await post('/api/tools/' + encodeURIComponent(id) + '/' + action);
    if (r.job_id) showAutoTerm(action + ' ' + id, r);
    else show((r.status || 'done') + ': ' + (r.detail || 'ok'), false);
  }} catch (e) {{ show(e.message, true); }}
}}
filterTools('all');
</script></body></html>"""


def safe_url(url: str) -> bool:
    """Only official allowlisted HTTPS sources are accepted."""
    try:
        parsed = urlparse(url)
        return parsed.scheme == "https" and parsed.netloc.lower() in ALLOWED_HOSTS
    except Exception:
        return False


def _require_url(url: str) -> str:
    if not safe_url(url):
        raise ValueError(f"source host is not allowlisted: {url}")
    return url


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def _attempts() -> int:
    return max(1, int(config.TOOL_MANAGER_RETRIES))


def _backoff(attempt: int) -> float:
    return min(30.0, float(config.TOOL_MANAGER_RETRY_DELAY) * (2 ** (attempt - 1)))


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=float(config.TOOL_MANAGER_TIMEOUT),
        follow_redirects=False,
        headers={"User-Agent": "apk-pentest-platform/tool-manager"},
    )


def _upstream_error(message: str, url: str, attempts: int, exc: Exception | None = None) -> RuntimeError:
    error = RuntimeError(
        f"{message} after {attempts} attempt(s) for {url}. "
        "Check the local network/proxy, or raise APKPT_TOOL_MANAGER_RETRIES / APKPT_TOOL_MANAGER_RETRY_DELAY."
    )
    if exc is not None:
        error.__cause__ = exc
    return error


def _request(url: str, method: str = "GET", **kwargs: Any) -> httpx.Response:
    """Request an official URL with allowlisted redirects and transient-502 retries."""
    current = _require_url(url)
    attempts = _attempts()
    for _ in range(5):
        for attempt in range(1, attempts + 1):
            try:
                with _client() as client:
                    response = client.request(method, current, **kwargs)
            except httpx.TransportError as exc:
                if attempt < attempts:
                    time.sleep(_backoff(attempt))
                    continue
                raise _upstream_error(f"network error ({type(exc).__name__})", current, attempts, exc)
            if response.status_code in _RETRY_STATUSES:
                if attempt < attempts:
                    time.sleep(_backoff(attempt))
                    continue
                raise _upstream_error(f"upstream returned HTTP {response.status_code}", current, attempts)
            if response.status_code in _REDIRECT_STATUSES and response.headers.get("location"):
                current = _require_url(urljoin(current, response.headers["location"]))
                break
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise _upstream_error(f"upstream returned HTTP {response.status_code}", current, attempt, exc)
            return response
    raise RuntimeError("too many redirects")


def _download(url: str, target: Path, sha256: str = "") -> Path:
    """Download an official asset, retrying transient proxy/upstream failures."""
    current = _require_url(url)
    target.parent.mkdir(parents=True, exist_ok=True)
    attempts = _attempts()
    for _ in range(5):
        redirected = False
        for attempt in range(1, attempts + 1):
            digest = hashlib.sha256()
            partial = target.with_name(target.name + ".part")
            partial.unlink(missing_ok=True)
            try:
                with _client() as client:
                    with client.stream("GET", current) as response:
                        if response.status_code in _REDIRECT_STATUSES and response.headers.get("location"):
                            current = _require_url(urljoin(current, response.headers["location"]))
                            redirected = True
                            break
                        if response.status_code in _RETRY_STATUSES:
                            if attempt < attempts:
                                time.sleep(_backoff(attempt))
                                continue
                            raise _upstream_error(
                                f"upstream returned HTTP {response.status_code}", current, attempts
                            )
                        response.raise_for_status()
                        with open(partial, "wb") as fh:
                            for chunk in response.iter_bytes(1024 * 1024):
                                fh.write(chunk)
                                digest.update(chunk)
            except httpx.TransportError as exc:
                partial.unlink(missing_ok=True)
                if attempt < attempts:
                    time.sleep(_backoff(attempt))
                    continue
                raise _upstream_error(f"network error ({type(exc).__name__})", current, attempts, exc)
            except httpx.HTTPStatusError as exc:
                partial.unlink(missing_ok=True)
                raise _upstream_error(
                    f"upstream returned HTTP {response.status_code}", current, attempt, exc
                )
            actual = digest.hexdigest()
            if sha256 and actual.lower() != sha256.lower():
                partial.unlink(missing_ok=True)
                raise RuntimeError(
                    f"checksum mismatch: expected {sha256[:12]}… got {actual[:12]}…"
                )
            partial.replace(target)
            return target
        if redirected:
            continue
    raise RuntimeError("too many redirects")


def _extract_zip(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            target = (root / member.filename).resolve()
            if not target.is_relative_to(root):
                raise RuntimeError(f"unsafe archive entry: {member.filename}")
        zf.extractall(destination)
    return destination


def _find_file(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        direct = root / name
        if direct.exists():
            return direct
    for name in names:
        for candidate in root.rglob(name):
            if candidate.is_file():
                return candidate
    return None


def _wrapper(name: str, target: Path, prefix: tuple[str, ...] = ()) -> Path:
    bin_dir = _tools_root() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    quoted = [f'"{target}"']
    if os.name == "nt":
        path = bin_dir / f"{name}.bat"
        path.write_text("@echo off\n" + " ".join([*prefix, *quoted]) + " %*\n", encoding="utf-8")
    else:
        path = bin_dir / name
        path.write_text("#!/bin/sh\n" + "exec " + " ".join([*prefix, *quoted]) + ' "$@"\n', encoding="utf-8")
        path.chmod(0o755)
    return path


def _run(
    cmd: list[str],
    log: Callable[[str], None],
    *,
    cwd: Path | None = None,
    check: bool = True,
    input_text: str | None = None,
) -> tuple[int, str]:
    log("$ " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, input=input_text,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=float(config.TOOL_MANAGER_TIMEOUT), shell=False,
            env=_subprocess_environment(),
        )
    except FileNotFoundError as exc:
        if check:
            raise RuntimeError(f"required command not found: {cmd[0]}") from exc
        return 127, str(exc)
    output = (proc.stdout or "").strip()
    for line in output.splitlines()[-200:]:
        log(line[:500])
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed with exit {proc.returncode}: {cmd[0]}")
    return proc.returncode, output


PKI_LOCAL_IDS = {"keytool", "openssl", "apksigner"}


def _pki_command_path(spec: ToolSpec) -> str:
    """Resolve a PKI CLI from overrides, PATH, or JDK/OpenSSL install locations."""
    override = {
        "keytool": config.KEYTOOL_CMD,
        "openssl": config.OPENSSL_CMD,
        "apksigner": config.APKSIGNER_CMD,
    }.get(spec.id, "").strip()
    if override:
        found = Path(override)
        if found.is_file():
            return str(found)
        on_path = shutil.which(override)
        if on_path:
            return on_path
    found = shutil.which(spec.command) if spec.command else ""
    if found:
        return found
    if spec.id == "keytool":
        java = _java_executable()
        if java:
            name = "keytool.exe" if os.name == "nt" else "keytool"
            candidate = Path(java).parent / name
            if candidate.is_file():
                return str(candidate)
        if os.name == "nt":
            for version_dir in sorted((Path(os.getenv("ProgramFiles") or "") / "Java").glob("jdk-*"), reverse=True):
                candidate = version_dir / "bin" / "keytool.exe"
                if candidate.is_file():
                    return str(candidate)
    if spec.id == "openssl" and os.name == "nt":
        for root in (
            Path(os.getenv("ProgramFiles") or "") / "OpenSSL-Win64" / "bin",
            Path(os.getenv("ProgramFiles") or "") / "OpenSSL-Win32" / "bin",
            Path(os.getenv("LOCALAPPDATA") or "") / "Programs" / "OpenSSL-Win64" / "bin",
        ):
            candidate = root / "openssl.exe"
            if candidate.is_file():
                return str(candidate)
    return ""


def _installed_version(spec: ToolSpec) -> tuple[bool, str, str]:
    """Return (installed, version, path/detail)."""
    root = _tools_root()
    if spec.id in PKI_LOCAL_IDS:
        path = _pki_command_path(spec)
        return (bool(path), _read_meta(spec.id).get("version", ""), path)
    if spec.method == "pip":
        try:
            version = importlib.metadata.version(spec.package)
            path = shutil.which(spec.command) or "python package"
            return True, version, path
        except importlib.metadata.PackageNotFoundError:
            return bool(shutil.which(spec.command)), "", shutil.which(spec.command) or ""
    if spec.method == "git":
        repo_dir = root / "repos" / spec.id
        if (repo_dir / ".git").exists():
            code, out = _run(["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"], lambda _m: None, check=False)
            return True, (out or "git")[:12], str(repo_dir)
        if repo_dir.exists():
            return True, str(_read_meta(spec.id).get("version", "snapshot")), str(repo_dir)
        return False, "", ""
    if spec.method == "github_release":
        meta = _read_meta(spec.id)
        path = Path(meta.get("path", ""))
        if path.exists():
            return True, str(meta.get("version", "")), str(path)
        found = shutil.which(spec.command)
        return bool(found), "", found or ""
    if spec.method == "google_zip":
        if spec.id == "cmdline-tools":
            path = root / "android-sdk" / "cmdline-tools" / "latest" / "bin" / spec.executable
        elif spec.id == "platform-tools":
            path = root / "android-sdk" / "platform-tools" / spec.executable
        else:
            path = root / spec.executable
        suffix = ".exe" if os.name == "nt" and not path.suffix else ""
        candidate = Path(str(path) + suffix)
        return candidate.exists(), _read_meta(spec.id).get("version", ""), str(candidate) if candidate.exists() else ""
    if spec.method == "sdkmanager":
        path = root / "android-sdk" / "build-tools" / spec.sdk_package.split(";")[-1] / spec.executable
        suffixes = (".exe", ".bat", "") if os.name == "nt" else ("",)
        for suffix in suffixes:
            candidate = Path(str(path) + suffix)
            if candidate.exists():
                return True, _read_meta(spec.id).get("version", ""), str(candidate)
        return False, "", ""
    found = shutil.which(spec.command) if spec.command else ""
    return bool(found), "", found or ""


def _auto_install_block(spec: ToolSpec) -> str:
    """Return why official auto-install is unavailable on this host, or '' if allowed."""
    if spec.manual:
        return spec.install_note or "Manual installation only."
    # The current official wheels/dependencies for these pip tools do not support
    # Python 3.15 on all hosts. Fail early with a clear reason instead of a long
    # pip traceback full of old wheel metadata and failed source builds.
    if spec.id in {"semgrep", "mobsf", "drozer", "androguard"} and sys.version_info >= (3, 15):
        return (
            f"Auto-install is unavailable on Python {sys.version.split()[0]} / {platform.system()}: "
            "the official package or one of its native dependencies has no compatible wheel for this host yet. "
            "Use a supported Python (3.10-3.14) or the official manual install guide, then run Verify."
        )
    return ""


def _github_asset(spec: ToolSpec) -> dict[str, Any] | None:
    release = _request(f"https://api.github.com/repos/{spec.repo}/releases/latest").json()
    pattern = re.compile(spec.asset_pattern + r"\Z")
    for asset in release.get("assets", []):
        if pattern.fullmatch(asset.get("name", "")):
            return {
                "name": asset["name"],
                "url": asset["browser_download_url"],
                "sha256": (asset.get("digest") or "").split(":", 1)[-1],
                "version": str(release.get("tag_name", "")).lstrip("v"),
                "tag": release.get("tag_name", ""),
            }
    return None


def _install_github_release(spec: ToolSpec, log: Callable[[str], None], force: bool) -> dict[str, Any]:
    asset = _github_asset(spec)
    if not asset:
        raise RuntimeError(f"no matching release asset for {spec.name}")
    meta = _read_meta(spec.id)
    installed, version, path = _installed_version(spec)
    if not force and installed and version == asset["version"]:
        log(f"{spec.name} {version} is already installed; use Update to refresh.")
        return {"status": "skipped", "version": version, "path": path}
    log(f"Downloading {asset['name']} ({asset['version']}) from the official GitHub release…")
    archive = _download(asset["url"], _tools_root() / "downloads" / asset["name"], asset["sha256"])
    log(f"Verified SHA-256 {asset['sha256'][:16]}…")
    app_dir = _tools_root() / "apps" / spec.id / asset["version"]
    if archive.suffix == ".jar":
        app_dir.mkdir(parents=True, exist_ok=True)
        target = app_dir / archive.name
        shutil.copy2(archive, target)
        wrapper = _wrapper(spec.command, target, prefix=("java", "-jar"))
    elif archive.suffix == ".zip":
        _extract_zip(archive, app_dir)
        executable = _find_file(app_dir, (spec.command, f"{spec.command}.bat", f"{spec.command}.exe"))
        if not executable:
            raise RuntimeError(f"could not locate {spec.command} in {archive.name}")
        wrapper = _wrapper(spec.command, executable)
    else:
        raise RuntimeError(f"unsupported archive type: {archive.suffix}")
    _write_meta(spec.id, {
        "version": asset["version"], "path": str(wrapper),
        "archive": str(archive), "source": asset["url"],
        "sha256": asset["sha256"], "installed_at": _now(),
    })
    log(f"Installed {spec.name} {asset['version']} → {wrapper}")
    return {"status": "installed", "version": asset["version"], "path": str(wrapper)}


def _install_pip(spec: ToolSpec, log: Callable[[str], None], force: bool) -> dict[str, Any]:
    installed, version, path = _installed_version(spec)
    if not force and installed:
        log(f"{spec.name} {version or '(version unknown)'} is already installed; use Update to refresh.")
        return {"status": "skipped", "version": version, "path": path}
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    if force:
        cmd.append("--upgrade")
    cmd.append(spec.package)
    _run(cmd, log)
    version = importlib.metadata.version(spec.package)
    path = shutil.which(spec.command) or "python package"
    _write_meta(spec.id, {"version": version, "path": path, "source": spec.source_url, "installed_at": _now()})
    log(f"Installed {spec.name} {version}")
    return {"status": "installed", "version": version, "path": path}


def _google_url(spec: ToolSpec) -> str:
    system = platform.system().lower()
    if spec.id == "platform-tools":
        os_name = "windows" if system == "windows" else "darwin" if system == "darwin" else "linux"
        return f"https://dl.google.com/android/repository/platform-tools-latest-{os_name}.zip"
    os_name = "win" if system == "windows" else "mac" if system == "darwin" else "linux"
    return f"https://dl.google.com/android/repository/commandlinetools-{os_name}-15859902_latest.zip"


def _install_google_zip(spec: ToolSpec, log: Callable[[str], None], force: bool) -> dict[str, Any]:
    installed, version, path = _installed_version(spec)
    if not force and installed:
        log(f"{spec.name} is already installed at {path}; use Update to refresh.")
        return {"status": "skipped", "version": version, "path": path}
    url = _require_url(_google_url(spec))
    archive = _download(url, _tools_root() / "downloads" / Path(url).name)
    log(f"Downloaded official Google package from {url}")
    sdk_root = Path(config.ANDROID_SDK_ROOT)
    staging = _tools_root() / "staging" / spec.id
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    _extract_zip(archive, staging)
    if spec.id == "cmdline-tools":
        target = sdk_root / "cmdline-tools" / "latest"
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging / "cmdline-tools"), str(target))
    else:
        target = sdk_root / "platform-tools"
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging / "platform-tools"), str(target))
    installed, _, path = _installed_version(spec)
    _write_meta(spec.id, {
        "version": version or "latest", "path": path, "archive": str(archive),
        "sdk_root": str(sdk_root), "source": url, "installed_at": _now(),
    })
    log(f"Installed {spec.name} → {path}")
    return {"status": "installed", "version": version or "latest", "path": path}


def _sdkmanager_path() -> Path:
    root = Path(config.ANDROID_SDK_ROOT)
    suffix = ".bat" if os.name == "nt" else ""
    return root / "cmdline-tools" / "latest" / "bin" / f"sdkmanager{suffix}"


def _install_sdkmanager(spec: ToolSpec, log: Callable[[str], None], force: bool) -> dict[str, Any]:
    installed, version, path = _installed_version(spec)
    if not force and installed:
        log(f"{spec.name} is already installed at {path}; use Update to refresh.")
        return {"status": "skipped", "version": version, "path": path}
    manager = _sdkmanager_path()
    if not manager.exists():
        raise RuntimeError("Install android-cmdline-tools before aapt2.")
    _run([str(manager), "--licenses"], log, check=False, input_text="y\n" * 25)
    _run([str(manager), "--install", spec.sdk_package], log)
    installed, _, path = _installed_version(spec)
    _write_meta(spec.id, {
        "version": spec.sdk_package, "path": path,
        "sdk_root": str(config.ANDROID_SDK_ROOT), "source": spec.source_url,
        "installed_at": _now(),
    })
    return {"status": "installed", "version": spec.sdk_package, "path": path}


def _github_repo_parts(spec: ToolSpec) -> tuple[str, str]:
    path = [part for part in urlparse(spec.source_url).path.split("/") if part]
    if len(path) < 2:
        raise RuntimeError(f"could not parse GitHub repository: {spec.source_url}")
    return path[0], path[1].removesuffix(".git")


def _git_snapshot(spec: ToolSpec, log: Callable[[str], None], force: bool) -> dict[str, Any]:
    """Fallback for hosts without git: install a pinned GitHub source snapshot."""
    owner, repo = _github_repo_parts(spec)
    info = _request(f"https://api.github.com/repos/{owner}/{repo}").json()
    branch = info.get("default_branch") or "main"
    commit = _request(f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}").json()
    sha = str(commit.get("sha", ""))[:12]
    installed, version, path = _installed_version(spec)
    if not force and installed and version == sha:
        log(f"{spec.name} snapshot {sha} is already installed; use Update/Pull to refresh.")
        return {"status": "skipped", "version": sha, "path": path}
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
    archive = _download(url, _tools_root() / "downloads" / f"{spec.id}-{sha}.zip")
    staging = _tools_root() / "staging" / f"{spec.id}-snapshot"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    _extract_zip(archive, staging)
    entries = [p for p in staging.iterdir() if p.is_dir()]
    if len(entries) != 1:
        raise RuntimeError(f"unexpected GitHub archive layout for {spec.name}")
    repo_dir = _tools_root() / "repos" / spec.id
    if repo_dir.exists():
        shutil.rmtree(repo_dir, ignore_errors=True)
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(entries[0]), str(repo_dir))
    _write_meta(spec.id, {
        "version": sha, "path": str(repo_dir), "archive": str(archive),
        "source": spec.source_url, "snapshot_url": url, "installed_at": _now(),
    })
    log(f"Git is unavailable; installed source snapshot {sha} from {spec.source_url}")
    if spec.install_note:
        log(spec.install_note)
    return {"status": "installed", "version": sha, "path": str(repo_dir)}


def _install_git(spec: ToolSpec, log: Callable[[str], None], force: bool, pull_only: bool = False) -> dict[str, Any]:
    url = _require_url(spec.source_url)
    if not shutil.which("git"):
        return _git_snapshot(spec, log, force=force or pull_only)
    repo_dir = _tools_root() / "repos" / spec.id
    if (repo_dir / ".git").exists():
        if not force and not pull_only:
            installed, version, _ = _installed_version(spec)
            log(f"{spec.name} is already cloned at {version or 'HEAD'}; use Update/Pull to refresh.")
            return {"status": "skipped", "version": version, "path": str(repo_dir)}
        _run(["git", "-C", str(repo_dir), "pull", "--ff-only"], log)
    else:
        if pull_only:
            return {"status": "skipped", "detail": f"{spec.name} has not been cloned yet; install it first."}
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--depth", "1", url, str(repo_dir)], log)
    installed, version, _ = _installed_version(spec)
    _write_meta(spec.id, {"version": version, "path": str(repo_dir), "source": url, "installed_at": _now()})
    log(f"Repository ready at {repo_dir}: {version}")
    if spec.install_note:
        log(spec.install_note)
    return {"status": "installed", "version": version, "path": str(repo_dir)}


def _verify(spec: ToolSpec, log: Callable[[str], None]) -> dict[str, Any]:
    if spec.id in PKI_LOCAL_IDS:
        installed, version, path = _installed_version(spec)
        if not installed or not path:
            return {"status": "skipped", "detail": spec.install_note or "Tool not found on PATH."}
        try:
            code, out = _run([path, *spec.version_args], log, check=False)
            lines = (out or "").strip().splitlines()
            detail = " · ".join(x for x in (version or "", lines[0] if lines else "", path) if x)
            return {
                "status": "ok" if code == 0 or out else "error",
                "detail": detail[:500] or f"found at {path}",
                "version": version or "",
                "path": path,
            }
        except Exception as exc:
            return {"status": "error", "detail": str(exc)[:500], "path": path}
    if spec.manual:
        return {"status": "skipped", "detail": spec.install_note or "Manual installation required."}
    try:
        if spec.method == "git":
            url = _require_url(spec.source_url)
            response = _request(url, method="HEAD")
            detail = f"HTTP {response.status_code} · {url}"
            if shutil.which("git"):
                code, out = _run(["git", "ls-remote", url, "HEAD"], log, check=False)
                if code == 0:
                    detail += f" · HEAD {out.strip()[:12]}"
            return {"status": "ok", "detail": detail}
        if spec.method == "github_release":
            asset = _github_asset(spec)
            return {
                "status": "ok" if asset else "error",
                "detail": f"{asset['version']} · {asset['name']}" if asset else "No matching release asset.",
            }
        if spec.method == "pip":
            data = _request(f"https://pypi.org/pypi/{spec.package}/json").json()
            version = data.get("info", {}).get("version", "")
            return {"status": "ok" if version else "error", "detail": f"PyPI {version}"}
        url = _require_url(_google_url(spec)) if spec.method == "google_zip" else spec.source_url
        response = _request(url, method="HEAD")
        return {"status": "ok", "detail": f"HTTP {response.status_code} · {url}"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:500]}


def _run_tool_action(spec: ToolSpec, action: str, log: Callable[[str], None]) -> dict[str, Any]:
    block = _auto_install_block(spec)
    if action in ("install", "update", "pull") and block:
        return {"status": "skipped", "detail": block}
    if action == "verify":
        return _verify(spec, log)
    if action == "pull" and spec.method != "git":
        return {"status": "skipped", "detail": "Pull is available only for repository-backed tools."}
    log(f"{action.title()} {spec.name} from {spec.source_url}")
    if spec.method == "github_release":
        return _install_github_release(spec, log, force=action == "update")
    if spec.method == "pip":
        return _install_pip(spec, log, force=action == "update")
    if spec.method == "google_zip":
        return _install_google_zip(spec, log, force=action == "update")
    if spec.method == "sdkmanager":
        return _install_sdkmanager(spec, log, force=action == "update")
    if spec.method == "git":
        return _install_git(spec, log, force=action in ("update", "pull"), pull_only=action == "pull")
    return {"status": "skipped", "detail": f"Unsupported method: {spec.method}"}


def install_dast_toolchain(log: Callable[[str], None], action: str = "install") -> dict[str, Any]:
    """Install host-side mobile DAST/SAST CLI tools using each spec's safe method.

    This never installs an agent on a device, starts an emulator, opens a
    browser or touches a radio. Manual/invasive tools are intentionally absent.
    """
    log(f"Installing host-side mobile DAST tooling ({', '.join(DAST_TOOL_IDS)}). No device is modified.")
    results: list[dict[str, Any]] = []
    for tool_id in DAST_TOOL_IDS:
        spec = SPEC_BY_ID[tool_id]
        try:
            result = _run_tool_action(spec, action, log)
        except Exception as exc:
            result = {"status": "error", "detail": f"{type(exc).__name__}: {exc}"[:500]}
        log(f"dast[{tool_id}]: {result.get('status')} {result.get('detail', '')}".strip())
        try:
            record_install(spec, result, "dast")
        except Exception as exc:
            log(f"WARNING: inventory update failed for {spec.name}: {type(exc).__name__}: {exc}")
        results.append({"id": tool_id, "status": result.get("status"), "detail": result.get("detail", "")})
    installed = sum(1 for item in results if item["status"] in {"installed", "skipped"})
    return {
        "status": "completed", "action": action, "installed_or_present": installed,
        "tools": results,
        "detail": (
            f"{installed}/{len(results)} DAST tools installed or already present. "
            "Device agents and radio tooling remain manual and gated."
        ),
    }


def install_emulator(log: Callable[[str], None]) -> dict[str, Any]:
    """Create an authorized test AVD using official Android SDK packages."""
    log("Preparing Android SDK command-line tools and an authorized test AVD.")
    if not _java_executable():
        log("Java was not found on PATH; sdkmanager requires a Java runtime.")
    for spec_id in ("cmdline-tools", "platform-tools"):
        result = _run_tool_action(SPEC_BY_ID[spec_id], "install", log)
        log(f"{spec_id}: {result.get('status')} {result.get('detail', '')}".strip())
    manager = _sdkmanager_path()
    if not manager.exists():
        raise RuntimeError("Android sdkmanager is unavailable after installation.")
    _run([str(manager), "--licenses"], log, check=False, input_text="y\n" * 40)
    image = str(config.EMULATOR_SYSTEM_IMAGE or _default_system_image())
    packages = [
        "platform-tools", "build-tools;35.0.0", "platforms;android-34", image, "emulator",
    ]
    for package in packages:
        _run([str(manager), "--install", package], log)
    suffix = ".bat" if os.name == "nt" else ""
    avdmanager = _sdkmanager_path().parent / f"avdmanager{suffix}"
    avd_name = str(config.EMULATOR_AVD or "apkpt_test_avd")
    _run([str(avdmanager), "create", "avd", "-n", avd_name, "-k", image, "--force", "--device", "pixel_5"], log)
    emulator_bin = Path(config.ANDROID_SDK_ROOT) / "emulator" / f"emulator{suffix}"
    if emulator_bin.exists():
        _wrapper("apkpt-emulator", emulator_bin)
    log(f"AVD '{avd_name}' created. Hardware acceleration and authorization are still required.")
    try:
        dast = install_dast_toolchain(log)
        log(f"Emulator DAST toolchain: {dast['detail']}")
    except Exception as exc:
        log(f"WARNING: DAST toolchain setup did not complete: {type(exc).__name__}: {exc}")
    return {
        "status": "installed", "avd": avd_name, "system_image": image,
        "sdk_root": str(config.ANDROID_SDK_ROOT), "dast_toolchain": DAST_TOOL_IDS,
    }


def _java_executable() -> str:
    """Resolve Java from PATH, an explicit override, or common install locations."""
    override = os.getenv("APKPT_JAVA_CMD", "").strip() or config.JAVA_CMD
    if override:
        return override
    on_path = shutil.which("java")
    if on_path:
        return on_path

    candidates: list[Path] = []
    if os.name == "nt":
        roots = [
            Path(os.getenv("ProgramFiles") or "") / "Java",
            Path(os.getenv("ProgramFiles(x86)") or "") / "Java",
            Path(os.getenv("LOCALAPPDATA") or "") / "Programs" / "Eclipse Adoptium",
            Path(os.getenv("LOCALAPPDATA") or "") / "Programs" / "Microsoft",
        ]
        for root in roots:
            if not root.is_dir():
                continue
            candidates.extend(sorted(root.glob("jdk-*/bin/java.exe"), reverse=True))
            candidates.extend(sorted(root.glob("jre-*/bin/java.exe"), reverse=True))
            candidates.append(root / "bin" / "java.exe")
    else:
        candidates.extend(Path(p) for p in ("/usr/bin/java", "/usr/local/bin/java"))
        jvm = Path("/usr/lib/jvm")
        if jvm.is_dir():
            candidates.extend(sorted(jvm.glob("*/bin/java"), reverse=True))
        mac = Path("/Library/Java/JavaVirtualMachines")
        if mac.is_dir():
            candidates.extend(sorted(mac.glob("*/Contents/Home/bin/java"), reverse=True))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _subprocess_environment() -> dict[str, str]:
    """Export the detected JDK to gated tool subprocesses.

    Android's ``sdkmanager.bat`` and ``avdmanager.bat`` require ``JAVA_HOME``
    (or ``java.exe`` on PATH). The server may discover Java outside its own
    inherited PATH, so each child process gets both values explicitly.
    """
    env = os.environ.copy()
    java = _java_executable()
    if not java:
        return env

    java_path = Path(java)
    if not java_path.is_absolute():
        resolved = shutil.which(java) or shutil.which(java_path.name)
        if resolved:
            java_path = Path(resolved)

    if java_path.name.lower() in ("java", "java.exe"):
        bin_dir = java_path.parent
    elif java_path.parent.name.lower() == "bin":
        bin_dir = java_path.parent
    else:
        return env
    if not str(bin_dir) or str(bin_dir) == ".":
        return env

    env["JAVA_HOME"] = str(bin_dir.parent)

    # Windows hosts can expose both PATH and Path. Collapse them so the child
    # receives one unambiguous PATH entry with the Java bin directory first.
    path_key = "Path" if os.name == "nt" else "PATH"
    existing_path = ""
    for key in list(env):
        if key.upper() == "PATH":
            existing_path = env.pop(key) or existing_path
    entries = [entry for entry in existing_path.split(os.pathsep) if entry]
    bin_text = str(bin_dir)
    normalized = bin_text.rstrip("\\/").lower()
    if not any(entry.rstrip("\\/").lower() == normalized for entry in entries):
        entries.insert(0, bin_text)
    env[path_key] = os.pathsep.join(entries)
    return env


def catalog() -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    ordered_specs = sorted(
        TOOL_SPECS,
        key=lambda spec: (tool_group(spec)["order"], spec.category, spec.name.lower()),
    )
    for spec in ordered_specs:
        group = tool_group(spec)
        installed, version, path = _installed_version(spec)
        block = _auto_install_block(spec)
        record = installed_db.get(spec.id) or {}
        web_url = str(record.get("web_url") or _configured_web_url(spec))
        tools.append({
            "id": spec.id,
            "name": spec.name,
            "order": group["order"],
            "group": group["id"],
            "group_title": group["title"],
            "icon": TOOL_ICONS.get(spec.id, group["icon"]),
            "category": spec.category,
            "method": spec.method,
            "description": spec.description,
            "source_url": spec.source_url,
            "homepage": spec.homepage or spec.source_url,
            "install_note": block or spec.install_note,
            "installable": not block,
            "install_block_reason": block,
            "invasive": spec.invasive,
            "manual": spec.manual,
            "installed": installed,
            "version": version,
            "path": path,
            "web_url": web_url,
            "web_open": bool(web_url) or spec.id == "mobsf",
            "inventory": bool(record),
            "actions": ["verify"] if block else [
                action for action in (
                    ("install", "update", "pull", "verify") if spec.method == "git"
                    else ("install", "update", "verify")
                )
                if not (action == "install" and installed)
            ],
        })
    java_exe = _java_executable()
    return {
        "enabled": bool(config.TOOL_MANAGER_ENABLED),
        "root": str(_tools_root()),
        "android_sdk_root": str(config.ANDROID_SDK_ROOT),
        "platform": platform.system(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "architecture": platform.architecture()[0],
            "python": sys.version.split()[0],
            "tools_root": str(_tools_root()),
            "android_sdk_root": str(config.ANDROID_SDK_ROOT),
        },
        "allowed_hosts": sorted(ALLOWED_HOSTS),
        "web_ports": web_ports_status(),
        "source_policy": {
            "official_hosts_only": True,
            "https_only": True,
            "verify_redirect_hosts": True,
            "verify_release_sha256": True,
            "transient_502_retries": _attempts(),
            "retry_delay_seconds": float(config.TOOL_MANAGER_RETRY_DELAY),
            "manual_tools_not_auto_installed": True,
            "config_env": "APKPT_TOOL_ALLOWED_HOSTS",
            "allowed_hosts": sorted(ALLOWED_HOSTS),
            "manual_tool_ids": sorted(MANUAL_IDS),
        },
        "tools": tools,
        "groups": [
            {**group, "count": sum(1 for tool in tools if tool["group"] == group["id"])}
            for group in TOOL_GROUPS
        ],
        "pki": pki_lab.status(),
        "emulator": {
            "avd": config.EMULATOR_AVD or "apkpt_test_avd",
            "system_image": config.EMULATOR_SYSTEM_IMAGE or _default_system_image(),
            "auto_proxy_allowed": bool(config.EMULATOR_AUTO),
            "needs": {
                "java_runtime": (
                    f"Installed: {java_exe}" if java_exe
                    else "Java runtime required on PATH"
                ),
                "android_sdk_root": str(config.ANDROID_SDK_ROOT),
                "system_image": config.EMULATOR_SYSTEM_IMAGE or _default_system_image(),
                "sdk_packages": "platform-tools, build-tools;35.0.0, platforms;android-34, emulator",
                "hardware_acceleration": "Required to launch the AVD; setup does not launch it",
                "authorization": "Use only an owned or explicitly authorized test environment",
            },
            "requirements": [
                "Java runtime on PATH for sdkmanager/avdmanager",
                "Sufficient disk space for Android SDK packages and the AVD",
                "Hardware acceleration to run the emulator (setup does not launch it)",
                "Explicit authorization before attaching or modifying any device",
            ],
        },
        "installed_database": str(installed_db.db_path()),
        "disclaimer": "For authorized security testing only. Installs change local system state.",
    }


SHELL_HELP = """Shell commands (allowlisted — no arbitrary OS shell):
  help                  show this help
  status                tool manager, platform, source policy and inventory
  jobs                  recent tool-manager jobs
  sync                  backfill the installed-software database
  install all           start an install/update-all job
  update all            start an update-all job
  verify all            verify official sources without installing
  emulator install      set up the authorized local AVD
  dast install          install host-side mobile DAST tools (no device changes)
  <tool> install        install one catalog tool
  <tool> update         update one catalog tool
  <tool> pull           pull one Git-backed tool
  <tool> verify         verify one tool's official source
  open <tool>           open a configured web UI (gated)
  clear                 clear this terminal

Examples:
  apktool install
  adb verify
  platform-tools update
  install all
  open mobsf

Type 'catalog' in the shell or tool manager to see tool IDs. Manual/licensed tools stay manual.
For authorized security testing only."""


SHELL_TOOL_ALIASES = {
    "adb": "platform-tools",
    "platform_tools": "platform-tools",
    "platformtools": "platform-tools",
}


def _shell_tool_id(token: str) -> str:
    return SHELL_TOOL_ALIASES.get(token, token)


def parse_shell_command(command: str) -> dict[str, Any]:
    """Parse the mini-terminal command into a safe, auditable manager plan."""
    text = " ".join(str(command or "").strip().split())
    if not text:
        return {"kind": "error", "detail": "empty command. Type 'help' for examples."}
    parts = text.lower().split()

    if parts in (["help"], ["?"]):
        return {"kind": "message", "output": SHELL_HELP}
    if parts == ["clear"]:
        return {"kind": "clear", "output": "terminal cleared"}
    if parts in (["status"], ["info"]):
        return {"kind": "status"}
    if parts in (["jobs"], ["jobs", "list"]):
        return {"kind": "jobs"}
    if parts in (["sync"], ["sync", "db"], ["sync", "database"]):
        return {"kind": "sync"}

    if len(parts) == 2:
        first, second = parts
        if first == "install" and second == "all":
            return {"kind": "job", "tool_id": "all", "action": "install_all"}
        if first == "update" and second == "all":
            return {"kind": "job", "tool_id": "all", "action": "update_all"}
        if first == "verify" and second == "all":
            return {"kind": "job", "tool_id": "all", "action": "verify_all"}
        if (first == "emulator" and second == "install") or (first == "install" and second == "emulator"):
            return {"kind": "job", "tool_id": "emulator", "action": "install"}
        if (first == "dast" and second in _DAST_ACTIONS) or (first in _DAST_ACTIONS and second == "dast"):
            return {"kind": "job", "tool_id": "dast", "action": second if first == "dast" else first}
        if first == "open":
            return {"kind": "web", "tool_id": _shell_tool_id(second)}
        if second == "catalog":
            return {"kind": "catalog"}
        first_tool = _shell_tool_id(first)
        second_tool = _shell_tool_id(second)
        if first_tool in SPEC_BY_ID and second in _ACTIONS:
            return {"kind": "job", "tool_id": first_tool, "action": second}
        if second_tool in SPEC_BY_ID and first in _ACTIONS:
            return {"kind": "job", "tool_id": second_tool, "action": first}

    return {"kind": "error", "detail": f"unknown command: {text}\nType 'help' for allowed commands."}


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(config.TOOL_MANAGER_MAX_WORKERS)),
            thread_name_prefix="apkpt-tools",
        )
        self.archive_obsolete_jobs()

    def _save(self, job: Job) -> None:
        path = _jobs_dir() / f"{job.job_id}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(job.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        with self._lock:
            self._jobs[job.job_id] = job

    def _logger(self, job: Job) -> Callable[[str], None]:
        def log(message: str) -> None:
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            with self._lock:
                job.logs.append(f"[{stamp}] {message}")
                if len(job.logs) > 2000:
                    job.logs = job.logs[-2000:]
            self._save(job)
        return log

    def submit(self, tool_id: str, action: str, actor: str = "anonymous") -> Job:
        if tool_id == "all" and action not in _BATCH_ACTIONS:
            raise ValueError(f"unsupported batch action: {action}")
        if tool_id == "emulator" and action not in _EMULATOR_ACTIONS:
            raise ValueError(f"unsupported emulator action: {action}")
        if tool_id == "dast" and action not in _DAST_ACTIONS:
            raise ValueError(f"unsupported DAST toolchain action: {action}")
        if tool_id not in ("all", "emulator", "dast") and (tool_id not in SPEC_BY_ID or action not in _ACTIONS):
            raise ValueError(f"unknown tool or action: {tool_id}/{action}")

        job = Job(
            job_id=uuid.uuid4().hex[:16], tool_id=tool_id, action=action,
            actor=actor, started_at=_now(),
        )
        log = self._logger(job)
        if not config.TOOL_MANAGER_ENABLED:
            job.status = "skipped"
            job.detail = DISABLED_MANAGER_DETAIL
            job.finished_at = _now()
            log(job.detail)
            self._save(job)
            return job
        self._save(job)
        self._executor.submit(self._execute, job, tool_id, action)
        return job

    def _execute(self, job: Job, tool_id: str, action: str) -> None:
        log = self._logger(job)
        try:
            job.status = "running"
            log(f"Job {job.job_id} started for {actor_label(job.actor)}.")
            if tool_id == "emulator":
                job.result = install_emulator(log)
                try:
                    sync_installed_database()
                    log("Installed-software database synced after emulator setup.")
                except Exception as exc:
                    log(f"WARNING: inventory sync failed: {type(exc).__name__}: {exc}")
            elif tool_id == "dast":
                job.result = install_dast_toolchain(log, action)
                try:
                    sync_installed_database()
                    log("Installed-software database synced after DAST toolchain setup.")
                except Exception as exc:
                    log(f"WARNING: inventory sync failed: {type(exc).__name__}: {exc}")
            elif tool_id == "all":
                results: list[dict[str, Any]] = []
                tools = [s for s in TOOL_SPECS if not s.manual]
                batch_action = "verify" if action == "verify_all" else "update" if action == "update_all" else "install"
                for index, spec in enumerate(tools):
                    job.progress = int(index * 100 / max(1, len(tools)))
                    log(f"[{index + 1}/{len(tools)}] {spec.name}")
                    try:
                        result = _run_tool_action(spec, batch_action, log)
                    except Exception as exc:
                        result = {"status": "error", "detail": str(exc)[:500]}
                    try:
                        record_install(spec, result, job.job_id)
                    except Exception as exc:
                        log(f"WARNING: inventory update failed for {spec.name}: {type(exc).__name__}: {exc}")
                    results.append({"tool": spec.id, **result})
                job.result = {"tools": results}
            else:
                spec = SPEC_BY_ID[tool_id]
                job.result = _run_tool_action(spec, action, log)
                try:
                    record_install(spec, job.result, job.job_id)
                except Exception as exc:
                    log(f"WARNING: inventory update failed for {spec.name}: {type(exc).__name__}: {exc}")
            job.status, job.detail = _job_outcome(
                job.result, "Job finished. Review the log for per-tool results.",
            )
            job.progress = 100
            log(f"[{job.status}] {job.detail}")
        except Exception as exc:
            job.status = "failed"
            job.detail = str(exc)[:1000]
            log(f"ERROR: {job.detail}")
        finally:
            job.finished_at = _now()
            self._save(job)

    def archive_obsolete_jobs(self) -> int:
        """Move stale 'manager disabled' records out of the active job history.

        The files are preserved under ``jobs/archive/<timestamp>/`` so the audit
        trail is retained, but they no longer crowd out real jobs in the UI once
        the manager has been enabled.
        """
        if not config.TOOL_MANAGER_ENABLED:
            return 0
        source = _jobs_dir()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%fZ")
        archive = source / "archive" / stamp
        moved = 0
        for path in sorted(source.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                job = Job(**{k: v for k, v in data.items() if k in Job.__dataclass_fields__})
            except Exception:
                continue
            if not _is_obsolete_disabled_job(job):
                continue
            archive.mkdir(parents=True, exist_ok=True)
            path.replace(archive / path.name)
            moved += 1
        if moved:
            with self._lock:
                for job_id in [
                    job_id for job_id, job in self._jobs.items()
                    if _is_obsolete_disabled_job(job)
                ]:
                    self._jobs.pop(job_id, None)
        return moved

    def get(self, job_id: str) -> Job | None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", job_id or ""):
            return None
        with self._lock:
            if job_id in self._jobs:
                return self._jobs[job_id]
        path = _jobs_dir() / f"{job_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Job(**{k: v for k, v in data.items() if k in Job.__dataclass_fields__})
        except Exception:
            return None

    def list(self, limit: int = 50) -> list[Job]:
        jobs: dict[str, Job] = {}
        for path in _jobs_dir().glob("*.json"):
            found = self.get(path.stem)
            if not found:
                continue
            if config.TOOL_MANAGER_ENABLED and _is_obsolete_disabled_job(found):
                continue
            jobs[found.job_id] = found
        with self._lock:
            for job_id, job in self._jobs.items():
                if config.TOOL_MANAGER_ENABLED and _is_obsolete_disabled_job(job):
                    continue
                jobs[job_id] = job
        return sorted(
            jobs.values(), key=lambda job: (job.started_at, job.job_id), reverse=True,
        )[:limit]


def actor_label(actor: str) -> str:
    return actor or "anonymous"


MANAGER = JobManager()
