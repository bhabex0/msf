# APK Pentest Platform — Tools, Techniques & Advanced Testing Guide

> **For authorized security testing only.** Only test applications, devices, accounts, endpoints and systems you own or have explicit written permission to assess. Keep all activity inside the agreed scope, use test data, and stop immediately if you encounter production or third-party systems outside the engagement.

This is the companion guide to `README.md`. It explains:

- modern mobile/Android/iOS testing frameworks and where the platform fits;
- advanced SAST, DAST, IAST, SCA, secrets, SBOM/VEX and manual techniques;
- every tool currently curated in the platform tool manager;
- practical commands for using external tools safely;
- recommended workflows for Android, iOS and backend/API testing.

Research basis: OWASP MASVS v2.1, OWASP MASTG v2.0, OWASP MASWE, OWASP DevSecOps Guideline, OWASP API Security Top 10 2023, MobSF documentation, ZAP documentation, Semgrep/CodeQL documentation, CycloneDX/OWASP Dependency-Track guidance, and official tool repositories. Sources are listed at the end.

> **PKI scope note:** `keytool`, `openssl`, `apksigner` and local CA/keystore material are benign evidence-gathering and lab tooling. The platform's PKI support is **not** a malware, threat or exploit-detection engine. Exact PKI tool/certificate artifact strings and SHA-256 fingerprints are excluded from suspicious-string and entropy heuristics, and all `PKI` findings are informational and excluded from release-policy gates.

> **Bluetooth scope note:** Bluetooth/BLE support is passive, informational evidence gathering only. The platform never performs a radio scan, pairing, bonding or any device modification. Bluetooth tool names and UUID-shaped values are excluded from suspicious-string and entropy heuristics, all `BLUETOOTH` findings carry an explicit non-malware disposition, and they are excluded from release-policy gates. Bluetooth tooling is **not** a malware, threat or exploit-detection engine.

---

## 1. Testing standards and coverage model

### 1.1 OWASP Mobile Application Security (MAS)

Use MAS as the checklist, not any single tool.

| Framework | What it provides | How to use it here |
|---|---|---|
| **MASVS v2.1** | 24 requirements in 8 control groups: storage, cryptography, authentication, network, platform, code, resilience, privacy | Map platform findings and manual evidence to these groups in reports |
| **MASWE** | Mobile weakness enumeration, e.g. cleartext storage, hardcoded secrets, unsafe WebViews, insecure intents | Use weakness IDs to explain root causes |
| **MASTG v2.0** | 285 tests, 152 demos, 167 techniques, 135 tools, 140 knowledge articles, 72 best practices and 28 reference apps with stable IDs | Pick tests by platform/profile, then reproduce with platform tools and manual steps |
| **MAS profiles L1 / L2 / R** | Risk-based test depth: baseline, defense-in-depth, resilience | Select scope with the business owner; do not assume one profile fits every app |

MASVS v2.1 control groups:

| Group | Question answered |
|---|---|
| `MASVS-STORAGE` | Is sensitive data stored and leaked safely on the device? |
| `MASVS-CRYPTO` | Are strong algorithms, protocols and key-management practices used? |
| `MASVS-AUTH` | Are authentication, authorization, session and local/biometric checks sound? |
| `MASVS-NETWORK` | Is traffic protected in transit and are endpoints identity-pinned? |
| `MASVS-PLATFORM` | Are IPC, WebViews, intents, deep links and UI interactions safe? |
| `MASVS-CODE` | Are inputs validated and are components free of known vulnerabilities? |
| `MASVS-RESILIENCE` | Are platform integrity, anti-tamper, anti-static and anti-dynamic controls present? |
| `MASVS-PRIVACY` | Is sensitive-data access minimized, transparent and user-controlled? |

The platform reports MASVS mappings, but a mapping is **evidence for review**, not certification.

### 1.2 Where each testing type fits

| Type | Runs | Sees | Best for | Main limits |
|---|---|---|---|---|
| **SAST** | At rest: source, bytecode, decompiled code, binaries | Code structure, data flow, patterns | Early detection, secrets, unsafe APIs, manifest/config issues | False positives; misses runtime-only and logic issues |
| **SCA** | On manifests, lockfiles, binaries or SBOMs | Third-party components and versions | Known CVEs, licenses, outdated/EOL components | Only as complete as the inventory; CVE presence does not prove exploitability |
| **DAST** | Against a running app/backend | External behavior, responses, traffic | Runtime/config issues, auth/session flaws, real attack surface | Cannot pinpoint code lines; misses unreached paths |
| **IAST** | Inside a running app via agent/sensor | Code paths, data flow, config and requests together | High-confidence, line-level findings during QA/functional tests | Requires instrumentation and supported runtime; limited native mobile support |
| **Secrets scanning** | Repos, history, files, binaries | Credentials and keys | Preventing leaked tokens/keys | Requires triage, rotation and verification |
| **SBOM/VEX** | Inventory and advisory lifecycle | Components, relationships, exploitability decisions | Supply-chain transparency and continuous monitoring | Needs accurate generation and ongoing maintenance |
| **Manual testing** | Throughout | Business logic, authorization, UX, device state | BOLA/BFLA, logic abuse, privacy context, tamper/resilience | Time-consuming; needs expertise |

Use them together: SAST + SCA early, DAST + IAST in test/staging, manual review for authorization and business logic, SBOM/VEX for supply-chain decisions.

---

## 2. What this platform already does

### 2.1 Built-in engines

| Area | Location in UI | Highlights |
|---|---|---|
| SAST | **Findings** | Manifest, binary XML, DEX strings; exported components, cleartext, backup, WebView, crypto, secrets, signing |
| SCA | **Components** | Bundled-library detection, offline advisories, optional OSV.dev enrichment |
| Advanced | **Advanced** | Deep links/App Links, network-security config, native ELF hardening, trackers, packers, high-entropy strings, certificate forensics |
| Chains | **Chains** | Attack-chain synthesis and guided verification playbook |
| Medical | **Medical** | PHI indicators, health permissions, cleartext/logging/storage correlation, HIPAA/GDPR/FDA/IEC/ISO/UL/HITRUST/MASVS evidence mapping |
| Live | **Live** | Opt-in Firebase/S3/plaintext endpoint checks and optional VirusTotal reputation |
| Dynamic | **Dynamic** | adb install/launch/logcat, deep links, exported-component fuzzing, optional Frida hooks and proxy capture |
| Bluetooth | **Bluetooth** | Passive Bluetooth permissions, BLE/GATT/classic API strings, pairing APIs and UUID evidence for manual review; never scans or pairs |
| Lab | **Lab** | Burp/ZAP/mitmproxy listener commands, proxy CA steps, NSC warnings, gated emulator launch/stop and gated patch/root workflows |
| Policy | **Policy** | Severity and compliance gates |
| Diff | **Diff** | New, resolved and changed findings between scans |
| Report | **Report** | HTML/JSON reports, CycloneDX SBOM, SARIF |

### 2.2 Safety gates

These defaults are intentional:

| Variable | Default | Meaning |
|---|---|---|
| `APKPT_LIVE_CHECKS` | `0` | No outbound live checks unless enabled |
| `APKPT_TOOLCHAIN_AUTO` | `0` | No third-party hooks or lab execution from scans |
| `APKPT_EMULATOR_AUTO` | `0` | No device proxy changes unless explicitly enabled |
| `APKPT_ALLOW_INVASIVE` | `0` | No patch/root/mod workflows unless explicitly enabled and authenticated |
| `APKPT_TOOL_MANAGER` | `0` | Install/update/pull jobs must be explicitly enabled |
| `APKPT_BROWSER_OPEN` | `0` | Server-side browser/MobSF opening must be explicitly enabled |
| `APKPT_BLUETOOTH_LAB` | `0` | Optional read-only probe of local Bluetooth tool availability |
| `APKPT_WEB_UI` | `static` | `react` serves the built React app; the static dashboard is active by default |

Manual tools and invasive tools are never falsely presented as one-click installs. When a tool cannot be auto-installed, the UI shows **Manual** / **Unavailable**, **Verify**, and **Why** with the exact reason.

When `APKPT_TOOL_MANAGER=1`, stale job records that only say `Tool manager is disabled` are archived under `backend/storage/tools/jobs/archive/<timestamp>/` and removed from the active “Recent tool jobs with logs” list. This keeps the audit trail while preventing old gated attempts from crowding out real installs, updates and verifies.

---

## 3. Platform tool manager catalog

Open **Tools & emulator manager** in the sidebar or visit `/tools/dashboard`. Tool access is grouped into seven ordered workflow groups:

1. Decode & inspect
2. Static analysis
3. Device & emulator
4. Runtime & patching
5. Dynamic testing
6. Proxy & browser
7. Manual / root lab

| Tool ID | Group | Purpose | How to use | Notes |
|---|---|---|---|---|
| `apktool` | Decode | Decode resources to smali/XML; rebuild modified APKs | Install, then `apktool d app.apk -o out` | Requires Java. Rebuilding produces an unsigned APK that must be re-signed |
| `jadx` | Decode | DEX to Java/Kotlin decompiler, GUI and CLI | `jadx -d jadx-out app.apk` or `jadx-gui` | Requires Java. Best for code search and xrefs |
| `aapt2` | Decode | Manifest/badging metadata | `aapt2 dump badging app.apk` | Installed through Android build-tools |
| `platform-tools` | Device | `adb`, `fastboot` | `adb devices`, `adb install app.apk`, `adb logcat` | Required for DAST and device work; `adb` is auto-discovered from `ANDROID_SDK_ROOT/platform-tools` when not on PATH (`APKPT_ADB_CMD` overrides) |
| `cmdline-tools` | Emulator | `sdkmanager`, `avdmanager` | Install SDK packages and create AVDs | Requires Java |
| `apkleaks` | Static | URIs, endpoints and secrets in APKs | `apkleaks -f app.apk -o report.txt` | Python package |
| `apkhunt` | Static | OWASP MASVS-oriented static workbench | Clone via manager, then start its documented web/Docker workflow | v2+ uses Docker Compose; manual startup |
| `semgrep` | Static | Rule-based SAST on decompiled Java/Kotlin | Run after `jadx`; see commands below | On Python 3.15 upstream wheels may be unavailable; platform reports `skipped` with the reason |
| `mobsf` | Static/Dynamic | Automated Android/iOS/Windows static and dynamic analysis | Run MobSF separately, set `APKPT_MOBSF_PORT=8001` (or full `APKPT_MOBSF_URL`), then use **Web UI** or scan hooks | Native deps vary. Prefer the official Docker image on port `8001`, not the platform's `8000` |
| `objection` | Runtime | Frida-powered runtime exploration | `objection -g com.example.app explore` | Repackaging/gadget changes signature |
| `frida-tools` | Runtime | Function tracing and instrumentation | `frida-ps -U`, `frida -U -f pkg -l hook.js` | Needs frida-server or Gadget |
| `rms` | Runtime | Frida-based runtime manipulation web UI | Install Node.js, start RMS, then open configured URL | Manual web workflow |
| `patch-apk` | Patching | Inject Frida Gadget into an APK | Use only on an authorized copy, then re-sign and test | Marked **invasive** |
| `trashdroid` | Dynamic | Automated Android DAST framework | Requires Python deps and an authorized device/emulator | Hook is gated by `APKPT_TOOLCHAIN_AUTO` |
| `drozer` | Dynamic | Android IPC/Binder attack-surface framework (OWASP MASTG-TOOL-0015) | Host console: `drozer console connect` after the agent is running on an owned device/emulator | Host-side `pip` install only; agent APK is **never** auto-installed. Set `APKPT_DROZER_CMD`. Windows hosts should use Docker/WSL |
| `androguard` | Static | Android reverse engineering and static-analysis Python toolkit | `androguard analyze app.apk` | Python package; set `APKPT_ANDROGUARD_CMD` |
| `apkid` | Static | Packer/obfuscator/compiler detection (MASTG-TOOL-0009) | `apkid app.apk` | Python package; requires Java; set `APKPT_APKID_CMD` |
| `qark` | Static | Android static analyser with PoC generation | `qark --apk app.apk` | Python package; set `APKPT_QARK_CMD` |
| `ghidra` | Decode | Native binary/firmware reverse engineering (MASTG-TOOL-0033) | Use the official release manually | **Manual/verify only**; requires a JDK |
| `radare2` | Decode | r2/r2frida reverse engineering (MASTG-TOOL-0028/0036) | Use upstream releases manually | **Manual/verify only**; r2frida needs Frida |
| `class-dump` | Decode | iOS Objective-C class interface dumping | Use upstream release manually | **Manual/verify only**; iOS binaries only |
| `internalblue` | Device | Broadcom/Cypress Bluetooth firmware experimentation | Use on compatible owned lab hardware | **Manual/verify + invasive**; firmware changes can affect radio behaviour |
| `ubertooth` | Device | 2.4 GHz Bluetooth sniffer | Attach owned hardware and capture manually | **Manual/verify + invasive**; passive monitoring in an RF lab |
| `nrf-sniffer` | Device | Nordic BLE sniffer for Wireshark | Use official Nordic hardware/tools | **Manual/verify only**; passive capture |
| `aircrack-ng` | Device | Wi-Fi capture, injection and WEP/WPA analysis | Use only on owned networks/RF lab | **Manual/verify + invasive**; active modules disrupt networks |
| `bettercap` | Device | Wi-Fi/BLE/network recon and MITM (MASTG-TOOL-0076) | Manual, scoped lab use | **Manual/verify + invasive**; never driven by this platform |
| `kismet` | Device | Passive wireless detector/sniffer/WIDS | Manual, authorized environments | **Manual/verify only** |
| `hcxtools` | Device | Convert wireless captures to offline hash formats | Manual use on captured data | **Manual/verify only**; handle captures as sensitive |
| `wireshark` | Device | Packet capture and protocol analysis (MASTG-TOOL-0081) | Use official installer | **Manual/verify only**; captures may contain secrets |
| `ipsw` | Device | iOS firmware/ipsw research (MASTG-TOOL-0105) | Manual CLI use | **Manual/verify only** |
| `ios-deploy` | Device | Install/debug iOS apps over USB (MASTG-TOOL-0054) | Manual, macOS only | **Manual/verify only**; changes device state |
| `libimobiledevice` | Device | Cross-platform iOS device protocols (MASTG-TOOL-0126) | Manual CLI use | **Manual/verify only** |
| `binwalk` | Root | Firmware image carving and extraction | Manual offline use on owned firmware | **Manual/verify only** |
| `unblob` | Root | Firmware extraction for 100+ formats | Manual offline use | **Manual/verify only** |
| `uefitool` | Root | UEFI/BIOS firmware parsing and module extraction | Manual offline use | **Manual/verify only**; never flash modified firmware |
| `chipsec` | Root | Platform/BIOS/firmware assessment | Manual use on test systems | **Manual/verify + invasive**; kernel driver and hardware access |
| `flashrom` | Root | SPI flash read/write/erase | Manual use on owned lab hardware | **Manual/verify + invasive**; writing can brick hardware |
| `fwupd` | Root | Firmware version/integrity baselining | Manual read-only checks | **Manual/verify only**; do not apply updates here |
| `u-boot` | Root | Bootloader and verified-boot tooling | Manual offline inspection/build | **Manual/verify only**; never replace a bootloader here |
| `hashcat` | Root | Offline hash auditing | Manual use on authorized hashes | **Manual/verify only** |
| `mitmproxy` | Proxy | HTTP(S) interception and scripting | `mitmdump -l 0.0.0.0:8080 -s addon.py` | Install device CA only on authorized test devices |
| `zaproxy` | Proxy | Intercepting proxy and web/API scanner | Use official installer; configure proxy and scope | **Manual** tool |
| `burp` | Proxy | Licensed interception proxy | Use PortSwigger installer and accept license | **Manual** tool |
| `chromium` | Browser | Browser used for configured web UIs | Install via OS package manager; set `APKPT_CHROMIUM_CMD` if needed | **Manual** tool |
| `bluetoothctl` | Device | Official BlueZ utility for local adapter inspection | `bluetoothctl` then `show`/`info` on authorized lab adapters | **Manual/verify only**; read-only; no scanning or pairing by the platform |
| `hcitool` | Device | BlueZ HCI adapter information | `hcitool dev` on authorized lab hardware | **Manual/verify only**; deprecated on newer BlueZ |
| `nrfutil` | Device | Nordic Semiconductor BLE development CLI | Use official Nordic distribution with authorized lab hardware | **Manual/verify only**; informational |
| `apatch` | Root | Root/system modification for owned lab devices | Perform manually only in an authorized lab | **Manual + invasive** |
| `recmanager` | Root | Magisk module/repository management | Install manually on authorized rooted device | **Manual + invasive** |

Installed tools do **not** show a redundant **Install** button. Missing installable tools show **Install**. Manual/unsupported tools show **Why** with the exact explanation. The toolbar's **Install DAST tools** action installs the host-side DAST/SAST CLI subset (`drozer`, `androguard`, `apkid`, `qark`) after `APKPT_TOOL_MANAGER=1`; it is also part of the gated emulator setup job.

The gated emulator setup passes the detected JDK to every tool subprocess as `JAVA_HOME` and prepends its `bin` directory to `PATH`. This prevents `sdkmanager.bat` / `avdmanager.bat` from failing with “JAVA_HOME is not set” when the platform server was launched without Java on its inherited PATH. `APKPT_JAVA_CMD` overrides detection.

### 3.1 Web UI port map

Run the platform on `8000` and give each optional web UI its own local port:

| Service | Recommended | Port variable | Full URL override |
|---|---:|---|---|
| Platform | `8000` | `APKPT_PLATFORM_PORT` (reported only; use `run.py --port`) | — |
| MobSF static | `8001` | `APKPT_MOBSF_PORT` | `APKPT_MOBSF_URL` |
| MobSF dynamic | `8002` (optional second instance) | `APKPT_MOBSF_DYNAMIC_PORT` | `APKPT_MOBSF_DYNAMIC_URL` |
| APKHunt | `8003` | `APKPT_APKHUNT_PORT` | `APKPT_APKHUNT_URL` |
| RMS | `8004` | `APKPT_RMS_PORT` | `APKPT_RMS_URL` |
| ZAP web UI | `8005` | `APKPT_ZAP_WEB_PORT` | `APKPT_ZAP_WEB_URL` |

Setting a port variable builds `http://127.0.0.1:<port>`; no URL is guessed until then. A full `*_URL` value always wins.

To activate all five tool ports automatically when the platform listens on `8000`, use either:

```bash
python run.py --port 8000 --auto-web-ports
# or set APKPT_TOOL_WEB_AUTO=1
```

The auto mode triggers only when the platform port matches `APKPT_TOOL_WEB_AUTO_TRIGGER_PORT` (default `8000`). It activates MobSF static (`8001`), APKHunt (`8003`), RMS (`8004`) and ZAP (`8005`). MobSF dynamic follows the static MobSF URL on `8001` unless you explicitly set `APKPT_MOBSF_DYNAMIC_PORT=8002` for a second instance. On any other platform port, set the individual `*_PORT` or `*_URL` variables you need. Starting with auto mode does **not** start MobSF/RMS/ZAP; it only configures dashboard links. The **Web UI ports** panel in the tool manager shows the recommended values, currently configured URLs, and an `auto` badge when activation is active.

When a web URL is configured, each tool card also shows **Open URL**, a direct browser link to that tool (MobSF, RMS, ZAP, APKHunt, etc.). This link opens in a new tab and does not require the server-side browser-open gate. The separate **Web UI** button remains the gated server-side launch described in section 2.2. **Open all web UIs** in the toolbar and tool-access header opens every configured web UI through that gated launcher; tools without a URL or with `APKPT_BROWSER_OPEN=0` are listed as skipped rather than hidden.

### 3.2 Dashboard UI and shell behaviour

Both the default static dashboard and the opt-in React dashboard share a compact cyber-glass design: frosted sidebar and summary cards, a dark grid backdrop, numbered tab chips, and an ordered sequence rail — **Intake → Static → SCA → Evidence → Lab → Report**. Dense tables and the 52-card tool catalog use near-solid surfaces so small text stays readable; no finding, skipped tool or missing-configuration message is hidden by the styling. The status colour map is unchanged (work/running/installing/updating `#39ff14`, success `#4ade80`, info `#60a5fa`, low `#facc15`, high `#fb923c`, critical `#ff6b6b`).

The bottom-right `›_ shell` tab opens the shell. **Clicking anywhere outside the shell hides it**; the tab and panel are the click-to-open targets. `pin` keeps it open across outside clicks, `Esc` hides it, and an unpinned shell still auto-hides after 30 seconds. Tool jobs continue to open the separate full-height live terminal, which auto-closes when the job finishes and keeps the authorized-use footer. The shell accepts `open all` for every configured web UI; a bare tool ID (for example `trashdroid`) prints valid actions, while `start <tool>` / `launch <tool>` are rejected because tools are never launched automatically.

---

## 4. Android testing workflows

### 4.1 Static analysis / reverse engineering

Recommended order:

1. **Extract metadata** with `aapt2` / platform built-in manifest parsing.
2. **Decode resources** with `apktool`.
3. **Decompile code** with `jadx`.
4. **Search for secrets and endpoints** with APKLeaks, Semgrep, Gitleaks/TruffleHog.
5. **Identify packers/obfuscators** with APKiD or the platform’s advanced signals.
6. **Run full automated static analysis** with MobSF.
7. **Manually verify** authorization, crypto, storage, WebView and resilience findings.

Commands:

```bash
# Decode resources and smali
apktool d app.apk -o work/apktool

# Decompile to Java-like source
jadx -d work/jadx app.apk
jadx-gui app.apk

# Manifest/badging
aapt2 dump badging app.apk

# Endpoint/secret sweep
apkleaks -f app.apk -o work/apkleaks.txt

# Semgrep over decompiled source (use rules appropriate to the app)
semgrep scan --config=auto --config=./rules/mobile.yml work/jadx --sarif --output work/semgrep.sarif

# CodeQL (source project, Java/Kotlin)
codeql database create work/codeql-db --language=java-kotlin --source-root ./app-source
codeql database analyze work/codeql-db codeql/java-queries --format=sarifv2.1.0 --output=work/codeql.sarif
```

What to look for:

- `debuggable`, `allowBackup`, cleartext traffic, legacy external storage.
- Exported activities/services/receivers/providers without permissions.
- Hardcoded API keys, private keys, passwords, tokens and internal URLs.
- Weak crypto: MD5, SHA-1, DES, RC4, ECB, static IVs, weak RNG.
- WebView JavaScript, JS bridges, local file access, remote debugging.
- World-readable files, external storage, logs with PHI/PII.
- TrustManager/hostname-verifier bypasses, missing pinning.
- Native `.so` hardening: PIE, NX, RELRO, stack canaries, FORTIFY, RPATH/RUNPATH.
- Packers, anti-debug/anti-emulator logic, tamper detection.

### 4.2 Dynamic analysis / DAST

Prerequisites:

- Authorized emulator or device.
- USB debugging or authorized adb connection.
- Test account and test data.
- Interception proxy CA installed only on the test device.

Basic device workflow:

```bash
adb devices
adb install -r app.apk
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
adb logcat -v time | tee work/logcat.txt

# Pull app data if debuggable or rooted lab device
adb shell run-as com.example.app ls -R .
adb pull /data/data/com.example.app work/app-data

# Deep link
adb shell am start -a android.intent.action.VIEW -d "example://open?token=test"

# Exported activity
adb shell am start -n com.example.app/.ExportedActivity
```

MobSF dynamic analysis:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest

# Static only — host 8001 keeps the platform on 8000
docker run -it --rm -p 8001:8000 \
  opensecurity/mobile-security-framework-mobsf:latest

# Static + Android dynamic analysis (second instance on host 8002)
docker run -it --rm -p 8002:8000 -p 1337:1337 \
  -e MOBSF_ANALYZER_IDENTIFIER=<adb-device-id> \
  opensecurity/mobile-security-framework-mobsf:latest
```

Then point the platform at the dedicated ports:

```powershell
$env:APKPT_MOBSF_PORT='8001'
$env:APKPT_MOBSF_DYNAMIC_PORT='8002'
```

If you only run one MobSF container, omit `APKPT_MOBSF_DYNAMIC_PORT`; dynamic analysis uses the same instance on `8001`. This host has no Docker daemon or usable WSL distribution, so the lab uses a native loopback install instead: Python 3.12.10 under `backend/storage/tools/python/python312`, MobSF 4.6.9 in `backend/storage/tools/apps/mobsf-venv`, and the local jadx/apktool/ADB/aapt2 overrides. Python 3.15.2 cannot install the current MobSF wheels on Windows.

### 3.1 Local native dashboard services (authorized lab)

For authorized security testing only. The four requested web tools are installed and left listening on loopback only. They are started separately from the platform; the dashboard's **Open URL** and gated **Web UI** actions never start or modify a service.

| Dashboard URL | Tool | Local install |
| --- | --- | --- |
| `http://127.0.0.1:8001/` | MobSF 4.6.9 | `backend/storage/tools/apps/mobsf-venv/Scripts/mobsf.exe` |
| `http://127.0.0.1:8003/` | APKHunt (`d75317204716`) | `backend/storage/tools/repos/apkhunt` |
| `http://127.0.0.1:8004/` | RMS 1.5.25 | `backend/storage/tools/repos/rms` |
| `http://127.0.0.1:8005/UI` | OWASP ZAP 2.17.0 | `backend/storage/tools/apps/zap/ZAP_2.17.0/zap.bat` |

The platform is reachable at `http://127.0.0.1:8000/`. A local helper, `backend/storage/tools/start_lab_tools.ps1`, starts or reuses the four services on their dedicated ports and restarts/refreshes the platform with the configured URLs:

```powershell
& 'C:\Users\bhabe\Documents\PROJECTS\apk-pentest-platform\backend\storage\tools\start_lab_tools.ps1'
```

The helper does not launch or stop an emulator, install an APK, attach a device proxy, install a CA, or touch radio/firmware/bootloader/BIOS state. APKHunt's `fcntl.py` shim and `os.fchmod` fallback are local Windows compatibility changes to the staged copy only. Verification evidence and install logs are under `backend/storage/reports/Sensinel_Clinician_v4.0.0-103_2026-11-20/evidence/tool_verification/`.

MobSF supports rooted Android VMs up to API 30 and, from v4.6.0, Frida Gadget mode for non-rooted/newer Android 5.0+ targets. For Docker with a host ADB server, restrict port `5037` to the Docker host.

Platform DAST wiring:

```powershell
$env:APKPT_DAST_SERIAL='emulator-5554'
$env:APKPT_DAST_FRIDA='1'
$env:APKPT_DAST_PROXY='burp'
python run.py --port 8000
```

Emulator-backed DAST is intentionally gated and observable:

- `GET /api/lab/emulator` reports adb availability, attached emulator/physical serials, the selected DAST target (an explicit `APKPT_DAST_SERIAL` wins; otherwise an emulator is preferred when `APKPT_DAST_PREFER_EMULATOR=1`), AVD presence and SDK paths.
- `GET /api/lab/emulator/plan` returns a non-executing plan: create AVD → launch → verify adb → run DAST → teardown.
- Set up the local AVD with the explicit, audited job: `POST /api/tools/emulator/install` with `{"confirm": true}` (requires `APKPT_TOOL_MANAGER=1`). This installs official Android SDK packages and creates `apkpt_test_avd`; it never launches the emulator.
- `POST /api/lab/emulator/launch` / `/api/lab/emulator/stop` require `confirm: true` and `APKPT_EMULATOR_AUTO=1`. With the default `APKPT_EMULATOR_AUTO=0` they return `skipped`. No emulator is ever launched automatically by a scan.
- DAST records include `emulator_target` and `dast_info.lab` (readiness + plan), visible in the static/React **Lab** tabs. Hardware acceleration is required to launch an AVD; the platform reports missing binaries or acceleration as `skipped`, not silent failures.

### 4.3 Runtime instrumentation

Frida:

```bash
pip install frida-tools frida

# Android device / emulator
adb shell getprop ro.product.cpu.abilist
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

frida-ps -U
frida -U -f com.example.app -l work/hook.js
frida-trace -U -f com.example.app -i "SSL_CTX_set_verify"
```

Example hook purpose: observe `Cipher.init`, `checkServerTrusted`, `HostnameVerifier.verify`, WebView bridge calls, biometrics callbacks and crypto key handling. Never deploy these hooks to third-party apps or production systems.

objection:

```bash
pip install objection
objection -g com.example.app explore
```

Useful REPL actions include filesystem browsing, SQLite inspection, memory search/dump, class hooking, `android sslpinning disable`, `android root disable` and environment/password-store review.

drozer (IPC attack surface):

```bash
# Use the platform's gated host-side install, or install manually with pipx:
POST /api/tools/dast/install   {"confirm": true}   # requires APKPT_TOOL_MANAGER=1
# pipx install drozer          # equivalent host-console install

# Manual, out-of-platform step on an OWNED device/emulator only:
adb install drozer-agent.apk
# Enable Embedded Server in the agent, then connect explicitly
adb forward tcp:31415 tcp:31415   # only if your setup requires explicit forwarding
drozer console connect

dz> run app.package.list -f example
dz> run app.package.attacksurface com.example.app
dz> run app.activity.start --component com.example.app .ExportedActivity
```

**Host-side DAST toolchain job:** the dashboard's **Install DAST tools** button (or `POST /api/tools/dast/install` with `confirm: true`, enabled by `APKPT_TOOL_MANAGER=1`) installs only the host-side CLI analysers **drozer** (console), **Androguard**, **APKiD** and **QARK**. The emulator setup job runs the same host-only step. No agent APK, emulator launch, device pairing, radio scan or firmware change is performed; those remain separate, explicit, manual operations in an authorized lab. All other mobile/radio/firmware catalog entries are **manual / verify-only** research references.

### 4.4 Interception proxy and certificate pinning

Tools: Burp Suite, ZAP, mitmproxy.

Generic steps:

1. Start listener on `127.0.0.1:8080` or a lab-only interface.
2. Export and install the proxy CA on the authorized test device.
3. Set device Wi-Fi/ADB proxy to the listener.
4. Trust user CAs where applicable; Android Network Security Configuration and certificate pinning may still block interception.
5. Exercise login, API calls, file uploads, WebSocket/traffic and error paths.
6. Remove proxy settings and CA afterwards.

ZAP commands:

```bash
# Passive baseline, safe for shared environments
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://test.example.internal -r zap-baseline.html

# API-aware active scan against an authorized test API
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t https://test.example.internal/openapi.json -f openapi -r zap-api.html
```

Active scans perform attacks. Run them only in isolated test environments.

### 4.5 Bluetooth / BLE evidence (passive only)

The platform reads Bluetooth-related manifest permissions and APK strings and reports them as informational `BLUETOOTH` findings in the **Bluetooth** tab, `GET /api/scans/{id}/bluetooth`, the HTML report and `GET /api/scans/{id}`. It reports:

- Permissions such as `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE` and location permissions used for legacy BLE scanning.
- BLE/GATT API strings (`BluetoothLeScanner`, `BluetoothGatt`, `writeCharacteristic`, …), classic RFCOMM/socket APIs and pairing/bonding APIs.
- UUID-shaped values that may identify GATT services or characteristics.

Manual follow-up on an authorized lab device (never automated by the platform):

```bash
# Read-only local adapter information
bluetoothctl show
hcitool dev

# Nordic BLE tooling with authorized hardware
nrfutil --version
```

`GET /api/bluetooth/status` reports local tool availability; it probes nothing unless `APKPT_BLUETOOTH_LAB=1` and never scans, pairs, bonds or changes a device. All catalog entries are manual/verify-only. Findings are informational evidence, carry an explicit non-malware disposition, are excluded from threat heuristics and cannot fail a release gate.

---

## 5. SAST, SCA, IAST and secrets in depth

### 5.1 Advanced SAST

Use more than one engine:

- **Semgrep** — fast pattern/AST rules, taint mode, custom rules, SARIF output. OWASP notes it is good for IDE/pre-commit/PR gates but not a replacement for manual review, DAST or SCA.
- **CodeQL** — semantic/taint analysis; supports Java/Kotlin, Swift, C/C++, C#, Go, JavaScript/TypeScript, Python, Ruby, Rust. Kotlin and Swift require build-aware database creation.
- **APKHunt / APKLeaks / MobSF** — mobile-specific static analysis of APK/IPA artifacts.
- **Platform engines** — binary XML, DEX strings, advanced configuration and medical/PHI checks without source code.

Recommended gate strategy:

| Stage | Action |
|---|---|
| IDE / pre-commit | Fast Semgrep rules and secret scanning |
| Pull request | Diff-aware SAST, block new high/critical findings |
| Nightly | Deep CodeQL/taint analysis and full MobSF scan |
| Release | Manual review of suppressed, accepted and unresolved findings |

### 5.2 SCA and SBOM

Mobile apps commonly ship Java/Kotlin, native, JavaScript and Flutter dependencies. Generate an SBOM from source and, where possible, from the final artifact.

```bash
# CycloneDX SBOM from source
cdxgen -o sbom.json .

# Alternative SBOM generation
syft . -o cyclonedx-json=sbom.json

# Vulnerability scan of SBOM
grype sbom:sbom.json -o json > grype.json
osv-scanner --sbom sbom.json

# OWASP Dependency-Check
dependency-check.sh --scan . --format HTML --out reports/dependency-check

# Publish to Dependency-Track
curl -X "POST" "https://dtrack.example.internal/api/v1/bom" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "autoCreate=true" \
  -F "projectName=mobile-app" \
  -F "projectVersion=1.0.0" \
  -F "bom=@sbom.json"
```

Maturity progression:

- **Starter:** Dependency-Check or Trivy in CI, baseline existing findings.
- **Intermediate:** Gate on new high/critical CVEs, license allowlist, SBOM per release, central tracking in Dependency-Track.
- **Advanced:** Reachability analysis, VEX statements, continuous SBOM monitoring, EPSS-based prioritization and MTTR metrics.

MASVS-CODE-3 requires components without known vulnerabilities. A CVE finding must still be triaged for reachability and exploitability.

### 5.3 IAST

IAST instruments the running application and observes actual data flow while functional/QA tests exercise it. It typically reports file/line plus the triggering request and full data-flow path.

Common tools:

- Contrast Assess / Contrast Community Edition
- Black Duck Seeker
- Checkmarx IAST
- HCL AppScan on Cloud

Example JVM agent pattern:

```bash
java -javaagent:/opt/contrast/contrast-agent.jar \
  -Dcontrast.config.path=/etc/contrast/contrast_security.yaml \
  -jar my-application.jar
```

Mobile caveats:

- Native mobile sandboxes do not always allow general-purpose IAST agents.
- Agent support is strongest for backend JVM/.NET/Node/Python services.
- For mobile, use Frida/objection/RMS runtime observations plus backend IAST and manual API testing as a practical substitute.
- IAST only reports code paths actually exercised; keep test coverage broad.

Platform integration: HCL AppScan is available as a gated toolchain hook, not a catalog auto-install. Set the `APKPT_APPSCAN_*` variables and enable `APKPT_TOOLCHAIN_AUTO=1` only for authorized test jobs.

### 5.4 Secrets scanning

```bash
# Gitleaks: working tree and full history
gitleaks dir -v ./app-source
gitleaks git -v --log-opts="--all" ./repo

# Create a baseline for legacy findings
gitleaks git --report-path gitleaks-baseline.json
gitleaks git --baseline-path gitleaks-baseline.json --report-path new-findings.json

# TruffleHog: verified secrets in CI
trufflehog git file://. --since-commit main --branch HEAD \
  --results=verified,unknown --fail
```

Use pre-commit hooks for fast feedback and CI/server-side hooks for enforcement. Treat any real secret as compromised: rotate it, then fix the root cause.

---

## 6. iOS testing workflows

iOS testing generally requires **macOS**, Xcode and Xcode Command Line Tools. OWASP notes that many tasks are difficult or impossible from Windows/Linux. Real-device IPA binaries cannot run in the iOS Simulator; use a jailbroken device, a licensed Corellium instance, or a correctly provisioned non-jailbroken device with Gadget/repackaging.

### 6.1 iOS static analysis

```bash
# Unpack IPA
unzip -q app.ipa -d work/ipa

# Inspect Info.plist and entitlements
plutil -p work/ipa/Payload/*.app/Info.plist
codesign -d --entitlements :- work/ipa/Payload/*.app

# Mach-O metadata, linked libraries and symbols
otool -arch arm64 -L work/ipa/Payload/*.app/AppBinary
otool -arch arm64 -tV work/ipa/Payload/*.app/AppBinary
nm -gU work/ipa/Payload/*.app/AppBinary
strings -a work/ipa/Payload/*.app/AppBinary | grep -Ei 'api|token|secret|http'

# Objective-C / Swift interface recovery
class-dump work/ipa/Payload/*.app/AppBinary > work/objc_headers.txt
dsdump --swift --color --verbose=5 --arch arm64 --defined AppBinary > work/swift.txt

# Upload the IPA to MobSF for automated static analysis
# Then set APKPT_MOBSF_PORT (recommended 8001) or APKPT_MOBSF_URL for platform-linked review.
```

Review:

- `Info.plist` purpose strings and exported URL schemes.
- App Transport Security exceptions.
- Keychain accessibility and data protection classes.
- `NSUserDefaults`, plist, SQLite and Core Data storage.
- WebKit/WebView configuration and JS bridges.
- Certificate/pinning code, TLS versions and cipher suites.
- Jailbreak detection, anti-debug and anti-tamper logic.
- Hardcoded secrets, analytics/tracking SDKs and privacy disclosures.

### 6.2 iOS dynamic analysis

Jailbroken device:

```bash
# Install Frida from Cydia repository build.frida.re, then:
frida-ps -U
frida -U -f com.example.app -l work/ios-hook.js
objection -g com.example.app explore
```

Non-jailbroken device with Frida Gadget:

1. Obtain the official universal iOS Gadget.
2. Inject it into a **debug/repackaged copy** of the app or use objection’s patching workflow.
3. Sign and sideload with a development certificate using Xcode/ios-deploy.
4. Attach with `frida -U -f <bundle-id>` or `objection -g <bundle-id> explore`.
5. Expect signature changes; do not use modified binaries outside the lab.

Useful tools:

| Tool | Use |
|---|---|
| `simctl` | Manage simulators, install/launch apps, screenshots, logs |
| `iproxy` | USB port forwarding, often for SSH to jailbroken devices |
| `idevicesyslog` / Xcode | Device logs |
| `frida-ios-dump` | Dump a decrypted IPA from a running app |
| `class-dump` / `dsdump` / `ktool` | Interface and Mach-O inspection |
| `SSL Kill Switch 3` | Test pinning behavior on authorized jailbroken devices |
| `MobSF` | Automated iOS static analysis and Corellium/jailbroken dynamic analysis |
| `Corellium` | Licensed iOS virtual devices for scalable dynamic testing |

---

## 7. Advanced technique playbook

### 7.1 Storage and privacy

- Inspect app-private storage, external/shared storage, backups, logs, clipboard, screenshots and notifications.
- Verify sensitive values are excluded from backups and logs.
- Check analytics/SDK data flows against the privacy policy and MASVS-PRIVACY-1..4.
- For healthcare apps, correlate PHI indicators with cleartext transport, logging, backup and exported components. Platform **Medical** findings are review evidence, not compliance certification.

### 7.2 Cryptography

- Replace MD5/SHA-1/DES/RC4/ECB/static IV/weak RNG findings with vetted primitives.
- Verify keys are generated and stored using platform keystores/keychains.
- Check certificate and public-key pinning plus hostname verification.
- Distinguish obfuscation from encryption; hardcoded “encrypted” keys are still hardcoded.

### 7.3 Authentication and authorization

- Test local auth, biometrics, session expiry, token storage, logout and re-authentication for sensitive actions.
- For mobile APIs, focus on OWASP API Top 10 2023: BOLA, broken authentication, object-property authorization, resource consumption and function-level authorization.
- Swap object IDs between two authorized test accounts and verify server-side ownership checks. A valid token with another user’s object ID must fail.

### 7.4 Platform interaction

- Enumerate activities, services, receivers, providers, exported components and intent filters.
- Test deep links/App Links, implicit intents, pending intents, URI permissions and task affinity.
- Review WebViews for JavaScript, bridges, local resource access and remote debugging.
- Check screenshots, overlays, accessibility services and notifications for sensitive-data leakage.

### 7.5 Network and APIs

- Diff HTTP(S) traffic against the documented API surface.
- Test TLS configuration, cleartext exceptions, user-CA trust and pinning.
- Feed OpenAPI/Swagger/GraphQL schemas into ZAP API scan.
- Use authenticated scans with test accounts; anonymous-only scans miss most of the attack surface.
- Keep active scans in isolated environments and respect rate limits.

### 7.6 Resilience and anti-analysis

- Identify packers, obfuscators, anti-emulator/anti-debug checks, root/jailbreak detection and tamper detection.
- Validate platform integrity and signature checks.
- Review native libraries for PIE, NX, RELRO, canaries, FORTIFY and dangerous RPATH/RUNPATH entries.
- Test bypasses only on authorized copies; repackaging changes signatures and invalidates original trust.

### 7.7 Attack chains

A single low finding may matter when chained. Example chains to verify manually:

- exported component + unsafe WebView + local file access;
- hardcoded token + cleartext endpoint + missing object-level authorization;
- debuggable app + `run-as` accessible PHI + backup inclusion;
- deep link + implicit intent + unvalidated extra;
- missing pinning + user-CA trust + sensitive API traffic.

The platform **Chains** tab proposes chains; confirm reachability and impact manually.

---

## 8. Recommended end-to-end runbooks

### 8.1 Platform baseline assessment

```bash
cd apk-pentest-platform
python -m pip install -r backend/requirements.txt
python run.py --port 8000
```

1. Open `http://127.0.0.1:8000`.
2. Upload the APK.
3. Review Findings, Components, Advanced, Chains, Medical, Playbook, Policy and Report.
4. Export HTML, JSON, SBOM and SARIF.
5. Diff against a previous build.
6. Triage findings into confirmed, false positive, accepted risk and needs-manual-review.

### 8.2 Deep static assessment

1. Enable the tool manager: `APKPT_TOOL_MANAGER=1`.
2. Install/verify `apktool`, `jadx`, `aapt2`, `apkleaks`, `semgrep`.
3. Start MobSF separately on a dedicated port (recommended `8001`) and set `APKPT_MOBSF_PORT` or a full `APKPT_MOBSF_URL`, plus the API key.
4. Run the commands in section 4.1.
5. Import or correlate results with platform findings and MASVS controls.

### 8.3 Dynamic Android assessment

1. Start an authorized emulator/device and confirm `adb devices`.
2. Configure `APKPT_DAST_SERIAL`, `APKPT_DAST_FRIDA` and `APKPT_DAST_PROXY` as needed.
3. Run a platform scan with DAST enabled.
4. Perform manual MobSF/drozer/objection/Frida testing from section 4.
5. Remove proxy/CA/test apps afterwards.

### 8.4 Supply-chain assessment

1. Export the platform CycloneDX SBOM from **Report**.
2. Generate an SBOM from source with cdxgen/syft.
3. Scan both with Grype/OSV-Scanner.
4. Publish to Dependency-Track and add VEX decisions for confirmed non-exploitable findings.
5. Gate releases on new high/critical or KEV-listed components.

### 8.5 Backend/API IAST assessment

1. Deploy the backend under test to an isolated test environment.
2. Attach a supported IAST agent during functional/QA tests.
3. Exercise all user roles and sensitive workflows.
4. Export IAST findings and correlate with mobile API traffic and DAST results.
5. Fix and rerun; keep evidence for audit.

---

## 9. Configuration quick reference

```powershell
# Explicit, audited tool jobs
$env:APKPT_TOOL_MANAGER='1'

# Optional web UI launching
$env:APKPT_BROWSER_OPEN='1'

# Dedicated web-tool ports (platform stays on 8000)
$env:APKPT_TOOL_WEB_HOST='127.0.0.1'
$env:APKPT_TOOL_WEB_AUTO='1'          # activate all tool ports when platform is on 8000
$env:APKPT_TOOL_WEB_AUTO_TRIGGER_PORT='8000'
$env:APKPT_MOBSF_PORT='8001'
$env:APKPT_MOBSF_DYNAMIC_PORT='8002'
$env:APKPT_APKHUNT_PORT='8003'
$env:APKPT_RMS_PORT='8004'
$env:APKPT_ZAP_WEB_PORT='8005'
# Full URLs still override the generated http://127.0.0.1:<port> values.
# This lab's configured values are:
$env:APKPT_MOBSF_URL='http://127.0.0.1:8001'
$env:APKPT_APKHUNT_URL='http://127.0.0.1:8003'
$env:APKPT_RMS_URL='http://127.0.0.1:8004'
$env:APKPT_ZAP_WEB_URL='http://127.0.0.1:8005/UI'

# MobSF integration
$env:APKPT_MOBSF_PORT='8001'
$env:APKPT_MOBSF_API_KEY='<api-key>'

# DAST target (emulator preferred by default when attached)
$env:APKPT_DAST_SERIAL='emulator-5554'
$env:APKPT_DAST_FRIDA='1'
$env:APKPT_DAST_PROXY='burp'

# Explicit host-side DAST CLI tool overrides (optional)
$env:APKPT_DROZER_CMD='drozer'
$env:APKPT_ANDROGUARD_CMD='androguard'
$env:APKPT_APKID_CMD='apkid'
$env:APKPT_QARK_CMD='qark'

# Optional Bluetooth read-only tooling status
$env:APKPT_BLUETOOTH_LAB='1'

# Explicitly serve the built React UI instead of the static dashboard
$env:APKPT_WEB_UI='react'

python run.py --port 8000
```

For a separate validation instance, use another port:

```bash
python run.py --port 8001
```

Notes:

- Python 3.15 is supported by the platform, but some upstream packages (`semgrep`, MobSF native dependencies, `drozer` and `androguard` through PyYAML) lack compatible wheels without local MSVC build tools. The platform reports these as **Unavailable** with **Why** and records install jobs as `skipped` rather than emitting long pip tracebacks. Install those tools under Python 3.10-3.14 when needed; APKiD and QARK installed successfully on the current Python 3.15 host.
- Use Python 3.10–3.14 or the official manual guide for those tools, then run **Verify**.
- `setx` affects new terminals only; in the current PowerShell session use `$env:` assignments.
- The static UI and `/tools/dashboard` are active by default; the React source is maintained and built, and can be served with `APKPT_WEB_UI=react`.

---

## 10. Safety checklist

Before any action:

- [ ] Written authorization and scope are available.
- [ ] Target app/device/API is owned by the organization or explicitly authorized.
- [ ] Test accounts, test data and isolated environments are used.
- [ ] Manual/licensed/root/invasive tools are handled by an authorized operator.
- [ ] Proxy CAs and device changes are limited to lab devices and removed afterwards.
- [ ] Radio/firmware/bootloader/BIOS tooling is used only on owned hardware in an authorized RF/hardware lab; active scanning, pairing, flashing and kernel-driver tools are never driven from this platform.
- [ ] drozer/dynamic tool agents are installed manually on owned devices only, never automatically from a scan or page load.
- [ ] Active DAST is not run against shared production systems.
- [ ] Findings are verified manually before being reported as exploitable.
- [ ] Medical/PHI/standards output is treated as evidence mapping, not certification.

---

## 11. Authoritative sources

### Mobile standards and techniques

- OWASP MASVS: https://mas.owasp.org/MASVS/
- MASVS v2.1 release and MASVS-PRIVACY: https://mas.owasp.org/news/2024/01/18/masvs-v210-release--masvs-privacy
- OWASP MASTG: https://mas.owasp.org/MASTG/
- MASTG techniques: https://mas.owasp.org/MASTG/techniques
- MASTG tools: https://mas.owasp.org/MASTG/tools
- MASTG v2.0 release: https://mas.owasp.org/news/2026/07/04/mastg-v200-release
- iOS security testing setup: https://mas.owasp.org/MASTG/0x06b-iOS-Security-Testing

### AppSec testing types

- OWASP SAST overview: https://devguide.owasp.org/en/05-implementation/05-static-analysis/
- OWASP Semgrep guide: https://devguide.owasp.org/en/05-implementation/05-static-analysis/01-semgrep
- OWASP DAST guideline: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-2-Dynamic-Application-Security-Testing
- OWASP IAST guideline: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-1-Interactive-Application-Security-Testing
- OWASP SCA guideline: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-3-Build/2-3-2-Software-Composition-Analysis/2-3-2-1-Software-Composition-Analysis
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10

### Tools and platforms

- MobSF documentation: https://mobsf.github.io/docs
- MobSF dynamic analyzer: https://mobsf.github.io/docs/dynamic_analyzer_docker.md
- MobSF API docs: https://mobsf.live/api_docs
- Semgrep documentation: https://docs.semgrep.dev/
- CodeQL code scanning: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning
- ZAP Docker docs: https://www.zaproxy.org/docs/docker
- ZAP API scan: https://www.zaproxy.org/docs/docker/api-scan
- OWASP Dependency-Check: https://owasp.org/projects/dependency-check
- OWASP Dependency-Track: https://dependencytrack.org/
- CycloneDX SBOM: https://cyclonedx.org/capabilities/sbom
- Gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- Apktool: https://github.com/iBotPeaches/Apktool
- jadx: https://github.com/skylot/jadx
- androguard: https://github.com/androguard/androguard
- Frida: https://frida.re/docs/home
- objection: https://github.com/sensepost/objection
- drozer: https://github.com/ReversecLabs/drozer
- Android platform-tools: https://developer.android.com/tools/releases/platform-tools
- Android emulator / AVD manager: https://developer.android.com/studio/run/managing-avds
- BlueZ: https://www.bluez.org/
- Nordic Semiconductor nRF Util: https://www.nordicsemi.com/Products/Development-tools/nRF-Util
- Nordic nRF Sniffer for BLE: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
- InternalBlue: https://github.com/seemoo-lab/InternalBlue
- Ubertooth One: https://github.com/greatscottgadgets/ubertooth
- Aircrack-ng: https://www.aircrack-ng.org/
- Bettercap: https://www.bettercap.org/
- Kismet: https://www.kismetwireless.net/
- hcxtools: https://github.com/ZerBea/hcxtools
- Wireshark: https://www.wireshark.org/
- Ghidra: https://ghidra-sre.org/
- radare2 / r2frida: https://rada.re/
- class-dump: https://github.com/nygard/class-dump
- APKiD: https://github.com/rednaga/APKiD
- QARK: https://github.com/linkedin/qark
- ipsw: https://github.com/blacktop/ipsw
- ios-deploy: https://github.com/ios-control/ios-deploy
- libimobiledevice: https://libimobiledevice.org/
- binwalk: https://github.com/ReFirmLabs/binwalk
- unblob: https://github.com/onekey-sec/unblob
- UEFITool: https://github.com/LongSoft/UEFITool
- CHIPSEC: https://chipsec.github.io/
- flashrom: https://www.flashrom.org/
- fwupd: https://fwupd.org/
- U-Boot: https://www.denx.de/wiki/U-Boot
- Hashcat: https://hashcat.net/hashcat/
- Burp Suite: https://portswigger.net/burp
- Contrast IAST: https://docs.contrastsecurity.com/en/iast-technology.html
- Black Duck Seeker: https://www.blackduck.com/interactive-application-security-testing.html

---

## Reusable cross-platform pentest agent

`tools/mobile_pentest_agent.py` is a safe-by-default, evidence-first wrapper around curated Android, Windows and Linux checks. It records every step — including skipped, blocked and not-testable rows — writes stdout/stderr evidence files, redacts credential-shaped values, and can emit JSON, Markdown, HTML, CSV and PDF reports. PDF support is lazily imported, so collection still works without ReportLab.

```powershell
# Master to-do list (50 Android / Windows / Linux checks)
python tools/mobile_pentest_agent.py checklist --out .\evidence\agent --format md,json

# Read-only host inventory on the current platform
python tools/mobile_pentest_agent.py collect --profile auto --out .\evidence\agent

# Android static + runtime defaults; invasive/network steps stay skipped unless opted in
python tools\mobile_pentest_agent.py collect --profile android --out .\evidence\agent `
  --target .\app.apk --package com.example.app --serial emulator-5554 `
  --hooks .\hooks.js

# Opt in only in an authorized lab
python tools\mobile_pentest_agent.py collect --profile android --out .\evidence\agent `
  --target .\app.apk --package com.example.app --serial emulator-5554 `
  --hooks .\hooks.js --allow-invasive --allow-network

# Multi-format report from normalized engagement JSON
python tools\mobile_pentest_agent.py report --input .\report_input.json --out .\ `
  --format json,md,html,pdf,csv
```

Safety behavior:

- no collector installs a CA on a real device, performs OTA radio capture, changes pairing/bonding, flashes firmware or touches bootloader/BIOS settings;
- `--allow-invasive` gates backup attempts, Frida hooks, Drozer invocation and bounded `tcpdump`; `--allow-network` gates proxy/capture steps; `--allow-ca-install` only records consent — installation remains a manual, explicitly authorized action;
- missing tools, missing configuration, timeouts and ungated steps appear in `agent_evidence/manifest.json` instead of being silently dropped;
- generated reports carry the authorization notice in the header and PDF page footer.

---

**For authorized security testing only.**
