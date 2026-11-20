# APK Pentest Platform

A self-hosted Android APK security assessment platform. Upload an APK and the platform runs:

- **SAST** — manifest, binary XML resources and DEX string constants
- **SCA** — bundled-library detection with an offline advisory database plus optional [OSV.dev](https://osv.dev/) lookups
- **Advanced analysis** — deep links/App Links, network-security-config hardening, native ELF hardening, trackers, packers/anti-analysis, high-entropy secrets, certificate forensics, attack chains, playbooks and compliance mapping
- **Live checks** — opt-in outbound checks for Firebase/S3 exposure, reachable plaintext endpoints and optional VirusTotal hash reputation
- **DAST** — adb-driven install/launch/logcat checks, deep-link and exported-component fuzzing, optional Frida hooks and proxy capture
- **Medical / PHI focus** — masked clinical-identifier detection, health-permission review and evidence mapping to HIPAA, GDPR, FDA, IEC 62304, ISO 14971, UL 2900-2-1, HITRUST and OWASP MASVS privacy
- **Advanced toolchain and interception lab** — APKHunt, APKLeaks, HCL AppScan, MobSF Dynamic, TrashDroid, RMS, Burp/ZAP/mitmproxy, MobSF-in-Chromium and gated patch/root/mod workflows
- **Tool manager** — curated catalog, one-click install/update, per-tool repository pull, source verification, Android emulator setup and jobs with live logs
- **Enterprise workflow** — custom rules, policy gates, scan diffing, CycloneDX SBOM, SARIF, optional JWT/API-token auth, audit logging and SSE progress
- **Reports** — self-contained HTML and JSON reports with severity, CWE, OWASP MASVS mapping and remediation

Everything works with just Python installed. External tools (apktool, jadx, aapt, semgrep, MobSF, adb, Frida) are optional hooks that enrich the built-in analysis.

> **For authorized security testing only.** Only analyze apps you own or have explicit written permission to test. Heuristic findings are leads, not proof — verify them manually. Live checks make outbound requests only when explicitly enabled and never write to third-party services. Medical/standards sections are evidence mappings, **not certifications** of HIPAA, GDPR, FDA, IEC 62304 or HITRUST compliance.

See **[TOOLS_README.md](TOOLS_README.md)** for the full tools/techniques reference: advanced SAST/DAST/IAST/SCA, SBOM/VEX, Android and iOS workflows, official sources, and practical commands for every curated tool.

---

## Quick start

Requires Python 3.10+ (tested on 3.15).

```bash
cd apk-pentest-platform
python -m pip install -r backend/requirements.txt
python run.py --port 8000
```

Open **http://127.0.0.1:8000** in a browser.

### Dedicated ports for web tools

The platform keeps port `8000`; each optional web UI has its own recommended local port so they can run at the same time:

| Service | Recommended port | Set one of these to enable its dashboard URL |
|---|---:|---|
| Platform dashboard | `8000` | `python run.py --port 8000` / `APKPT_PLATFORM_PORT` |
| MobSF static | `8001` | `APKPT_MOBSF_PORT=8001` or `APKPT_MOBSF_URL=...` |
| MobSF dynamic | `8002` | `APKPT_MOBSF_DYNAMIC_PORT=8002` or `APKPT_MOBSF_DYNAMIC_URL=...` |
| APKHunt | `8003` | `APKPT_APKHUNT_PORT=8003` or `APKPT_APKHUNT_URL=...` |
| RMS | `8004` | `APKPT_RMS_PORT=8004` or `APKPT_RMS_URL=...` |
| ZAP web UI | `8005` | `APKPT_ZAP_WEB_PORT=8005` or `APKPT_ZAP_WEB_URL=...` |

Setting a `*_PORT` variable constructs `http://127.0.0.1:<port>` for that tool; a full `*_URL` variable always wins. No URL is guessed until you set one of these variables, and Web UI launching remains gated. The **Tools → Web UI ports** panel shows the effective values.

Alternatively, run the API alone:

```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Try it with a deliberately vulnerable sample

```bash
python tools/make_sample_apk.py sample-vulnerable.apk
python tools/smoke_scan.py sample-vulnerable.apk      # engine-only smoke test
python tools/http_smoke.py http://127.0.0.1:8000 sample-vulnerable.apk
python tools/verify_all.py --iterations 100           # repeated verification
```

---

## Using the web UI

1. Drop an `.apk` on the upload panel (or click *browse*).
2. The scan runs in the background; progress updates via SSE with polling fallback.
3. Open the **Findings**, **Components**, **Advanced**, **Chains**, **Medical**, **Toolchain**, **Lab**, **Live**, **Policy**, **Dynamic**, **Tools**, **Metadata**, **Diff** and **Report** tabs.
4. From **Report**, download the HTML report, JSON report, CycloneDX SBOM or SARIF file.
5. From **Diff**, choose another completed scan to see new, resolved and changed findings.
6. Click **Tools & emulator manager** in the sidebar for one-click install/update, per-tool pull, source verification, emulator setup, installed-software inventory and job logs. Open **Installed software dashboard** for the standalone HTML view of executables, setup files, official sources, emulator needs and web-UI launch buttons.

Scan history is stored on disk, so previous reports remain available after a restart.

---

## What the built-in engines detect

**SAST** (manifest + binary XML + DEX strings):

- `debuggable`, `allowBackup` without rules, `usesCleartextTraffic`, legacy external storage, old target/min SDK, `sharedUserId`
- Exported activities/services/receivers/providers without permission guards, URI-grant providers, task-affinity hijacking
- Hardcoded secrets (AWS/GitHub/Slack/Stripe/Google API keys, private keys, JWTs, credentials in URLs, password assignments)
- Weak crypto (MD5, SHA-1, DES, RC4, ECB), weak RNG, TLS TrustManager/hostname-verifier bypasses, missing pinning
- WebView risks (JavaScript, `addJavascriptInterface`, file/content access, remote debugging)
- World-readable files, public external storage, raw SQLite queries, sensitive logging
- Signing scheme checks (missing/v1-only signatures, multiple signers), root-detection and obfuscation hints

**SCA**:

- Detects OkHttp, jsoup, Guava, Log4j, Jackson Databind, Commons IO, Bouncy Castle, libwebp, Retrofit, Gson, Glide, Firebase and AndroidX WebKit
- Version extraction from embedded strings where possible
- Offline advisories (including real CVEs such as CVE-2021-44228, CVE-2021-37714, CVE-2023-4863) and online OSV.dev enrichment

**Advanced**:

- Browsable custom-scheme deep links and unverified HTTPS App Links
- Implicit intents, mutable PendingIntents and unvalidated parcelable extras
- `network_security_config.xml` parsing: user CAs, debug overrides, cleartext rules, pin sets and expired pins
- Tracker/SDK inventory (Analytics, Ads, Crash Reporting, Social, Attribution, Payments, Messaging)
- APKiD-like packer/anti-analysis signals
- ELF hardening for bundled `.so` files: PIE, NX stack, RELRO/full RELRO, stack canaries, FORTIFY, RPATH/RUNPATH, stripped symbols
- Signing certificate forensics: debug certificates, SHA-1 chains, short keys, expiry and v1/JANUS risk
- High-entropy string candidates that may be hardcoded secrets
- Attack-chain synthesis, a guided verification playbook and OWASP MASVS v2 / Mobile Top 10 coverage mapping

**Live checks** (opt-in with `APKPT_LIVE_CHECKS=1`):

- Firebase Realtime Database and S3 bucket exposure probes
- Plaintext HTTP endpoint reachability
- Optional VirusTotal hash reputation when `APKPT_VIRUSTOTAL_API_KEY` is set
- Only public hosts are contacted; redirects are disabled and requests use short timeouts

**DAST** (when `adb` and a device are available):

- Installs the APK, launches the launcher activity, captures logcat
- Detects runtime crashes, cleartext URLs, sensitive log lines, `DEBUGGABLE` flag and data readable via `run-as`
- Launches browsable deep links and fuzzes exported activities/services/receivers with hostile Intent extras
- Optional Frida hooks for `checkServerTrusted`, `HostnameVerifier`, WebView JavaScript and JS bridges
- Optional HTTP proxy configuration (Burp/ZAP) and screenshot capture
- Uninstalls the test app afterwards
- Records the configured Burp/ZAP/mitmproxy endpoint, proxy CA status and Network Security Configuration constraints (including user-CA trust and pinning)

**Medical / PHI analysis** (enabled by default):

- Detects masked MRN/SSN/DOB/insurance, ICD-10/CPT/NDC, FHIR/HL7 and clinical-context indicators in APK strings
- Reviews health-related permissions (SMS, contacts, location, camera/audio, body sensors, notifications, biometric)
- Correlates PHI indicators with cleartext transport, logging, backup, exported components, unsafe storage, trackers and weak authentication
- Maps evidence to HIPAA `45 CFR 164.312`, GDPR Arts. 5/6/32, FDA 2026 premarket cybersecurity guidance, IEC 62304, ISO 14971/AAMI SW96, UL 2900-2-1, HITRUST CSF and OWASP MASVS v2.1 privacy
- Emits `MEDICAL` findings and an optional release gate via `APKPT_POLICY_MEDICAL_GAPS`
- Reports are evidence/review material only; they do **not** certify regulatory compliance

**Advanced toolchain and interception lab** (opt-in):

- **Probe-only by default**: `GET /api/tools/advanced` reports availability, enablement and skip reasons without running anything
- **Safe hooks** (`APKPT_TOOLCHAIN_AUTO=1`): APKHunt (local web workbench HTTP hook or legacy CLI), APKLeaks endpoints/secrets, HCL AppScan upload, MobSF Dynamic scan and TrashDroid (the latter also requires emulator/invasive opt-ins)
- **Interception lab**: generates Burp/ZAP/mitmproxy listener commands, Android proxy set/clear commands, a metadata-only mitmproxy addon, proxy-CA steps and Network Security Configuration warnings; DAST records the same proxy/CA/NSC state
- **MobSF in Chromium**: `POST /api/lab/open-mobsf` opens only a configured MobSF URL (or its system-browser fallback) after explicit `APKPT_BROWSER_OPEN=1`
- **Invasive workflows are never started by a scan**: `patch-apk.py`, objection/Frida gadget injection, manual `apktool` + `jarsigner`/`apksigner` smali patching, test-only NSC patching, APatch root/system modification, ReC Manager, RMS, APK modding and translation are planned first. Execution requires `APKPT_TOOLCHAIN_AUTO=1`, `APKPT_ALLOW_INVASIVE=1` and an authenticated `POST /api/lab/patch`
- Missing tools, devices, CA certificates or approvals are reported as `skipped`/`manual-required`, never as a silent failure

**PKI / certificate and keystore tooling**:

- Passive analysis of APK signing certificates: subject/issuer, serial, SHA-256 fingerprint, signature algorithm, public-key algorithm/size, validity, self-signed and CA-basic-constraints flags, plus v1-only/JANUS surface
- Emits informational `PKI` findings for weak signature algorithms, small RSA/EC keys, expired or very long-lived certificates, debug/self-signed identities, CA certificates used as app signers, user-CA trust and cleartext traffic. These are context for manual review, never threat/malware verdicts, and are excluded from release-policy gates
- Surfaces TLS trust/pinning evidence from `network_security_config.xml` and includes a PKI section in the HTML report, `GET /api/scans/{id}`, `GET /api/scans/{id}/pki`, and the static/React **PKI** tabs
- Local lab CA generation/import and PKCS#12 keystore generation are **local files only** under `APKPT_PKI_DIR`; they never install a CA on a device and never launch an emulator or browser
- Write endpoints require authentication (when enabled), `confirm: true`, `APKPT_PKI_LAB=1` and an explicit action; every call is audit-logged. Device CA deployment remains a separate invasive workflow requiring `APKPT_EMULATOR_AUTO=1`, `APKPT_ALLOW_INVASIVE=1` and an authenticated device action
- Catalog entries for `keytool`, `openssl` and `apksigner` expose official-source metadata and **Verify** actions. Manual JDK/OpenSSL tools are never falsely auto-installed; `apksigner` is installed only through the official Android SDK build-tools job
- **PKI tooling is not a malware/threat detection engine.** Exact PKI tool and certificate artifact strings (`keytool`, `openssl`, `apksigner`, `keystore`, SHA-256 fingerprints, etc.) are filtered from suspicious-string and entropy heuristics so they are never reported as malware or threat indicators. Every PKI finding is labelled informational and carries an explicit non-accusatory disposition in the report and UI.

**Bluetooth / BLE communication surface** (passive, informational only):

- Passive evidence only: Bluetooth-related manifest permissions, BLE/GATT and classic RFCOMM API strings, pairing/bonding APIs, and UUID-shaped values extracted from the APK.
- Emits informational `BLUETOOTH` findings with an explicit non-accusatory disposition. They are excluded from release-policy gates and from suspicious-string/entropy heuristics, exactly like PKI evidence.
- Available in the HTML report, `GET /api/scans/{id}`, `GET /api/scans/{id}/bluetooth`, `GET /api/bluetooth/status`, and the static/React **Bluetooth** tabs.
- Local `bluetoothctl`, `hcitool` and `nrfutil` availability is reported read-only. The platform **never performs a radio scan, pairing, bonding, or any device modification**. `APKPT_BLUETOOTH_LAB=1` only enables optional local tooling status (default `0`).
- Catalog entries use official sources (BlueZ, Nordic Semiconductor) and are manual/verify-only; they are never falsely auto-installed.
- **Bluetooth tooling is not a malware/threat detection engine.** Tool names and UUID-shaped values are filtered from threat heuristics so they cannot be reported as malware or threat indicators.

**Emulator-backed DAST wiring** (all launches remain gated):

- `GET /api/lab/emulator` reports read-only DAST readiness: adb availability, attached emulator/physical serials, selected target (`APKPT_DAST_SERIAL` wins; otherwise an emulator is preferred when `APKPT_DAST_PREFER_EMULATOR=1`), AVD presence and SDK paths.
- `GET /api/lab/emulator/plan` returns a non-executing plan (create AVD → launch → verify adb → run DAST → teardown).
- `POST /api/lab/emulator/launch` and `POST /api/lab/emulator/stop` require `confirm: true`, authentication when enabled, and `APKPT_EMULATOR_AUTO=1`. With the default gate off they return `skipped`. No emulator is ever launched automatically by a scan.
- DAST records now include `emulator_target` and `dast_info.lab` with the readiness and plan, visible in the static/React **Lab** tabs.

**Tool manager and emulator setup** (explicit dashboard action, disabled by default):

- Open **Tools & emulator manager** in the sidebar. Jobs never start from a scan or from page load.
- Set `APKPT_TOOL_MANAGER=1` and restart the server to enable job execution. With the default `0`, actions return `skipped` and explain how to enable them.
- **Install / update all** processes every auto-installable tool sequentially; **Update all** refreshes installed tools; **Verify all sources** performs allowlisted reachability checks only.
- Per-tool **Install**, **Update**, **Pull** and **Verify** buttons let you manage one tool at a time. `Pull`/`Update` for Git-backed tools runs `git pull --ff-only` when `git` is installed; otherwise the manager downloads a pinned GitHub source snapshot through the API.
- **Install emulator** downloads official Android cmdline-tools and platform-tools, accepts SDK licenses, installs platform 34/build-tools/emulator, creates a local AVD, and then installs the host-side DAST toolchain. It does not launch or modify a device. `adb` is auto-discovered from `ANDROID_SDK_ROOT/platform-tools` when it is not on PATH, so DAST and readiness checks work after setup without manual PATH edits; `APKPT_ADB_CMD` still takes precedence.
- **Install DAST tools** (`POST /api/tools/dast/install` with `confirm: true`) installs only host-side mobile CLI tooling: **drozer** console, **Androguard**, **APKiD** and **QARK**. The drozer agent APK is never installed automatically — it needs a separate, explicit manual action on an owned device/emulator. No emulator launch, radio scan, device pairing or firmware change is performed. The same toolchain is a step in the emulator DAST plan (`install_dast_tools`).
- The catalog also includes research/verification entries for **Bluetooth/BLE** (InternalBlue, Ubertooth, nRF Sniffer), **Wi-Fi** (Aircrack-ng, Bettercap, Kismet, hcxtools, Wireshark), **iOS** (ipsw, ios-deploy, libimobiledevice, class-dump), reverse engineering (Ghidra, radare2) and **bootloader/firmware/BIOS** work (Binwalk, unblob, UEFITool, CHIPSEC, flashrom, fwupd, U-Boot, Hashcat). All of these are **manual / verify-only**: the platform records their official source and setup notes but never installs, launches or drives them. Active radio, device-modification and firmware-writing tools are additionally marked *invasive*. This is tooling guidance for authorized labs, not a malware/threat detection engine.
- Every job has a persistent ID, status, progress, timestamp and log. The final status/detail now reflect the tool result (`completed`, `skipped` with the exact reason, or `failed`) instead of a generic “Job finished” message. Poll `GET /api/tools/jobs/{id}` or stream `GET /api/tools/jobs/{id}/events`.
- Once the manager is enabled, obsolete `Tool manager is disabled` records are moved from the active job list into `backend/storage/tools/jobs/archive/<timestamp>/` so they cannot hide real jobs; the audit logs remain on disk.
- Downloads are restricted to official HTTPS hosts by default (`api.github.com`, `github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `raw.githubusercontent.com`, `dl.google.com`, `developer.android.com`, `docs.oracle.com`, `docs.openssl.org`, `www.openssl.org`, `pypi.org`, `files.pythonhosted.org`, `zaproxy.org`, `portswigger.net`, `www.chromium.org`, `www.bluez.org`, `www.nordicsemi.com`, `developer.nordicsemi.com`). New tool entries use only these allowlisted HTTPS sources (GitHub/PyPI/Nordic); administrators can narrow the list with `APKPT_TOOL_ALLOWED_HOSTS`. Redirects to other hosts are rejected. GitHub release assets are SHA-256 verified from the release API.
- Transient upstream/proxy `502`, `503` and `504` responses are retried with exponential backoff (`APKPT_TOOL_MANAGER_RETRIES=3`, `APKPT_TOOL_MANAGER_RETRY_DELAY=2` by default). Partial downloads are discarded between attempts. Persistent failures include the URL and retry settings in the job log. The dashboard also retries failed read-only `GET` requests; a `502` for the page itself means the backend is not reachable through the current port-forward/proxy.
- Burp Suite, ZAP's installer, APatch, ReC Manager, Chromium, `keytool` and OpenSSL are intentionally **manual** because of licenses, interactive installers, JDK dependence or device risk. The catalog shows their official source and setup note. Cards for manual or unsupported tools show **Manual** / **Unavailable**, a **Verify** action and a **Why** explanation instead of a misleading download button. Tools that are already installed no longer show a redundant **Install** action. Auto-install attempts that upstream cannot satisfy (for example `semgrep`, `mobsf`, `drozer` or `androguard` wheels on Python 3.15) are reported as `skipped` with the exact reason instead of failing with a long pip traceback; use Python 3.10-3.14 or the official manual guide, then run **Verify**. On the current Python 3.15 host, APKiD and QARK are already installed while the drozer console and Androguard need a supported Python.
- `patch-apk.py` and APatch are marked invasive; installing tooling does not execute patching or rooting. Those workflows still require the separate lab gates.
- Each successful install/update writes the tool name, version, executable path, setup/archive path, official source URL, configured web URL, install timestamp and originating job ID to a local SQLite inventory (`backend/storage/installed_tools.db` by default). `Sync installed DB` backfills records for tools already found on the system.
- The standalone HTML dashboard is available at `/tools/dashboard`. It shows the OS, source policy, emulator requirements, installed executables/setup files, ordered tool access and recent job logs. It does not launch anything on page load.
- Tool access is sequenced into seven numbered workflow groups with icons and small action text: **1 Decode & inspect**, **2 Static analysis**, **3 Device & emulator**, **4 Runtime & patching**, **5 Dynamic testing**, **6 Proxy & browser**, **7 Manual / root lab**. Search by name/id/category or click a group chip to filter. Manual and invasive tools are labelled and placed last. Each card exposes only the allowed actions for that tool (Install, Update, Pull for repository-backed tools, Verify, Web UI for configured URLs, and official Source). The full table is still available under **Detailed catalog table** in the main UI.
- Per-tool **Web UI** buttons (and the MobSF button) call the gated `/api/tools/web/{tool_id}` endpoint. Only explicitly configured URLs are used: `APKPT_MOBSF_URL` / `APKPT_MOBSF_DYNAMIC_URL`, `APKPT_APKHUNT_URL`, `APKPT_RMS_URL` and `APKPT_ZAP_WEB_URL`, or the matching `APKPT_*_PORT` variables that build local URLs on dedicated ports. Server-side launching still requires `APKPT_BROWSER_OPEN=1`; otherwise the API returns `skipped`. The existing `POST /api/lab/open-mobsf` remains available for scan-specific MobSF links. Both responses now include a fresh `installed` / `version` / `path` check, and a skipped MobSF URL message states whether the local MobSF package is installed. The UI refreshes the catalog and installed inventory as soon as a job finishes or a Web UI action returns, so tool status and the message banner update immediately instead of staying `missing` until a manual reload.
- Starting any install/update/verify/emulator/DAST-toolchain job opens a full-height **green live terminal** on the right side. It streams the persisted job log while the job runs, then closes automatically 3 seconds after completion, failure or skip. `×` or `Esc` closes it early. The footer keeps the “For authorized security testing only” notice visible.
- A bottom-right **shell** widget provides a small command console for the same gated jobs. It is collapsed by default, toggles with the `›_ shell` button or `Ctrl`/`Cmd` + `` ` ``, and auto-hides after 30 seconds of inactivity. It accepts only allowlisted commands such as `help`, `status`, `jobs`, `sync`, `install all`, `update all`, `verify all`, `emulator install`, `dast install`, `apktool install`, `adb verify`, `gittool pull` and `open mobsf`; it does **not** expose an arbitrary OS shell. Commands are audited, require `confirm: true`, and create normal persisted jobs with streamed logs. `clear`, ↑/↓ history and `Esc` hide are client-side only. Job banners, status pills, progress indicators and streamed log lines use terminal-style colours: neon **green** while installing/updating/processing/running, regular green for normal success, **blue** for info, **yellow** for low-level warnings, **orange** for high errors and **red** for critical errors. The same colour classes are used by `/tools/dashboard` and the React source UI.

---

## Optional external tools

| Tool | Purpose | How to enable |
|---|---|---|
| `apktool` | Decompile manifest/resources for extra strings | Install on PATH; detected automatically |
| `jadx` | Decompile DEX to Java for higher-fidelity secrets detection | Install on PATH; detected automatically |
| `aapt` / `aapt2` | Capture package badging metadata | Install on PATH; detected automatically |
| `semgrep` | Rule-based scan of jadx-generated Java source | Install on PATH; requires jadx source |
| `MobSF` | Full MobSF static scan merged into findings | `APKPT_MOBSF_URL=http://127.0.0.1:8000`, `APKPT_MOBSF_API_KEY=...` |
| `adb` | Required for DAST | On PATH, or auto-discovered from `ANDROID_SDK_ROOT/platform-tools` after emulator setup |
| `frida` | Runtime hooking | `pip install frida-tools`, set `APKPT_DAST_FRIDA=1` |
| Emulator | DAST target | Start an Android emulator with USB debugging |

If a tool is missing, the corresponding check is reported as *skipped* — scans still complete.

Findings from external tools and SCA advisories are imported without a count limit by default (`APKPT_TOOL_FINDING_LIMIT=0`). A positive value is an optional volume guard for constrained hosts; it does not change the built-in SAST/SCA/DAST engines. Exact duplicates are still collapsed, but distinct matches that share a rule or title are preserved.

For DAST with a specific device:

```bash
APKPT_DAST_SERIAL=emulator-5554 APKPT_DAST_FRIDA=1 python run.py
```

---

## Configuration

All settings are environment variables with sensible defaults:

| Variable | Default | Meaning |
|---|---|---|
| `APKPT_STORAGE_DIR` | `backend/storage` | Where uploads, records, reports, exports and the audit log are stored |
| `APKPT_MAX_UPLOAD_MB` | `250` | Upload size limit |
| `APKPT_ENABLE_SAST` / `_SCA` / `_DAST` / `_ADVANCED` | `1` | Toggle engines |
| `APKPT_SCA_ONLINE` | `1` | Query OSV.dev (failures ignored) |
| `APKPT_SCA_ONLINE_TIMEOUT` | `6` | OSV timeout in seconds |
| `APKPT_DAST_SERIAL` | empty | Target adb device serial |
| `APKPT_DAST_WAIT` | `12` | Seconds to observe the app after launch |
| `APKPT_DAST_FRIDA` | `0` | Enable Frida hooks |
| `APKPT_DAST_PROXY` | empty | `burp`, `zap`, `mitmproxy`, `http://host:port` or `host:port` |
| `APKPT_DAST_UNINSTALL` | `1` | Uninstall test app after DAST |
| `APKPT_ENABLE_MEDICAL` | `1` | Enable medical/PHI analysis |
| `APKPT_MEDICAL_DOMAIN` / `APKPT_PHI_MODE` | `healthcare` / `detect` | Domain label and PHI mode (`off` disables detection) |
| `APKPT_POLICY_MEDICAL_GAPS` | `-1` | Maximum unresolved medical control gaps (`-1` disables the gate) |
| `APKPT_TOOLCHAIN_AUTO` | `0` | Allow third-party tool hooks and lab probe execution |
| `APKPT_TOOLCHAIN_TIMEOUT` | `300` | Timeout for external tool commands |
| `APKPT_TOOL_FINDING_LIMIT` | `0` | Max imported tool/SCA findings; `0` means unlimited (no 100-result cap) |
| `APKPT_TOOL_APKHUNT` / `_APKLEAKS` / `_APPSCAN` / `_TRASHDROID` / `_RMS` / `_MITMPROXY` / `_ZAP` / `_BURP` / `_RECMANAGER` | `1` | Per-tool enable switches |
| `APKPT_APKHUNT_PORT` | `8003` | Build `APKPT_APKHUNT_URL` on a dedicated local port when set |
| `APKPT_APKHUNT_URL` / `_UPLOAD_PATH` / `_REPORT_PATH` / `_API_KEY` | empty | Authorised APKHunt web workbench hook |
| `APKPT_APPSCAN_SERVER` / `_API_KEY` / `_CMD` | empty | HCL AppScan upload settings; `_CMD` must be a non-interactive template |
| `APKPT_TRASHDROID_CMD` / `_DROZER_CMD` / `_ANDROGUARD_CMD` / `_APKID_CMD` / `_QARK_CMD` / `_RMS_CMD` / `_MITMPROXY_CMD` / `_ZAP_CMD` / `_BURP_CMD` | tool defaults | Binary overrides for lab tools |
| `APKPT_PATCHAPK_CMD` / `_OBJECTION_CMD` / `_APATCH_CMD` / `_RECMANAGER_CMD` / `_CHROMIUM_CMD` | defaults/empty | Patching, root, reverse-engineering and browser command overrides |
| `APKPT_ADB_CMD` | `adb` | adb binary/command override |
| `APKPT_TOOL_APKTOOL` / `_JADX` / `_AAPT` / `_SEMGREP` | `1` | Enable tool hooks when installed |
| `APKPT_SEMGREP_TIMEOUT` | `90` | Semgrep timeout in seconds |
| `APKPT_TOOL_WEB_HOST` | `127.0.0.1` | Host used when a `*_PORT` variable builds a tool web UI URL |
| `APKPT_PLATFORM_PORT` | `8000` | Reported platform port (the actual listener is set with `run.py --port`) |
| `APKPT_MOBSF_PORT` | `8001` | Build `APKPT_MOBSF_URL` on a dedicated local port when set |
| `APKPT_MOBSF_URL` / `_API_KEY` | empty | MobSF static integration; a full URL overrides `APKPT_MOBSF_PORT` |
| `APKPT_MOBSF_DYNAMIC_PORT` | `8002` | Build `APKPT_MOBSF_DYNAMIC_URL` on a dedicated local port when set |
| `APKPT_MOBSF_DYNAMIC_URL` | `APKPT_MOBSF_URL` | MobSF dynamic API instance |
| `APKPT_BROWSER_OPEN` | `0` | Allow server-side web-UI/MobSF launching in Chromium/system browser |
| `APKPT_EMULATOR_AUTO` | `0` | Allow explicit device proxy changes |
| `APKPT_ALLOW_INVASIVE` | `0` | Allow patch/root/mod workflows (still requires an authenticated call) |
| `APKPT_EMULATOR_CMD` / `_AVD` | empty | Emulator command and AVD for generated lab commands |
| `APKPT_JAVA_CMD` | empty | Explicit Java runtime for emulator setup; auto-detected from PATH or common install paths when empty |
| `APKPT_TOOL_MANAGER` | `0` | Enable explicit install/update/pull/emulator jobs |
| `APKPT_TOOLS_DIR` | `backend/storage/tools` | Managed downloads, repositories, wrappers, metadata and job logs |
| `APKPT_ANDROID_SDK_ROOT` | `APKPT_TOOLS_DIR/android-sdk` | SDK root used by emulator setup |
| `APKPT_TOOL_MANAGER_TIMEOUT` / `_WORKERS` | `900` / `2` | Per-command timeout and maximum concurrent jobs |
| `APKPT_TOOL_MANAGER_RETRIES` / `_RETRY_DELAY` | `3` / `2` | Retry transient upstream/proxy 502/503/504 responses with exponential backoff |
| `APKPT_TOOL_ALLOWED_HOSTS` | official hosts listed above | Comma-separated HTTPS download host allowlist |
| `APKPT_INSTALLED_DB` | `backend/storage/installed_tools.db` | SQLite inventory of installed executables/setup files |
| `APKPT_RMS_PORT` | `8004` | Build `APKPT_RMS_URL` on a dedicated local port when set |
| `APKPT_RMS_URL` | empty | Configured RMS web UI used by the gated Web UI button |
| `APKPT_ZAP_WEB_PORT` | `8005` | Build `APKPT_ZAP_WEB_URL` on a dedicated local port when set |
| `APKPT_ZAP_WEB_URL` | empty | Configured ZAP web UI used by the gated Web UI button |
| `APKPT_EMULATOR_SYSTEM_IMAGE` | Android 34 Google APIs | AVD system image (arch auto-detected) |
| `APKPT_PROXY_HOST` / `_PORT` | `127.0.0.1` / `8080` | Interception proxy listener address |
| `APKPT_CA_CERT_PATH` | empty | Proxy CA to push to the authorized test device |
| `APKPT_KEYTOOL_CMD` / `_OPENSSL_CMD` | `keytool` / `openssl` | Command overrides for PKI tool detection and Verify |
| `APKPT_PKI_LAB` | `0` | Enable explicit local CA/keystore generate/import endpoints |
| `APKPT_PKI_DIR` | `APKPT_TOOLS_DIR/pki` | Directory for local lab CA, key and PKCS#12 keystore |
| `APKPT_PKI_CA_DAYS` | `365` | Validity of generated lab CA/leaf certificates |
| `APKPT_PKI_KEYSTORE_PASSWORD` | `changeit` | Password for generated local lab keystores (change in real labs) |
| `APKPT_LIVE_CHECKS` | `0` | Enable outbound live checks |
| `APKPT_LIVE_TIMEOUT` / `_MAX_ENDPOINTS` | `6` / `5` | Live-check request timeout and endpoint cap |
| `APKPT_VIRUSTOTAL_API_KEY` | empty | Enable VirusTotal hash reputation lookup |
| `APKPT_CUSTOM_RULES` | `backend/app/data/custom_rules.json` | Custom rule store |
| `APKPT_POLICY_CRITICAL` / `_HIGH` / `_MEDIUM` / `_LOW` | `0/0/10/100` | Release-gate maximums per severity |
| `APKPT_AUTH_ENABLED` | `0` | Require auth for write operations |
| `APKPT_ADMIN_USER` / `_PASS` | `admin` / `admin` | Login credentials (change before use) |
| `APKPT_JWT_SECRET` | `change-me-in-production` | HMAC signing secret (change before use) |
| `APKPT_JWT_TTL_HOURS` | `24` | Token lifetime |
| `APKPT_API_TOKEN` | empty | Optional static `X-API-Key` for automation |
| `APKPT_CORS_ORIGINS` | localhost:5173 | Comma-separated allowed origins |
| `VITE_API_URL` | empty (same origin) | API base URL for the React app |

Authentication is off by default for local development. Before exposing the service, set `APKPT_AUTH_ENABLED=1`, change the admin password and JWT secret, and preferably set `APKPT_API_TOKEN`. All write operations, lab actions and login events are appended to `backend/storage/audit.log`. Keep `APKPT_EMULATOR_AUTO` and especially `APKPT_ALLOW_INVASIVE` off unless the device and app are in your authorized test scope.

---

## Custom rules

Rules are JSON documents with `id`, `title`, `severity`, `scope` and `pattern`:

```json
{
  "id": "MY-RULE",
  "title": "Custom: internal hostname",
  "severity": "medium",
  "scope": "strings",
  "pattern": "internal\\.corp\\.example",
  "remediation": "Remove development endpoints from release builds."
}
```

Scopes: `strings`, `manifest`, `permission`, `component`, `package`, `filename`.

Manage them through `GET/POST/DELETE /api/rules` or edit `backend/app/data/custom_rules.json` directly. Changed rules apply to the next scan.

---

## REST API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Engine/tool status |
| `GET` | `/health`, `/healthz` | Hidden aliases for proxies and uptime checks |
| `GET` | `/api/config` | Configuration summary |
| `GET` | `/api/tools/advanced` | Probe the advanced toolchain (no execution) |
| `GET` | `/api/tools/catalog` | Curated tool catalog, OS details, installed versions, source policy and emulator needs |
| `GET` | `/api/tools/installed` | SQLite inventory of installed executables and setup files |
| `POST` | `/api/tools/installed/sync` | Backfill the inventory with tools already on the system (gated) |
| `POST` | `/api/tools/web/{id}` | Open a configured tool/MobSF web UI (gated by `APKPT_BROWSER_OPEN`) |
| `POST` | `/api/tools/shell` | Run one allowlisted mini-terminal command through the gated manager (audited) |
| `GET` | `/tools/dashboard` | Standalone HTML dashboard for inventory, sources, emulator needs and job logs |
| `GET` | `/api/tools/jobs` | Recent tool-manager jobs |
| `GET` | `/api/tools/jobs/{id}` | Job detail, progress and logs |
| `GET` | `/api/tools/jobs/{id}/events` | SSE stream of job progress/logs |
| `POST` | `/api/tools/install-all` | Create an install/update-all job (gated) |
| `POST` | `/api/tools/update-all` | Create an update-all job (gated) |
| `POST` | `/api/tools/emulator/install` | Create an emulator setup job (gated) |
| `POST` | `/api/tools/{id}/{action}` | Per-tool `install`, `update`, `pull` or `verify` job (gated) |
| `GET` | `/api/lab/status` | Emulator, device, proxy and CA status |
| `POST` | `/api/lab/proxy` | Set or clear the device proxy (gated, authenticated when enabled) |
| `POST` | `/api/lab/open-mobsf` | Open a configured MobSF URL in Chromium (gated) |
| `POST` | `/api/lab/patch` | Execute an explicitly gated patch workflow |
| `GET` | `/api/pki/status` | Local PKI lab status (read-only, no device changes) |
| `POST` | `/api/pki/ca/generate` | Generate a local lab CA (gated, audited, local-only) |
| `POST` | `/api/pki/ca/import` | Import a PEM certificate into local lab storage (gated, audited) |
| `POST` | `/api/pki/keystore/generate` | Generate a local PKCS#12 lab keystore (gated, audited) |
| `POST` | `/api/auth/login` | Obtain a bearer token (when auth is enabled) |
| `GET` | `/api/rules` | List custom rules |
| `POST` | `/api/rules` | Add/update a custom rule (auth required when enabled) |
| `DELETE` | `/api/rules` | Delete a custom rule by `rule_id` (auth required when enabled) |
| `POST` | `/api/scans` | Multipart upload (`file` field), returns `scan_id` |
| `GET` | `/api/scans` | List scans with policy status |
| `GET` | `/api/scans/{id}` | Full scan record (polling endpoint) |
| `GET` | `/api/scans/{id}/medical` | Medical/PHI evidence and standards mapping |
| `GET` | `/api/scans/{id}/pki` | Passive PKI certificate/trust analysis and lab status for this scan |
| `GET` | `/api/scans/{id}/toolchain` | Advanced tool status for this scan |
| `GET` | `/api/scans/{id}/lab` | Generated emulator/proxy/patching plan |
| `GET` | `/api/scans/{id}/events` | Server-sent progress events |
| `GET` | `/api/scans/{id}/report.html` | Self-contained HTML report |
| `GET` | `/api/scans/{id}/report.json` | JSON report |
| `GET` | `/api/scans/{id}/export/sbom.json` | CycloneDX 1.5 SBOM |
| `GET` | `/api/scans/{id}/export/sarif.json` | SARIF 2.1.0 report |
| `GET` | `/api/scans/{id}/diff?against={id2}` | New/resolved/changed findings between scans |
| `POST` | `/api/scans/{id}/cleanup` | Remove temporary decompilation artifacts |
| `DELETE` | `/api/scans/{id}` | Delete a scan |

Upload example:

```bash
curl -F "file=@app.apk" http://127.0.0.1:8000/api/scans
```

Authenticated write example:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" -F "file=@app.apk" http://127.0.0.1:8000/api/scans
```

---

## Frontend

The API serves a zero-dependency dashboard from `frontend/static` by default.

A React/Vite version of the same UI lives in `frontend/`. If Node is installed:

```bash
cd frontend
npm install
npm run dev          # http://127.0.0.1:5173 (proxies /api to :8000)
npm run build        # writes frontend/dist
```

When `frontend/dist` exists, the API serves the React build instead of the static dashboard.

---

## Project layout

```
backend/app/
  main.py            FastAPI routes, auth dependencies, SSE, exports, diff
  auth.py            HMAC tokens, API keys, audit log
  config.py          environment configuration
  models.py          Pydantic models
  storage.py         filesystem scan store
  tool_manager.py    curated catalog, gated install/update jobs, inventory and HTML dashboard, emulator setup
  installed_db.py    SQLite inventory of executables, setup files, sources and job IDs
  scanner/
    apk.py           AXML + DEX parser, APK metadata, signing info
    sast.py          static analysis rules
    sca.py           composition analysis + OSV.dev
    advanced.py      deep links, NSC/ELF hardening, trackers, chains, compliance
    medical.py       PHI indicators, health permissions, standards mapping
    custom.py        administrator-defined rules
    live.py          opt-in outbound checks
    dast.py          adb/Frida dynamic analysis + intent fuzzing
    tools.py         apktool/jadx/aapt/semgrep/MobSF hooks
    toolchain.py     APKHunt/APKLeaks/AppScan/MobSF Dynamic/TrashDroid hooks
    lab.py           emulator, proxy, CA, Chromium and patch-workflow planner
    exports.py       CycloneDX SBOM, SARIF, scan diffing
    policy.py        release-gate evaluation
    pipeline.py      orchestration
    reporting.py     HTML report generator
  data/
    vuln_db.json     offline advisory database
    custom_rules.json bundled example rules
frontend/
  static/index.html  zero-dependency dashboard
  src/               React/Vite application
tools/               sample APK generator, smoke tests, 100x verifier
```

---

## Tests and verification

```bash
python -m compileall -q backend tools run.py
python -m unittest discover -s backend/tests -v
python tools/smoke_scan.py sample-vulnerable.apk
python tools/verify_all.py --iterations 100
```

`verify_all.py` repeats a full in-process assessment of the sample APK 100 times. Each iteration checks SAST, SCA, custom rules, advanced analysis, medical/PHI analysis, attack chains, playbook, compliance, toolchain/lab safety gates, DAST's no-device behavior, policy evaluation (including the optional medical gate), HTML/SBOM/SARIF generation, scan diffing and auth tokens. OSV, live checks, third-party hooks, proxy changes, browser opening and invasive workflows are disabled during verification so results are deterministic and no outbound requests or device modifications are made. The verifier checks the tool-manager catalog and install gate without running any install job.

For HTTP coverage, start the server and run:

```bash
python run.py --port 8123
python tools/http_smoke.py http://127.0.0.1:8123 sample-vulnerable.apk
```

---

## Limitations

- DEX inspection is string-based; it does not decompile bytecode or build full data-flow graphs. Some rules are deliberately heuristic and marked with low confidence.
- The offline vulnerability database is curated for demonstration, not exhaustive. Keep OSV lookup enabled and replace `vuln_db.json` with a maintained feed in production.
- Version detection from strings is best-effort; absence of a version does not mean a component is safe.
- DAST requires a real device/emulator and is reported as *skipped* when prerequisites are missing. Deep-link and intent fuzzing only run with a connected device.
- Live checks are disabled by default and depend on public DNS/HTTP access; a `skipped`, `error` or `not_applicable` result is not proof of safety.
- Semgrep findings require jadx-generated Java source; if jadx is unavailable the hook reports why it was skipped.
- Medical/PHI detection is keyword- and pattern-based. Masked indicators are review leads; they do not establish that real ePHI is present, and standards mappings are not legal or regulatory certification.
- HTTPS interception on Android 7+ requires a trusted user CA or a test-only Network Security Configuration; Android 14+ system-store changes generally require a rooted, authorized test device. The lab reports these constraints rather than bypassing them.
- Rooting, APatch, Frida/objection injection, smali patching, modding and translation can damage a device or invalidate an app signature. They are planned only until explicitly enabled and authenticated.
- Tool-manager jobs are disabled by default. Enabling `APKPT_TOOL_MANAGER=1` permits local downloads, pip installs, Git pulls and SDK installs only after an explicit authenticated action; manual/licensed tools are never auto-installed.
- Android emulator setup requires a Java runtime, significant disk space and hardware acceleration. It creates a local AVD but does not launch it or accept licenses on a device.
- The React build requires Node/npm. The static dashboard is the active UI when `frontend/dist` is absent.
- This tool does not replace a manual assessment by a qualified pentester.
