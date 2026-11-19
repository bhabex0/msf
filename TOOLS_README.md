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
| Lab | **Lab** | Burp/ZAP/mitmproxy listener commands, proxy CA steps, NSC warnings, gated patch/root workflows |
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
| `platform-tools` | Device | `adb`, `fastboot` | `adb devices`, `adb install app.apk`, `adb logcat` | Required for DAST and device work |
| `cmdline-tools` | Emulator | `sdkmanager`, `avdmanager` | Install SDK packages and create AVDs | Requires Java |
| `apkleaks` | Static | URIs, endpoints and secrets in APKs | `apkleaks -f app.apk -o report.txt` | Python package |
| `apkhunt` | Static | OWASP MASVS-oriented static workbench | Clone via manager, then start its documented web/Docker workflow | v2+ uses Docker Compose; manual startup |
| `semgrep` | Static | Rule-based SAST on decompiled Java/Kotlin | Run after `jadx`; see commands below | On Python 3.15 upstream wheels may be unavailable; platform reports `skipped` with the reason |
| `mobsf` | Static/Dynamic | Automated Android/iOS/Windows static and dynamic analysis | Run MobSF separately, set `APKPT_MOBSF_URL`, then use **Web UI** or scan hooks | Native deps vary. Prefer the official Docker image |
| `objection` | Runtime | Frida-powered runtime exploration | `objection -g com.example.app explore` | Repackaging/gadget changes signature |
| `frida-tools` | Runtime | Function tracing and instrumentation | `frida-ps -U`, `frida -U -f pkg -l hook.js` | Needs frida-server or Gadget |
| `rms` | Runtime | Frida-based runtime manipulation web UI | Install Node.js, start RMS, then open configured URL | Manual web workflow |
| `patch-apk` | Patching | Inject Frida Gadget into an APK | Use only on an authorized copy, then re-sign and test | Marked **invasive** |
| `trashdroid` | Dynamic | Automated Android DAST framework | Requires Python deps and an authorized device/emulator | Hook is gated by `APKPT_TOOLCHAIN_AUTO` |
| `mitmproxy` | Proxy | HTTP(S) interception and scripting | `mitmdump -l 0.0.0.0:8080 -s addon.py` | Install device CA only on authorized test devices |
| `zaproxy` | Proxy | Intercepting proxy and web/API scanner | Use official installer; configure proxy and scope | **Manual** tool |
| `burp` | Proxy | Licensed interception proxy | Use PortSwigger installer and accept license | **Manual** tool |
| `chromium` | Browser | Browser used for configured web UIs | Install via OS package manager; set `APKPT_CHROMIUM_CMD` if needed | **Manual** tool |
| `apatch` | Root | Root/system modification for owned lab devices | Perform manually only in an authorized lab | **Manual + invasive** |
| `recmanager` | Root | Magisk module/repository management | Install manually on authorized rooted device | **Manual + invasive** |

Installed tools do **not** show a redundant **Install** button. Missing installable tools show **Install**. Manual/unsupported tools show **Why** with the exact explanation.

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

# Static only
docker run -it --rm -p 8000:8000 \
  opensecurity/mobile-security-framework-mobsf:latest

# Static + Android dynamic analysis
docker run -it --rm -p 8000:8000 -p 1337:1337 \
  -e MOBSF_ANALYZER_IDENTIFIER=<adb-device-id> \
  opensecurity/mobile-security-framework-mobsf:latest
```

MobSF supports rooted Android VMs up to API 30 and, from v4.6.0, Frida Gadget mode for non-rooted/newer Android 5.0+ targets. For Docker with a host ADB server, restrict port `5037` to the Docker host.

Platform DAST wiring:

```powershell
$env:APKPT_DAST_SERIAL='emulator-5554'
$env:APKPT_DAST_FRIDA='1'
$env:APKPT_DAST_PROXY='burp'
python run.py --port 8000
```

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
pipx install drozer
adb install drozer-agent.apk
# Enable Embedded Server in the agent, then connect
drozer console connect

dz> run app.package.list -f example
dz> run app.package.attacksurface com.example.app
dz> run app.activity.start --component com.example.app .ExportedActivity
```

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
# Then set APKPT_MOBSF_URL to that MobSF instance for platform-linked review.
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
3. Start MobSF separately and set `APKPT_MOBSF_URL` / API key.
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

# MobSF integration
$env:APKPT_MOBSF_URL='http://127.0.0.1:8000'
$env:APKPT_MOBSF_API_KEY='<api-key>'

# DAST target
$env:APKPT_DAST_SERIAL='emulator-5554'
$env:APKPT_DAST_FRIDA='1'
$env:APKPT_DAST_PROXY='burp'

python run.py --port 8000
```

For a separate validation instance, use another port:

```bash
python run.py --port 8001
```

Notes:

- Python 3.15 is supported by the platform, but some upstream packages (`semgrep`, MobSF native dependencies) may lack compatible wheels. The platform reports these as **Unavailable** with **Why** and records install jobs as `skipped` rather than emitting long pip tracebacks.
- Use Python 3.10–3.14 or the official manual guide for those tools, then run **Verify**.
- `setx` affects new terminals only; in the current PowerShell session use `$env:` assignments.
- The static UI and `/tools/dashboard` are active; React components are maintained but unbuilt because Node/npm are unavailable in this environment.

---

## 10. Safety checklist

Before any action:

- [ ] Written authorization and scope are available.
- [ ] Target app/device/API is owned by the organization or explicitly authorized.
- [ ] Test accounts, test data and isolated environments are used.
- [ ] Manual/licensed/root/invasive tools are handled by an authorized operator.
- [ ] Proxy CAs and device changes are limited to lab devices and removed afterwards.
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
- Burp Suite: https://portswigger.net/burp
- Contrast IAST: https://docs.contrastsecurity.com/en/iast-technology.html
- Black Duck Seeker: https://www.blackduck.com/interactive-application-security-testing.html

---

**For authorized security testing only.**
