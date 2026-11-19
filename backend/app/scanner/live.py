"""Optional live checks against endpoints/references found in the APK.

Live checks are disabled by default because they make outbound requests. When
enabled, only public hosts are contacted, redirects are not followed and every
request has a short timeout. Nothing is written to third-party services.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from .. import config
from .rules import finding

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
FIREBASE_RE = re.compile(r"https://([a-z0-9-]+)\.firebaseio\.com/?", re.I)
S3_VIRTUAL_RE = re.compile(r"https://([a-z0-9][a-z0-9.-]{1,60})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/?", re.I)
S3_PATH_RE = re.compile(r"https://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,60})/?", re.I)


def _public_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if not host or host in ("localhost", "127.0.0.1", "::1") or host.endswith((".local", ".internal")):
        return False
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_global)
    except ValueError:
        pass
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(config.LIVE_TIMEOUT, 3))
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(old)
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return False
        except Exception:
            return False
    return bool(infos)


def _extract_urls(strings: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in strings[:200_000]:
        for match in URL_RE.findall(s):
            url = match.rstrip(".,);]}")
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            if len(out) >= config.LIVE_MAX_ENDPOINTS * 4:
                return out
    return out


def _virustotal_check(sha256: str | None, client: httpx.Client) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not config.VIRUSTOTAL_API_KEY or not sha256:
        return ({"name": "virustotal", "status": "skipped", "detail": "API key or SHA-256 not available"}, [])
    try:
        r = client.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
        )
        if r.status_code == 404:
            return ({"name": "virustotal", "status": "not_applicable", "detail": "hash not known to VirusTotal"}, [])
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        detail = f"VirusTotal detections: {stats}"
        check = {"name": "virustotal", "status": "passed" if malicious == 0 else "failed", "detail": detail}
        if malicious:
            return (check, [finding(
                "LIVE-VIRUSTOTAL-MALICIOUS",
                "VirusTotal reports malicious detections for this APK hash",
                "high",
                category="LIVE",
                description=f"VirusTotal reported {malicious} malicious engine detections for SHA-256 {sha256}.",
                evidence=str(stats),
                remediation="Treat the sample as potentially malicious; perform sandbox analysis and verify provenance.",
                confidence="medium",
                references=[f"https://www.virustotal.com/gui/file/{sha256}"],
            )])
        return (check, [])
    except Exception as exc:
        return ({"name": "virustotal", "status": "error", "detail": str(exc)[:300]}, [])


def run_live_checks(
    strings: list[str],
    sha256: str | None = None,
    *,
    enabled: bool | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (checks, findings)."""
    use_live = config.ENABLE_LIVE_CHECKS if enabled is None else enabled
    if not use_live:
        return ([{
            "name": "live_checks",
            "status": "skipped",
            "detail": "Set APKPT_LIVE_CHECKS=1 to enable outbound endpoint checks.",
            "evidence": "",
        }], [])

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    urls = _extract_urls(strings)
    timeout = httpx.Timeout(config.LIVE_TIMEOUT)
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False, headers={"User-Agent": "apkpt-live/1.0"}) as client:
        check, f = _virustotal_check(sha256, client)
        checks.append(check)
        findings.extend(f)

        firebase_projects: list[str] = []
        s3_buckets: list[str] = []
        for url in urls:
            for m in FIREBASE_RE.finditer(url):
                project = m.group(1).lower()
                if project not in firebase_projects:
                    firebase_projects.append(project)
            for rx in (S3_VIRTUAL_RE, S3_PATH_RE):
                for m in rx.finditer(url):
                    bucket = m.group(1).lower()
                    if bucket not in s3_buckets:
                        s3_buckets.append(bucket)

        for project in firebase_projects[:3]:
            target = f"https://{project}.firebaseio.com/.json"
            if not _public_host(f"{project}.firebaseio.com"):
                checks.append({"name": f"firebase:{project}", "status": "skipped", "detail": "host is not public or DNS failed", "evidence": ""})
                continue
            try:
                r = client.get(target)
                body = r.text[:1000]
                denied = "permission_denied" in body.lower()
                status = "failed" if r.status_code == 200 and not denied else "passed"
                checks.append({"name": f"firebase:{project}", "status": status, "detail": f"HTTP {r.status_code}", "evidence": body[:300]})
                if status == "failed":
                    findings.append(finding(
                        "LIVE-FIREBASE-OPEN",
                        "Firebase Realtime Database appears publicly readable",
                        "critical",
                        category="LIVE",
                        description=f"An unauthenticated read of {target} returned data. This may expose user records and secrets.",
                        evidence=body[:400],
                        remediation="Set Firebase security rules to deny unauthenticated reads/writes and rotate exposed data.",
                        location=target,
                        cwe="CWE-306",
                        masvs="MASVS-NETWORK-2",
                        confidence="medium",
                    ))
            except Exception as exc:
                checks.append({"name": f"firebase:{project}", "status": "error", "detail": str(exc)[:300], "evidence": ""})

        for bucket in s3_buckets[:3]:
            target = f"https://{bucket}.s3.amazonaws.com/"
            if not _public_host(f"{bucket}.s3.amazonaws.com"):
                checks.append({"name": f"s3:{bucket}", "status": "skipped", "detail": "host is not public or DNS failed", "evidence": ""})
                continue
            try:
                r = client.get(target)
                body = r.text[:1000]
                listed = r.status_code == 200 and "ListBucketResult" in body
                checks.append({"name": f"s3:{bucket}", "status": "failed" if listed else "passed", "detail": f"HTTP {r.status_code}", "evidence": body[:300]})
                if listed:
                    findings.append(finding(
                        "LIVE-S3-OPEN",
                        "S3 bucket appears publicly listable",
                        "critical",
                        category="LIVE",
                        description=f"An unauthenticated request to {target} returned an object listing.",
                        evidence=body[:400],
                        remediation="Block public access, review IAM/bucket policies and rotate any exposed credentials/data.",
                        location=target,
                        cwe="CWE-306",
                        masvs="MASVS-NETWORK-2",
                        confidence="medium",
                    ))
            except Exception as exc:
                checks.append({"name": f"s3:{bucket}", "status": "error", "detail": str(exc)[:300], "evidence": ""})

        probed = 0
        for url in urls:
            if probed >= config.LIVE_MAX_ENDPOINTS:
                break
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            if not _public_host(parsed.hostname):
                continue
            probed += 1
            try:
                r = client.get(url)
                checks.append({
                    "name": f"endpoint:{parsed.hostname}",
                    "status": "passed" if r.status_code < 400 else "info",
                    "detail": f"{parsed.scheme.upper()} {r.status_code} for {parsed.path or '/'}",
                    "evidence": "",
                })
                if parsed.scheme == "http" and r.status_code < 400:
                    findings.append(finding(
                        "LIVE-HTTP-REACHABLE",
                        "Plaintext HTTP endpoint is reachable",
                        "medium",
                        category="LIVE",
                        description=f"The app references {url}, which responded over unencrypted HTTP.",
                        evidence=f"HTTP {r.status_code}",
                        remediation="Replace the endpoint with HTTPS and disable cleartext traffic.",
                        location=url,
                        cwe="CWE-319",
                        masvs="MASVS-NETWORK-1",
                        confidence="high",
                    ))
            except Exception as exc:
                checks.append({"name": f"endpoint:{parsed.hostname}", "status": "error", "detail": str(exc)[:300], "evidence": ""})

        if not checks:
            checks.append({"name": "live_checks", "status": "not_applicable", "detail": "No public endpoints found in APK strings.", "evidence": ""})
    return checks, findings
