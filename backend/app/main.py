"""APK Pentest Platform - HTTP API."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Body, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, auth, config, pki_lab, storage, tool_manager
from .scanner.custom import add_custom_rule, delete_custom_rule, load_custom_rules
from .scanner.exports import cyclonedx_sbom, diff_scans, sarif_report
from .scanner.bluetooth import bluetooth_lab_status
from .scanner.lab import (
    apply_proxy,
    build_emulator_dast_plan,
    build_lab_plan,
    emulator_status,
    launch_emulator,
    open_mobsf_browser,
    run_patch_step,
    stop_emulator,
)
from .scanner.pipeline import run_scan
from .scanner.tools import probe_tools
from .scanner.toolchain import probe_toolchain

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("apkpt")

app = FastAPI(
    title="APK Pentest Platform",
    version=__version__,
    description="Upload an APK and run SAST, SCA, DAST, advanced analysis, policy gates and reporting.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class RuleDeleteRequest(BaseModel):
    rule_id: str


class ProxyRequest(BaseModel):
    host: str = ""
    port: int = 0
    device_serial: str | None = None
    clear: bool = False


class BrowserRequest(BaseModel):
    url: str | None = None
    scan_id: str | None = None


class PatchRequest(BaseModel):
    workflow: str
    scan_id: str


class ToolActionRequest(BaseModel):
    confirm: bool = True


class ShellRequest(BaseModel):
    command: str
    confirm: bool = True


class PkiCaGenerateRequest(BaseModel):
    common_name: str = "APKPT Lab CA"
    days: int | None = None
    force: bool = False
    confirm: bool = True


class PkiCaImportRequest(BaseModel):
    pem_text: str = ""
    path: str = ""
    force: bool = False
    confirm: bool = True


class PkiKeystoreGenerateRequest(BaseModel):
    alias: str = "apkpt-lab"
    password: str | None = None
    force: bool = False
    confirm: bool = True


class EmulatorActionRequest(BaseModel):
    confirm: bool = False


def _download(data: dict[str, Any], filename: str) -> JSONResponse:
    return JSONResponse(
        data,
        status_code=200,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _get_record(scan_id: str) -> Any:
    record = storage.load_record(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    return record


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "engines": {
            "sast": config.ENABLE_SAST,
            "sca": config.ENABLE_SCA,
            "dast": config.ENABLE_DAST,
            "sca_online": config.SCA_ONLINE_LOOKUP,
            "advanced": config.ENABLE_ADVANCED,
            "live_checks": config.ENABLE_LIVE_CHECKS,
            "medical": config.ENABLE_MEDICAL,
            "pki": True,
            "bluetooth": True,
            "toolchain": config.TOOLCHAIN_AUTO,
            "tool_manager": config.TOOL_MANAGER_ENABLED,
            "auth": config.AUTH_ENABLED,
        },
        "tools": probe_tools(),
        "toolchain": probe_toolchain(),
        "limits": {
            "max_upload_mb": config.MAX_UPLOAD_MB,
            "finding_limit": config.TOOL_FINDING_LIMIT,
            "finding_limit_unlimited": config.TOOL_FINDING_LIMIT == 0,
        },
    }


@app.get("/health", include_in_schema=False)
@app.get("/healthz", include_in_schema=False)
def health_alias() -> dict:
    """Conventional aliases for proxies and uptime checks."""
    return health()


@app.get("/api/config")
def get_config() -> dict:
    return {
        "dast": {
            "enabled": config.ENABLE_DAST,
            "device_serial": config.DAST_DEVICE_SERIAL or None,
            "frida": config.DAST_FRIDA,
            "proxy_configured": bool(config.DAST_PROXY),
        },
        "advanced": {
            "enabled": config.ENABLE_ADVANCED,
            "live_checks": config.ENABLE_LIVE_CHECKS,
            "custom_rules": len(load_custom_rules()),
        },
        "medical": {
            "enabled": config.ENABLE_MEDICAL,
            "domain": config.MEDICAL_DOMAIN,
            "phi_mode": config.MEDICAL_PHI_MODE,
            "policy_gap_limit": config.POLICY_MEDICAL_GAPS,
        },
        "policy": config.POLICY_THRESHOLDS,
        "limits": {
            "finding_limit": config.TOOL_FINDING_LIMIT,
            "finding_limit_unlimited": config.TOOL_FINDING_LIMIT == 0,
        },
        "pki": pki_lab.status(),
        "tools": probe_tools(),
        "toolchain": probe_toolchain(),
        "lab": emulator_status(),
        "tool_manager": {
            "enabled": config.TOOL_MANAGER_ENABLED,
            "root": str(config.TOOLS_ROOT),
            "android_sdk_root": str(config.ANDROID_SDK_ROOT),
            "emulator_avd": config.EMULATOR_AVD or "apkpt_test_avd",
        },
    }


@app.get("/api/tools/advanced")
def advanced_tools() -> list[dict]:
    return probe_toolchain()


@app.get("/api/tools/catalog")
def tools_catalog() -> dict:
    return tool_manager.catalog()


@app.get("/api/tools/installed")
def installed_tools(limit: int = 200) -> dict:
    return tool_manager.installed_summary(limit=min(max(limit, 1), 500))


@app.post("/api/tools/installed/sync")
def sync_installed_tools(
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "inventory sync was not confirmed")
    added = tool_manager.sync_installed_database()
    summary = tool_manager.installed_summary()
    summary["added"] = added
    auth.audit("tools.installed_sync", {"added": added}, actor)
    return summary


@app.post("/api/tools/web/{tool_id}")
def open_tool_web(
    tool_id: str,
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "web UI launch was not confirmed")
    result = tool_manager.open_web_ui(tool_id)
    auth.audit("tools.open_web", {"tool": tool_id, "status": result.get("status")}, actor)
    return result


@app.post("/api/tools/shell")
def tool_shell(payload: ShellRequest, actor: str = Depends(auth.require_auth)) -> dict:
    """Run an allowlisted mini-terminal command through the gated tool manager."""
    command = payload.command.strip()
    if not payload.confirm:
        raise HTTPException(400, "shell command was not confirmed")
    if not command:
        raise HTTPException(400, "shell command is empty")
    if len(command) > 500:
        raise HTTPException(400, "shell command is too long")

    plan = tool_manager.parse_shell_command(command)
    kind = plan["kind"]
    auth.audit("tools.shell", {"command": command[:200], "kind": kind}, actor)

    if kind == "error":
        raise HTTPException(400, plan["detail"])
    if kind == "clear":
        return {"status": "ok", "level": "dim", "clear": True, "output": plan["output"]}
    if kind == "message":
        return {"status": "ok", "level": "info", "output": plan["output"]}
    if kind == "catalog":
        catalog = tool_manager.catalog()
        output = "\n".join(
            f"{tool['id']:<20} {tool['name']:<28} {'manual' if tool['manual'] else tool['method']}"
            for tool in catalog["tools"]
        )
        return {"status": "ok", "level": "info", "output": output}
    if kind == "status":
        catalog = tool_manager.catalog()
        inventory = tool_manager.installed_summary()
        mobsf = next((t for t in catalog["tools"] if t["id"] == "mobsf"), {})
        output = "\n".join([
            f"tool manager: {'enabled' if catalog['enabled'] else 'disabled'}",
            f"platform: {catalog['platform']} {catalog['os']['release']} / {catalog['os']['machine']}",
            f"catalog: {len(catalog['tools'])} tools · installed records: {inventory['count']}",
            f"policy: {len(catalog['allowed_hosts'])} HTTPS hosts · SHA-256 verified · "
            f"502 retries {catalog['source_policy']['transient_502_retries']}",
            f"MobSF web: {mobsf.get('web_url') or 'not configured'}",
            catalog["disclaimer"],
        ])
        return {"status": "ok", "level": "info", "output": output}
    if kind == "jobs":
        jobs = tool_manager.MANAGER.list(limit=12)
        output = "\n".join(
            f"{job.job_id[:12]}  {job.status:<9}  {job.tool_id}/{job.action}"
            for job in jobs
        ) or "No tool jobs yet."
        return {"status": "ok", "level": "info", "output": output}
    if kind == "sync":
        added = tool_manager.sync_installed_database()
        summary = tool_manager.installed_summary()
        output = f"inventory synced: {added} new record(s); {summary['count']} total."
        return {"status": "ok", "level": "ok", "output": output}
    if kind == "web":
        result = tool_manager.open_web_ui(plan["tool_id"])
        output = f"{plan['tool_id']}: {result.get('status')} {result.get('detail') or result.get('url') or ''}".strip()
        level = "low" if result.get("status") == "skipped" else "ok" if result.get("status") in ("ok", "opened") else "high"
        return {"status": result.get("status", "ok"), "level": level, "output": output}
    if kind == "job":
        try:
            job = tool_manager.MANAGER.submit(plan["tool_id"], plan["action"], actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        auth.audit("tools.shell_job", {
            "command": command[:200], "job_id": job.job_id, "status": job.status,
        }, actor)
        level = "low" if job.status == "skipped" else "work" if job.status in ("queued", "running") else "ok"
        return {
            "status": job.status,
            "level": level,
            "output": f"job {job.job_id} submitted as {job.status}. {job.detail}".strip(),
            "job_id": job.job_id,
            "job": job.to_dict(),
        }
    raise HTTPException(400, "unsupported shell command")


@app.get("/api/tools/jobs")
def list_tool_jobs(limit: int = 50) -> list[dict]:
    return [job.to_dict() for job in tool_manager.MANAGER.list(limit=min(max(limit, 1), 200))]


@app.get("/api/tools/jobs/{job_id}")
def get_tool_job(job_id: str) -> dict:
    job = tool_manager.MANAGER.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job.to_dict()


@app.get("/api/tools/jobs/{job_id}/events")
async def tool_job_events(job_id: str) -> StreamingResponse:
    async def stream():
        last = ""
        for _ in range(900):
            job = tool_manager.MANAGER.get(job_id)
            if job is None:
                yield 'event: error\ndata: {"detail":"job not found"}\n\n'
                return
            payload = json.dumps(job.to_dict())
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            if job.status in ("completed", "failed", "skipped"):
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/tools/install-all")
def install_all_tools(
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "installation was not confirmed")
    job = tool_manager.MANAGER.submit("all", "install_all", actor)
    auth.audit("tools.install_all", {"job_id": job.job_id, "status": job.status}, actor)
    return job.to_dict()


@app.post("/api/tools/update-all")
def update_all_tools(
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "update was not confirmed")
    job = tool_manager.MANAGER.submit("all", "update_all", actor)
    auth.audit("tools.update_all", {"job_id": job.job_id, "status": job.status}, actor)
    return job.to_dict()


@app.post("/api/tools/emulator/install")
def install_emulator_tools(
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "emulator installation was not confirmed")
    job = tool_manager.MANAGER.submit("emulator", "install", actor)
    auth.audit("tools.emulator_install", {"job_id": job.job_id, "status": job.status}, actor)
    return job.to_dict()


@app.post("/api/tools/{tool_id}/{action}")
def tool_action(
    tool_id: str,
    action: str,
    payload: ToolActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    if payload is not None and not payload.confirm:
        raise HTTPException(400, "action was not confirmed")
    try:
        job = tool_manager.MANAGER.submit(tool_id, action, actor)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    auth.audit("tools.action", {"tool": tool_id, "action": action, "job_id": job.job_id}, actor)
    return job.to_dict()


@app.get("/api/lab/status")
def lab_status() -> dict:
    return emulator_status()


@app.get("/api/lab/emulator")
def emulator_dast_status() -> dict:
    """Read-only emulator/DAST readiness. Never launches or modifies a device."""
    return emulator_status()


@app.get("/api/lab/emulator/plan")
def emulator_dast_plan() -> dict:
    """Non-executing guided plan for emulator-backed DAST."""
    return {
        "authorization": "For authorized security testing only.",
        "steps": build_emulator_dast_plan(),
    }


@app.post("/api/lab/emulator/launch")
def emulator_launch(
    payload: EmulatorActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    confirm = bool(payload and payload.confirm)
    result = launch_emulator(confirm)
    auth.audit("lab.emulator_launch", {"status": result.get("status"), "performed": result.get("performed")}, actor)
    return result


@app.post("/api/lab/emulator/stop")
def emulator_stop(
    payload: EmulatorActionRequest | None = Body(None),
    actor: str = Depends(auth.require_auth),
) -> dict:
    confirm = bool(payload and payload.confirm)
    result = stop_emulator(confirm)
    auth.audit("lab.emulator_stop", {"status": result.get("status"), "performed": result.get("performed")}, actor)
    return result


@app.get("/api/bluetooth/status")
def bluetooth_status() -> dict:
    """Read-only local Bluetooth tooling status. Never scans or pairs."""
    return bluetooth_lab_status()


@app.post("/api/lab/proxy")
def lab_proxy(payload: ProxyRequest, actor: str = Depends(auth.require_auth)) -> dict:
    result = apply_proxy(
        payload.host or config.PROXY_HOST,
        payload.port or config.PROXY_PORT,
        payload.device_serial,
        payload.clear,
    )
    auth.audit("lab.proxy", {"clear": payload.clear, "result": result.get("status")}, actor)
    return result


@app.post("/api/lab/open-mobsf")
def lab_open_mobsf(payload: BrowserRequest, actor: str = Depends(auth.require_auth)) -> dict:
    if payload.scan_id and storage.load_record(payload.scan_id) is None:
        raise HTTPException(404, "scan not found")
    result = tool_manager.with_install_state(open_mobsf_browser(payload.url, payload.scan_id), "mobsf")
    auth.audit("lab.open_mobsf", {"status": result.get("status")}, actor)
    return result


@app.post("/api/lab/patch")
def lab_patch(payload: PatchRequest, actor: str = Depends(auth.require_auth)) -> dict:
    record = _get_record(payload.scan_id)
    result = run_patch_step(
        payload.workflow,
        storage.paths(payload.scan_id)["apk"],
        storage.paths(payload.scan_id)["work"],
        record.manifest.package,
    )
    auth.audit("lab.patch", {"workflow": payload.workflow, "status": result.get("status")}, actor)
    return result


@app.get("/api/pki/status")
def pki_status() -> dict:
    """Read-only local PKI lab status. Never pushes material to a device."""
    return pki_lab.status()


@app.post("/api/pki/ca/generate")
def pki_generate_ca(
    payload: PkiCaGenerateRequest,
    actor: str = Depends(auth.require_auth),
) -> dict:
    if not payload.confirm:
        raise HTTPException(400, "CA generation was not confirmed")
    result = pki_lab.generate_ca(payload.common_name, payload.days, payload.force)
    auth.audit("pki.ca.generate", {
        "common_name": payload.common_name, "force": payload.force, "status": result.get("status"),
    }, actor)
    return result


@app.post("/api/pki/ca/import")
def pki_import_ca(
    payload: PkiCaImportRequest,
    actor: str = Depends(auth.require_auth),
) -> dict:
    if not payload.confirm:
        raise HTTPException(400, "CA import was not confirmed")
    result = pki_lab.import_ca(payload.pem_text, payload.path, payload.force)
    auth.audit("pki.ca.import", {
        "source": "pem_text" if payload.pem_text else payload.path,
        "force": payload.force, "status": result.get("status"),
    }, actor)
    return result


@app.post("/api/pki/keystore/generate")
def pki_generate_keystore(
    payload: PkiKeystoreGenerateRequest,
    actor: str = Depends(auth.require_auth),
) -> dict:
    if not payload.confirm:
        raise HTTPException(400, "keystore generation was not confirmed")
    result = pki_lab.generate_keystore(payload.alias, payload.password, payload.force)
    auth.audit("pki.keystore.generate", {
        "alias": payload.alias, "force": payload.force, "status": result.get("status"),
    }, actor)
    return result


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict:
    user = auth.authenticate(payload.username, payload.password)
    if not user:
        raise HTTPException(401, "invalid username or password")
    token = auth.create_token(user)
    auth.audit("login", {"user": user}, user)
    return {"access_token": token, "token_type": "bearer", "user": user}


@app.get("/api/rules")
def list_rules() -> list[dict]:
    return load_custom_rules()


@app.post("/api/rules")
def create_rule(rule: dict[str, Any] = Body(...), actor: str = Depends(auth.require_auth)) -> dict:
    try:
        rules = add_custom_rule(rule)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    auth.audit("rule.create", rule.get("id", ""), actor)
    return {"created": True, "id": rule.get("id"), "total": len(rules)}


@app.delete("/api/rules")
def remove_rule(payload: RuleDeleteRequest, actor: str = Depends(auth.require_auth)) -> dict:
    rules = delete_custom_rule(payload.rule_id)
    auth.audit("rule.delete", payload.rule_id, actor)
    return {"deleted": True, "rule_id": payload.rule_id, "total": len(rules)}


@app.post("/api/scans", status_code=202)
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    actor: str = Depends(auth.require_auth),
) -> dict:
    filename = Path(file.filename or "upload.apk").name
    if not filename.lower().endswith(tuple(config.ALLOWED_EXTENSIONS)):
        raise HTTPException(400, "Only .apk files are accepted")
    if file.size is not None and file.size > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File exceeds the {config.MAX_UPLOAD_MB} MB limit")

    scan_id = storage.new_scan_id()
    record = storage.ensure_scan(scan_id, filename)
    target = storage.paths(scan_id)["apk"]
    written = 0
    try:
        with open(target, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File exceeds the {config.MAX_UPLOAD_MB} MB limit")
                out.write(chunk)
    except Exception:
        storage.delete_scan(scan_id)
        raise
    finally:
        await file.close()

    record.size_bytes = written
    storage.save_record(record)
    auth.audit("scan.upload", {"scan_id": scan_id, "filename": filename, "bytes": written}, actor)
    background_tasks.add_task(run_scan, scan_id)
    log.info("accepted scan %s (%s bytes)", scan_id, written)
    return {"scan_id": scan_id, "status": "queued", "poll_url": f"/api/scans/{scan_id}"}


@app.get("/api/scans")
def list_scans() -> list[dict]:
    records = storage.list_records()
    return [
        {
            "scan_id": r.scan_id,
            "filename": r.filename,
            "uploaded_at": r.uploaded_at,
            "status": r.status,
            "stage": r.stage,
            "progress": r.progress,
            "package": r.manifest.package,
            "risk_score": r.summary.risk_score,
            "risk_label": r.summary.risk_label,
            "total_findings": r.summary.total,
            "sha256": r.sha256,
            "policy_status": r.policy.get("status") if isinstance(r.policy, dict) else None,
        }
        for r in records
    ]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    return _get_record(scan_id).model_dump()


@app.get("/api/scans/{scan_id}/medical")
def get_medical(scan_id: str) -> dict:
    return _get_record(scan_id).medical


@app.get("/api/scans/{scan_id}/pki")
def get_pki(scan_id: str) -> dict:
    return _get_record(scan_id).pki


@app.get("/api/scans/{scan_id}/bluetooth")
def get_bluetooth(scan_id: str) -> dict:
    return _get_record(scan_id).bluetooth


@app.get("/api/scans/{scan_id}/toolchain")
def get_toolchain(scan_id: str) -> list[dict]:
    return _get_record(scan_id).toolchain


@app.get("/api/scans/{scan_id}/lab")
def get_lab(scan_id: str) -> dict:
    record = _get_record(scan_id)
    if record.emulator:
        return record.emulator
    paths = storage.paths(scan_id)
    return build_lab_plan(paths["apk"], paths["work"], record.manifest.package)


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    """Server-sent events for live progress (fallback for browsers without SSE)."""
    async def stream():
        last = ""
        for _ in range(900):
            record = storage.load_record(scan_id)
            if record is None:
                yield 'event: error\ndata: {"detail":"scan not found"}\n\n'
                return
            payload = json.dumps({
                "scan_id": scan_id,
                "status": record.status,
                "stage": record.stage,
                "progress": record.progress,
                "summary": record.summary.model_dump(),
                "policy": record.policy,
            })
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            if record.status in ("completed", "failed"):
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def get_html_report(scan_id: str) -> HTMLResponse:
    record = _get_record(scan_id)
    path = storage.paths(scan_id)["html"]
    if not path.exists():
        raise HTTPException(409, f"report not ready (scan status: {record.status})")
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/api/scans/{scan_id}/report.json")
def get_json_report(scan_id: str) -> JSONResponse:
    return JSONResponse(_get_record(scan_id).model_dump(), status_code=200)


@app.get("/api/scans/{scan_id}/export/sbom.json")
def get_sbom(scan_id: str) -> JSONResponse:
    return _download(cyclonedx_sbom(_get_record(scan_id)), f"sbom-{scan_id}.cdx.json")


@app.get("/api/scans/{scan_id}/export/sarif.json")
def get_sarif(scan_id: str) -> JSONResponse:
    return _download(sarif_report(_get_record(scan_id)), f"report-{scan_id}.sarif")


@app.get("/api/scans/{scan_id}/diff")
def diff_scan(scan_id: str, against: str) -> dict:
    current = _get_record(scan_id)
    previous = _get_record(against)
    return diff_scans(current, previous)


@app.post("/api/scans/{scan_id}/cleanup")
def cleanup_scan(scan_id: str, actor: str = Depends(auth.require_auth)) -> dict:
    _get_record(scan_id)
    work = storage.paths(scan_id)["work"]
    import shutil

    removed = work.exists()
    shutil.rmtree(work, ignore_errors=True)
    auth.audit("scan.cleanup", scan_id, actor)
    return {"cleaned": removed, "scan_id": scan_id}


@app.delete("/api/scans/{scan_id}")
def remove_scan(scan_id: str, actor: str = Depends(auth.require_auth)) -> dict:
    if not storage.delete_scan(scan_id):
        raise HTTPException(404, "scan not found")
    auth.audit("scan.delete", scan_id, actor)
    return {"deleted": True, "scan_id": scan_id}


@app.get("/tools/dashboard", response_class=HTMLResponse)
def installed_dashboard() -> HTMLResponse:
    return HTMLResponse(tool_manager.installed_dashboard_html())


# The zero-dependency static dashboard is the active UI by default. The React
# build is maintained and built, and is served only with APKPT_WEB_UI=react.
# Both are mounted after the API routes so /api/* wins.
_project_root = Path(__file__).resolve().parent.parent.parent
_dist = _project_root / "frontend" / "dist"
_static = _project_root / "frontend" / "static"
_web = _dist if config.WEB_UI == "react" and _dist.exists() else _static
if _web.exists():
    app.mount("/", StaticFiles(directory=str(_web), html=True), name="frontend")
    log.info("serving frontend from %s", _web)
