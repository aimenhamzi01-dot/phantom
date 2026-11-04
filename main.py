"""
PHANTOM — FastAPI Backend Server
Main entry point — orchestrates all engines
"""
import asyncio
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

import colorlog
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from config import config
from models.schemas import ScanRequest, ScanResult, HealthResponse, TargetType
from engines.recon import ReconEngine
from engines.ai_engine import AIEngine
from engines.report_engine import ReportEngine
from security import require_api_token, validate_target, verify_manifest

# ─── LOGGING SETUP ───────────────────────────────────────────────────────────
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(name)s] %(levelname)s%(reset)s — %(message)s",
    datefmt="%H:%M:%S",
    log_colors={
        "DEBUG": "cyan", "INFO": "green",
        "WARNING": "yellow", "ERROR": "red", "CRITICAL": "bold_red"
    }
))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("phantom.main")

# ─── IN-MEMORY SCAN STORE ────────────────────────────────────────────────────
# In production: replace with Redis or PostgreSQL
scan_store: dict[str, dict] = {}

# ─── APP INIT ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PHANTOM — AI Bug Bounty Hunter",
    description="Elite AI-powered security analysis engine for authorized bug bounty hunting",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── ENGINE INSTANCES ────────────────────────────────────────────────────────
recon_engine = ReconEngine()
ai_engine = AIEngine()
report_engine = ReportEngine()


# ─── SCAN ORCHESTRATOR ───────────────────────────────────────────────────────
async def run_scan(scan_id: str, request: ScanRequest):
    """
    Full scan pipeline:
    1. Recon (real data gathering)
    2. AI Analysis (Claude with full context)
    3. Report Assembly
    """
    try:
        scan_store[scan_id]["status"] = "running"
        scan_store[scan_id]["phase"] = "recon"
        scan_store[scan_id]["message"] = "Gathering intelligence..."
        scan_store[scan_id]["progress"] = 10

        logger.info(f"[{scan_id}] Starting recon for: {request.target}")

        # ── Phase 1: Reconnaissance ──────────────────────────
        recon = await recon_engine.run(request.target, request.target_type.value)

        scan_store[scan_id]["phase"] = "ai_analysis"
        scan_store[scan_id]["message"] = "AI engine analyzing target..."
        scan_store[scan_id]["progress"] = 40

        logger.info(f"[{scan_id}] Recon complete. IP: {recon.ip}, Server: {recon.server}")
        logger.info(f"[{scan_id}] Technologies: {recon.technologies}")

        # ── Phase 2: AI Analysis ─────────────────────────────
        ai_result = await ai_engine.analyze(
            target=request.target,
            target_type=request.target_type.value,
            scope=request.scope,
            recon=recon,
        )

        scan_store[scan_id]["phase"] = "report"
        scan_store[scan_id]["message"] = "Assembling report..."
        scan_store[scan_id]["progress"] = 85

        # ── Phase 3: Report Assembly ─────────────────────────
        result = report_engine.build(
            target=request.target,
            target_type=request.target_type.value,
            recon=recon,
            ai_result=ai_result,
        )

        scan_store[scan_id]["status"] = "complete"
        scan_store[scan_id]["phase"] = "complete"
        scan_store[scan_id]["message"] = f"Found {len(result.vulnerabilities)} vulnerabilities"
        scan_store[scan_id]["progress"] = 100
        scan_store[scan_id]["result"] = result.model_dump()

        logger.info(
            f"[{scan_id}] Scan complete: {len(result.vulnerabilities)} vulns | "
            f"Risk: {result.risk_rating} | "
            f"Bounty: ${result.estimated_bounty.most_likely:,}"
        )

    except Exception as e:
        logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
        scan_store[scan_id]["status"] = "error"
        scan_store[scan_id]["message"] = str(e)
        scan_store[scan_id]["progress"] = 0


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {"phantom": "online", "version": "1.0.0"}


@app.get("/health", response_model=HealthResponse)
async def health():
    """Check system status and configured APIs"""
    return HealthResponse(
        status="online",
        version="1.0.0",
        ai_engine=config.AI_MODEL,
        apis_configured={
            "meta_model_api": bool(
                os.getenv("MODEL_API_KEY") or os.getenv("META_API_KEY") or os.getenv("META_MODEL_API_KEY")
            ),
            "shodan": bool(config.SHODAN_API_KEY),
            "virustotal": bool(config.VIRUSTOTAL_API_KEY),
        }
    )


@app.post("/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, x_phantom_api_token: Optional[str] = Header(default=None)):
    """
    Start a new async scan.
    Returns scan_id immediately — poll /scan/{id}/status for progress.
    """
    try:
        require_api_token(x_phantom_api_token)
    except PermissionError as e:
        raise HTTPException(status_code=401, detail=str(e))

    if request.manifest is not None:
        try:
            target, target_type, scope = verify_manifest(request.manifest)
        except ValueError as e:
            raise HTTPException(status_code=403, detail=str(e))
        request.target = target
        request.target_type = TargetType(target_type)
        request.scope = scope
    elif not config.ALLOW_DIRECT_SCANS:
        raise HTTPException(status_code=403, detail="Direct scans are disabled; submit a signed Mizan manifest.")
    else:
        try:
            request.target = validate_target(request.target or "", request.target_type.value)
        except ValueError as e:
            raise HTTPException(status_code=403, detail=str(e))

    # Validate API key on first request
    try:
        config.validate()
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))

    scan_id = str(uuid.uuid4())[:8].upper()

    scan_store[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "target_type": request.target_type.value,
        "status": "queued",
        "phase": "queued",
        "message": "Scan queued...",
        "progress": 0,
        "result": None,
        "started_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(run_scan, scan_id, request)

    logger.info(f"Scan {scan_id} started for: {request.target}")
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, x_phantom_api_token: Optional[str] = Header(default=None)):
    """Poll scan progress"""
    try:
        require_api_token(x_phantom_api_token)
    except PermissionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    store = scan_store[scan_id]
    return {
        "scan_id": scan_id,
        "status": store["status"],
        "phase": store["phase"],
        "message": store["message"],
        "progress": store["progress"],
    }


@app.get("/scan/{scan_id}/result")
async def get_scan_result(scan_id: str, x_phantom_api_token: Optional[str] = Header(default=None)):
    """Get full scan result when complete"""
    try:
        require_api_token(x_phantom_api_token)
    except PermissionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    store = scan_store[scan_id]
    if store["status"] != "complete":
        raise HTTPException(
            status_code=425,
            detail=f"Scan not complete yet. Status: {store['status']}"
        )

    return store["result"]


@app.get("/scan/{scan_id}/report", response_class=PlainTextResponse)
async def get_text_report(scan_id: str):
    """Get plain-text report for export"""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    store = scan_store[scan_id]
    if store["status"] != "complete":
        raise HTTPException(status_code=425, detail="Scan not complete")

    result = ScanResult(**store["result"])
    return report_engine.to_text_report(result)


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Clean up scan data"""
    if scan_id in scan_store:
        del scan_store[scan_id]
    return {"deleted": scan_id}


@app.get("/scans")
async def list_scans():
    """List all scans (without full results)"""
    return [
        {
            "scan_id": k,
            "target": v["target"],
            "status": v["status"],
            "risk_rating": v.get("result", {}).get("risk_rating") if v.get("result") else None,
            "started_at": v.get("started_at"),
        }
        for k, v in scan_store.items()
    ]


# ─── STARTUP ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    logger.info("=" * 50)
    logger.info("PHANTOM AI Bug Bounty Hunter — ONLINE")
    logger.info(f"AI Model: {config.AI_MODEL} (Meta Model API)")
    logger.info(f"Shodan: {'✓' if config.SHODAN_API_KEY else '✗ (optional)'}")
    logger.info(f"VirusTotal: {'✓' if config.VIRUSTOTAL_API_KEY else '✗ (optional)'}")
    logger.info(f"Docs: http://{config.HOST}:{config.PORT}/docs")
    logger.info("=" * 50)


@app.on_event("shutdown")
async def shutdown():
    await recon_engine.close()
    logger.info("PHANTOM — Shutdown complete")


# ─── RUN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
        log_level="info",
    )
