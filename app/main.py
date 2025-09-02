# app/main.py
import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .models import ScanRequest, ScanResponse, ScanStatus
from .report_generator import ReportGenerator
from .scanner import SecurityScanner

app = FastAPI(title="SecureScan Pro", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for jobs (use Redis/DB in production)
jobs_storage: Dict[str, Dict[str, Any]] = {}
reports_dir = "reports"
os.makedirs(reports_dir, exist_ok=True)

scanner = SecurityScanner()
report_generator = ReportGenerator()

@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")

@app.get("/api/")
async def api_root():
    return {"message": "SecureScan Pro API", "version": "1.0.0"}

@app.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan"""
    job_id = str(uuid.uuid4())
    
    # Initialize job
    jobs_storage[job_id] = {
        "id": job_id,
        "status": ScanStatus.QUEUED,
        "target": scan_request.target,
        "scan_type": scan_request.scan_type,
        "components": scan_request.components,
        "created_at": datetime.utcnow().isoformat(),
        "progress": 0,
        "results": None,
        "error": None
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan, job_id, scan_request)
    
    return ScanResponse(
        job_id=job_id,
        status=ScanStatus.QUEUED,
        message="Scan queued successfully"
    )

@app.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Get scan status and results"""
    if job_id not in jobs_storage:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = jobs_storage[job_id]
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job["progress"],
        "target": job["target"],
        "created_at": job["created_at"],
        "results": job.get("results"),
        "error": job.get("error")
    }

@app.get("/report/{job_id}.{format}")
async def get_report(job_id: str, format: str):
    """Download report in PDF or JSON format"""
    if job_id not in jobs_storage:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = jobs_storage[job_id]
    if job["status"] != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    if format.lower() == "json":
        report_path = f"{reports_dir}/{job_id}.json"
        if not os.path.exists(report_path):
            # Generate JSON report
            with open(report_path, 'w') as f:
                json.dump(job["results"], f, indent=2)
        return FileResponse(report_path, filename=f"scan_report_{job_id}.json")
    
    elif format.lower() == "pdf":
        report_path = f"{reports_dir}/{job_id}.pdf"
        if not os.path.exists(report_path):
            # Generate PDF report
            await report_generator.generate_pdf_report(job["results"], report_path)
        return FileResponse(report_path, filename=f"scan_report_{job_id}.pdf")
    
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'json' or 'pdf'")

async def run_scan(job_id: str, scan_request: ScanRequest):
    """Execute the security scan"""
    try:
        jobs_storage[job_id]["status"] = ScanStatus.RUNNING
        jobs_storage[job_id]["progress"] = 10
        
        # Perform the scan
        results = await scanner.scan(
            target=scan_request.target,
            scan_type=scan_request.scan_type,
            components=scan_request.components,
            progress_callback=lambda p: update_progress(job_id, p)
        )
        
        jobs_storage[job_id]["results"] = results
        jobs_storage[job_id]["status"] = ScanStatus.COMPLETED
        jobs_storage[job_id]["progress"] = 100
        jobs_storage[job_id]["completed_at"] = datetime.utcnow().isoformat()
        
    except Exception as e:
        jobs_storage[job_id]["status"] = ScanStatus.FAILED
        jobs_storage[job_id]["error"] = str(e)

def update_progress(job_id: str, progress: int):
    """Update job progress"""
    if job_id in jobs_storage:
        jobs_storage[job_id]["progress"] = progress

if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    # Don't interfere with API routes
    if full_path.startswith(("api/", "docs", "redoc", "scan", "report")):
        raise HTTPException(status_code=404, detail="Not found")
    # For all other paths, serve the React app
    return FileResponse("static/index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
