from fastapi import APIRouter, HTTPException
from db.supabase import get_client
from pydantic import BaseModel
from datetime import datetime, timezone

router = APIRouter(prefix="/security", tags=["Security"])

class ThreatEvent(BaseModel):
    title:          str
    description:    str
    severity:       str
    category:       str
    source_ip:      str | None = None
    source_country: str | None = None

class IOC(BaseModel):
    type:        str
    value:       str
    threat_name: str | None = None
    severity:    str = "medium"
    source:      str | None = None

class Vulnerability(BaseModel):
    title:       str
    cve_id:      str | None = None
    cvss_score:  float | None = None
    severity:    str
    affected:    str
    description: str
    status:      str = "open"

@router.get("/threats")
async def list_threats(severity: str = None, category: str = None, limit: int = 25):
    sb = get_client()
    query = sb.table("threat_events").select("*").order("created_at", desc=True)
    if severity:
        query = query.eq("severity", severity)
    if category:
        query = query.eq("category", category)
    result = query.limit(limit).execute()
    return {"threats": result.data or []}

@router.post("/threats")
async def create_threat(threat: ThreatEvent):
    sb = get_client()
    result = sb.table("threat_events").insert({
        **threat.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    return {"created": result.data[0] if result.data else {}}

@router.get("/iocs")
async def list_iocs(type: str = None, limit: int = 50):
    sb = get_client()
    query = sb.table("iocs").select("*").order("created_at", desc=True)
    if type:
        query = query.eq("type", type)
    result = query.limit(limit).execute()
    return {"iocs": result.data or [], "total": len(result.data or [])}

@router.post("/iocs")
async def add_ioc(ioc: IOC):
    sb = get_client()
    result = sb.table("iocs").insert({
        **ioc.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    return {"created": result.data[0] if result.data else {}}

@router.get("/vulnerabilities")
async def list_vulnerabilities(status: str = None, severity: str = None):
    sb = get_client()
    query = sb.table("vulnerabilities").select("*").order("cvss_score", desc=True)
    if status:
        query = query.eq("status", status)
    if severity:
        query = query.eq("severity", severity)
    result = query.execute()
    return {"vulnerabilities": result.data or []}

@router.post("/vulnerabilities")
async def add_vulnerability(vuln: Vulnerability):
    sb = get_client()
    result = sb.table("vulnerabilities").insert({
        **vuln.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    return {"created": result.data[0] if result.data else {}}

@router.patch("/vulnerabilities/{vuln_id}/status")
async def update_vuln_status(vuln_id: str, status: str):
    if status not in ["open", "in_progress", "patched"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    sb = get_client()
    result = sb.table("vulnerabilities").update({"status": status}).eq("id", vuln_id).execute()
    return {"updated": result.data[0] if result.data else {}}
