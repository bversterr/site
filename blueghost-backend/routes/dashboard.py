from fastapi import APIRouter
from db.supabase import get_client
from datetime import datetime, timedelta, timezone

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
async def get_stats():
    sb = get_client()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    threats = sb.table("threat_events").select("id, severity", count="exact").gte("created_at", since).execute()
    critical = [t for t in (threats.data or []) if t.get("severity") == "critical"]

    vulns = sb.table("vulnerabilities").select("id, severity", count="exact").eq("status", "open").execute()
    vuln_critical = [v for v in (vulns.data or []) if v.get("severity") == "critical"]
    vuln_high     = [v for v in (vulns.data or []) if v.get("severity") == "high"]

    blocked = sb.table("audit_log").select("id", count="exact").eq("event_type", "block").gte("created_at", since).execute()

    return {
        "threats_24h":      threats.count or 0,
        "critical_threats": len(critical),
        "open_vulns":       vulns.count or 0,
        "vuln_critical":    len(vuln_critical),
        "vuln_high":        len(vuln_high),
        "blocked_24h":      blocked.count or 0,
    }

@router.get("/threats")
async def get_threats(limit: int = 20):
    sb = get_client()
    result = sb.table("threat_events").select("*").order("created_at", desc=True).limit(limit).execute()
    return {"threats": result.data or []}

@router.get("/audit")
async def get_audit_log(limit: int = 50, event_type: str = None):
    sb = get_client()
    query = sb.table("audit_log").select("*").order("created_at", desc=True)
    if event_type:
        query = query.eq("event_type", event_type)
    result = query.limit(limit).execute()
    return {"events": result.data or [], "total": len(result.data or [])}
