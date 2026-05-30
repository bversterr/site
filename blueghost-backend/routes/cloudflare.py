from fastapi import APIRouter, HTTPException
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(prefix="/cloudflare", tags=["Cloudflare"])

CF_TOKEN   = os.environ.get("CLOUDFLARE_API_TOKEN")
CF_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
CF_BASE    = "https://api.cloudflare.com/client/v4"

HEADERS = {
    "Authorization": f"Bearer {CF_TOKEN}",
    "Content-Type":  "application/json",
}

def cf_get(path: str) -> dict:
    with httpx.Client(timeout=10.0) as client:
        r = client.get(f"{CF_BASE}{path}", headers=HEADERS)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    data = r.json()
    if not data.get("success"):
        raise HTTPException(status_code=400, detail=str(data.get("errors")))
    return data

@router.get("/dns")
async def get_dns_records():
    data = cf_get(f"/zones/{CF_ZONE_ID}/dns_records?per_page=100")
    records = [
        {
            "id":       r["id"],
            "type":     r["type"],
            "name":     r["name"],
            "content":  r["content"],
            "ttl":      r["ttl"],
            "proxied":  r.get("proxied", False),
            "modified": r.get("modified_on", ""),
        }
        for r in data["result"]
    ]
    return {"records": records, "total": len(records)}

@router.get("/zone")
async def get_zone():
    data = cf_get(f"/zones/{CF_ZONE_ID}")
    z = data["result"]
    return {
        "name":         z["name"],
        "status":       z["status"],
        "plan":         z["plan"]["name"],
        "name_servers": z["name_servers"],
        "created":      z["created_on"],
        "modified":     z["modified_on"],
    }

@router.get("/firewall")
async def get_firewall_events():
    data = cf_get(f"/zones/{CF_ZONE_ID}/security/events?per_page=25")
    events = [
        {
            "id":        e.get("ray_id", ""),
            "action":    e.get("action", ""),
            "country":   e.get("country", ""),
            "ip":        e.get("clientIP", ""),
            "method":    e.get("method", ""),
            "path":      e.get("uri_path", ""),
            "timestamp": e.get("occurred_at", ""),
        }
        for e in data.get("result", [])
    ]
    return {"events": events, "total": len(events)}

@router.get("/analytics")
async def get_analytics():
    data = cf_get(
        f"/zones/{CF_ZONE_ID}/analytics/dashboard?since=-1440&until=0&continuous=true"
    )
    totals = data["result"].get("totals", {})
    return {
        "requests": {
            "total":    totals.get("requests", {}).get("all", 0),
            "cached":   totals.get("requests", {}).get("cached", 0),
            "threats":  totals.get("threats", {}).get("all", 0),
        },
        "bandwidth": {
            "total_bytes": totals.get("bandwidth", {}).get("all", 0),
        },
        "pageviews": totals.get("pageviews", {}).get("all", 0),
        "uniques":   totals.get("uniques", {}).get("all", 0),
    }

@router.get("/ssl")
async def get_ssl():
    data = cf_get(f"/zones/{CF_ZONE_ID}/ssl/certificate_packs")
    certs = [
        {
            "id":      c["id"],
            "type":    c["type"],
            "status":  c["status"],
            "hosts":   c.get("hosts", []),
            "expires": c.get("certificates", [{}])[0].get("expires_on", ""),
        }
        for c in data.get("result", [])
    ]
    return {"certificates": certs}

@router.get("/waf")
async def get_waf_rules():
    data = cf_get(f"/zones/{CF_ZONE_ID}/firewall/rules?per_page=50")
    rules = [
        {
            "id":          r["id"],
            "description": r.get("description", ""),
            "action":      r["action"],
            "paused":      r.get("paused", False),
        }
        for r in data.get("result", [])
    ]
    return {"rules": rules, "total": len(rules)}
