"""IOC lookup and export endpoints (``/api/v2/ioc``).

- ``GET  /check-ip``     reputation from the local IOC DB, ThreatFox and Shodan
- ``POST /check-hash``   MalwareBazaar + ThreatFox lookup for a file hash
- ``GET  /export/stix``  STIX 2.1 bundle of active indicators (TLP by risk)

Lookups call external services with blocking HTTP clients, so the handlers are
plain ``def`` (run in the threadpool) rather than ``async def``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IndicatorOfCompromise
from modules.phishing_detector.threat_intel import (
    check_hash_malwarebazaar,
    check_ioc_threatfox,
    check_ip_shodan,
)

from . import service

router = APIRouter(tags=["ioc"])

# Deterministic, spec-valid (UUID-based) STIX identity for this platform.
STIX_IDENTITY_ID = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'aegisnexus.threat-intelligence')}"


# ── STIX 2.1 helpers ─────────────────────────────────────

_STIX_TYPE_MAP = {
    "ip": "ipv4-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "hash": "file:hashes.'SHA-256'",
    "email": "email-addr:value",
}

_TLP_MAP = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519f9",
    "green": "marking-definition--34098fce-860f-48ae-8e10-7be814e5c36a",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _ioc_to_stix_indicator(row: IndicatorOfCompromise) -> dict:
    stix_attr = _STIX_TYPE_MAP.get(row.ioc_type or "url", "url:value")
    # STIX patterning string literals escape backslash and single quote.
    literal = row.ioc_value.replace('\\', '\\\\').replace("'", "\\'")
    pattern = f"[{stix_attr} = '{literal}']"
    tlp = "white" if (row.risk_score or 0) < 50 else "amber" if (row.risk_score or 0) < 80 else "red"
    valid_from = (row.first_seen or row.created_at or datetime.now(UTC)).isoformat()
    valid_until = (row.last_seen or datetime.now(UTC)).isoformat()
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, row.ioc_value)}",
        "created": row.created_at.isoformat() if row.created_at else valid_from,
        "modified": row.updated_at.isoformat() if row.updated_at else valid_from,
        "name": f"{row.threat_type or 'unknown'} — {row.ioc_value[:60]}",
        "description": f"Source: {row.source} | Risk: {row.risk_score}/100 | Detections: {row.detection_count}",
        "created_by_ref": STIX_IDENTITY_ID,
        "indicator_types": [row.threat_type or "unknown"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "valid_until": valid_until,
        "confidence": int((row.confidence or 0.5) * 100),
        "labels": [row.threat_type or "unknown", f"risk-{row.risk_score or 0}"],
        "object_marking_refs": [_TLP_MAP[tlp]],
        "external_references": (
            [{"source_name": row.source, "url": row.source_reference}]
            if row.source_reference else []
        ),
    }


class HashCheckRequest(BaseModel):
    hash: str = Field(min_length=32, max_length=128, pattern=r'^\s*[A-Fa-f0-9]+\s*$', description='MD5, SHA-1 or SHA-256')


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _lookup_local_ioc(db: Session, value: str) -> dict:
    row = (
        db.query(IndicatorOfCompromise)
        .filter(
            IndicatorOfCompromise.ioc_value == value,
            or_(
                IndicatorOfCompromise.status == "active",
                IndicatorOfCompromise.status.is_(None),
            ),
        )
        .order_by(IndicatorOfCompromise.risk_score.desc(), IndicatorOfCompromise.created_at.desc())
        .first()
    )
    if not row:
        return {"found": False}
    return {
        "found": True,
        "type": row.threat_type,
        "risk_score": row.risk_score,
        "source": row.source,
    }


@router.get("/check-ip", summary="IP reputation (local DB, ThreatFox, Shodan)")
def check_ip_reputation(ip: str = Query(max_length=45), db: Session = Depends(get_db)):
    if not _is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Geçersiz IP adresi")

    confidence = 0
    sources: list[str] = []
    threat_types: set[str] = set()
    is_c2 = False

    local = _lookup_local_ioc(db, ip)
    if local.get("found"):
        confidence += 50
        sources.append("local_db")
        if local.get("type"):
            threat_types.add(str(local["type"]))
            if str(local["type"]).lower() in {"botnet", "c2", "botnet_cc"}:
                is_c2 = True

    tf = check_ioc_threatfox(ip, timeout=10)
    if tf.get("found"):
        confidence += int(tf.get("confidence") or 30)
        sources.append("threatfox")
        if tf.get("threat_type"):
            threat_types.add(str(tf["threat_type"]))
            if str(tf["threat_type"]).lower() == "botnet_cc":
                is_c2 = True

    shodan = check_ip_shodan(ip, timeout=10)
    if shodan.get("found"):
        sources.append("shodan")
        tags = shodan.get("tags", [])
        if "scanner" in tags:
            confidence += 20
        if "tor" in tags:
            confidence += 15
        if shodan.get("vulns"):
            confidence += 10

    return {
        "status": "success",
        "data": {
            "ip": ip,
            "malicious": confidence >= 40,
            "confidence": min(confidence, 100),
            "is_c2_server": is_c2,
            "threat_types": sorted(threat_types),
            "open_ports": shodan.get("open_ports", []) if shodan else [],
            "cves": shodan.get("vulns", []) if shodan else [],
            "sources": sources,
        },
        "module": "02_honeypot_ioc",
    }


@router.post("/check-hash", summary="File hash reputation (MalwareBazaar, ThreatFox)")
def check_hash_reputation(payload: HashCheckRequest):
    file_hash = payload.hash.strip().lower()

    mb_result = check_hash_malwarebazaar(file_hash, timeout=10)
    tf_result = check_ioc_threatfox(file_hash, timeout=10)

    found = bool(mb_result.get("found") or tf_result.get("found"))
    confidence = int(tf_result.get("confidence") or 0) if tf_result.get("found") else 0
    if mb_result.get("found"):
        confidence = max(confidence, 70)

    return {
        "status": "success",
        "data": {
            "hash": file_hash,
            "found": found,
            "malware_family": mb_result.get("malware_family") or tf_result.get("malware"),
            "tags": sorted(set((mb_result.get("tags") or []) + (tf_result.get("tags") or []))),
            "confidence": min(confidence, 100),
            "malicious": found,
            "malwarebazaar": mb_result,
            "threatfox": tf_result,
        },
        "module": "02_honeypot_ioc",
    }


@router.get("/stats", summary="IOC counters and weekly growth")
def get_ioc_statistics(db: Session = Depends(get_db)):
    stats = service.ioc_statistics(db)
    return {
        "total_records": stats["total_records"],
        "today_added": stats["today_added"],
        "weekly_growth": stats["weekly_growth"],
        "top_threats": [{"threat_type": t["type"], "count": t["count"]} for t in stats["top_threats"]],
        "last_updated": stats["last_updated"],
    }


@router.get("/phishing/data", summary="Phishing URL counters and recent URLs")
def get_phishing_data(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    stats = service.phishing_statistics(db, recent_limit=limit, url_chars=100)
    return {
        "total_urls": stats["total_urls"],
        "daily_new": stats["daily_new"],
        "top_domains": stats["top_domains"],
        "recent_urls": [{**{k: v for k, v in r.items() if k != "time"}, "submission_time": r["time"]} for r in stats["recent_urls"]],
    }


@router.get(
    "/export/stix",
    summary="STIX 2.1 Bundle export",
    description=(
        "IOC veritabanını STIX 2.1 formatında dışa aktarır. "
        "USOM, MISP ve tüm CTI platformları bu formatı destekler. "
        "TLP renklendirmesi otomatik uygulanır (risk<50→WHITE, <80→AMBER, ≥80→RED)."
    ),
    response_class=JSONResponse,
)
def export_stix_bundle(
    threat_type: str | None = Query(None, description="Filtre: phishing, malware, botnet, c2, spam"),
    min_risk_score: int = Query(0, ge=0, le=100, description="Minimum risk skoru"),
    limit: int = Query(1000, ge=1, le=5000, description="Maksimum kayıt sayısı"),
    db: Session = Depends(get_db),
):
    q = db.query(IndicatorOfCompromise).filter(
        IndicatorOfCompromise.status == "active",
        IndicatorOfCompromise.risk_score >= min_risk_score,
    )
    if threat_type:
        q = q.filter(IndicatorOfCompromise.threat_type == threat_type)
    rows = q.order_by(IndicatorOfCompromise.risk_score.desc()).limit(limit).all()

    identity_id = STIX_IDENTITY_ID
    indicators = [_ioc_to_stix_indicator(r) for r in rows]

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "name": "AegisNexus Threat Intelligence",
                "identity_class": "system",
                "description": "Türkiye merkezli açık kaynak siber tehdit istihbaratı platformu.",
                "created": "2024-01-01T00:00:00Z",
                "modified": datetime.now(UTC).isoformat(),
            },
            *indicators,
        ],
        "_meta": {
            "generated_at": datetime.now(UTC).isoformat(),
            "indicator_count": len(indicators),
            "filters": {"threat_type": threat_type, "min_risk_score": min_risk_score},
            "source": "AegisNexus",
        },
    }
    return JSONResponse(
        content=bundle,
        media_type="application/stix+json",
        headers={"Content-Disposition": f'attachment; filename="aegisnexus-ioc-stix-{datetime.now(UTC).strftime("%Y%m%d")}.json"'},
    )
