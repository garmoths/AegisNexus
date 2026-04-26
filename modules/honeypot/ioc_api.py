"""
IOC API Endpoints
- /api/v2/ioc/check-ip
- /api/v2/ioc/check-hash
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Set

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Date, cast, desc, func, or_
from sqlalchemy.orm import Session

from app.models import IndicatorOfCompromise, PhishingURL
from modules.phishing_detector.threat_intel import (
    check_hash_malwarebazaar,
    check_ioc_threatfox,
    check_ip_shodan,
)
from shared.utils.db import get_db

router = APIRouter(tags=["IOC"])


class HashCheckRequest(BaseModel):
    hash: str


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _lookup_local_ioc(db: Session, value: str) -> Dict:
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


@router.get("/check-ip")
async def check_ip_reputation(ip: str, db: Session = Depends(get_db)):
    if not _is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Geçersiz IP adresi")

    confidence = 0
    sources: List[str] = []
    threat_types: Set[str] = set()
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


@router.post("/check-hash")
async def check_hash_reputation(payload: HashCheckRequest):
    file_hash = payload.hash.strip()
    if not file_hash:
        raise HTTPException(status_code=400, detail="Hash boş olamaz")

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


@router.get("/stats")
def get_ioc_statistics(db: Session = Depends(get_db)):
    total = db.query(func.count(IndicatorOfCompromise.id)).scalar() or 0
    today = datetime.utcnow().date()
    today_added = (
        db.query(func.count(IndicatorOfCompromise.id))
        .filter(cast(IndicatorOfCompromise.created_at, Date) == today)
        .scalar()
        or 0
    )

    weekly_growth = []
    for i in range(7, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        count = (
            db.query(func.count(IndicatorOfCompromise.id))
            .filter(cast(IndicatorOfCompromise.created_at, Date) == date)
            .scalar()
            or 0
        )
        weekly_growth.append({"date": date.isoformat(), "count": count})

    top_threats = (
        db.query(
            IndicatorOfCompromise.threat_type,
            func.count(IndicatorOfCompromise.id).label("count"),
        )
        .filter(IndicatorOfCompromise.threat_type.isnot(None))
        .group_by(IndicatorOfCompromise.threat_type)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    return {
        "total_records": total,
        "today_added": today_added,
        "weekly_growth": weekly_growth,
        "top_threats": [{"threat_type": t[0], "count": t[1]} for t in top_threats],
        "last_updated": datetime.utcnow(),
    }


@router.get("/phishing/data")
def get_phishing_data(limit: int = 100, db: Session = Depends(get_db)):
    total = db.query(func.count(PhishingURL.id)).scalar() or 0
    today = datetime.utcnow().date()
    daily_new = (
        db.query(func.count(PhishingURL.id))
        .filter(cast(PhishingURL.submission_time, Date) == today)
        .scalar()
        or 0
    )

    top_domains = (
        db.query(PhishingURL.domain_norm, func.count(PhishingURL.id).label("count"))
        .filter(PhishingURL.domain_norm.isnot(None))
        .group_by(PhishingURL.domain_norm)
        .order_by(desc("count"))
        .limit(20)
        .all()
    )

    recent = db.query(PhishingURL).order_by(desc(PhishingURL.submission_time)).limit(limit).all()
    recent_list = [
        {
            "url": r.url[:100] + "..." if len(r.url) > 100 else r.url,
            "domain": r.domain_norm,
            "target": r.target,
            "status": r.status,
            "submission_time": r.submission_time.isoformat() if r.submission_time else None,
        }
        for r in recent
    ]

    return {
        "total_urls": total,
        "daily_new": daily_new,
        "top_domains": [{"domain": d[0], "count": d[1]} for d in top_domains],
        "recent_urls": recent_list,
    }
