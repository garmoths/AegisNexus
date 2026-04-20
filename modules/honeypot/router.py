"""
02 - Honeypot Module Router (IP Avcısı)
Dolandırıcıları tersine mühendislik ile avlayan tuzak endpointleri
"""
from __future__ import annotations

import json
import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from shared.utils.db import get_db
from app.models import HoneypotEvent, IndicatorOfCompromise
from .engine import honeypot_engine, HoneypotSession
from .ioc_collector import IOCCollectorEngine, IOCRecord, IOCType, ThreatType, IOCSource

logger = logging.getLogger(__name__)

router = APIRouter(tags=["02-honeypot"])
ioc_engine = IOCCollectorEngine()


def _client_ip(request: Request) -> str:
    """İstemci IP adresini çıkar"""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class HoneypotInteractionRequest(BaseModel):
    session_id: str
    action: str  # login_attempt, otp_request, password_reset
    payload: Optional[dict] = None


class HoneypotCreateRequest(BaseModel):
    decoy_type: str = "bank_login"  # bank_login, social_login, shopping_login


class IOCCollectRequest(BaseModel):
    source: str = "external"
    payload: Optional[dict] = None
    raw_text: Optional[str] = None
    tags: Optional[List[str]] = None


# Gerçekçi banka login tuzak sayfası
_BANK_DECOY_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ziraat Bankası - İnternet Şubesi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a5f2a 0%, #0d3d1a 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #1a5f2a;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #1a5f2a;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #1a5f2a;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #124a1f;
        }
        .security-badge {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }
        .hidden-warning {
            position: fixed;
            bottom: 10px;
            right: 10px;
            background: #ff4444;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            font-size: 12px;
            opacity: 0.9;
        }
        #status-message {
            display: none;
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .error { background: #ffebee; color: #c62828; border: 1px solid #ef5350; }
        .info { background: #e3f2fd; color: #1565c0; border: 1px solid #42a5f5; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>Ziraat Bankası</h1>
            <p>İnternet Şubesi</p>
        </div>
        <div id="status-message"></div>
        <form id="login-form">
            <div class="form-group">
                <label>Müşteri/TCKN</label>
                <input type="text" id="customer-id" placeholder="Müşteri Numaranız veya TCKN" maxlength="11">
            </div>
            <div class="form-group">
                <label>Şifre</label>
                <input type="password" id="password" placeholder="Şifreniz">
            </div>
            <div class="form-group">
                <label>Onay Kodu</label>
                <input type="text" id="otp" placeholder="Telefonunuza gelen kod" maxlength="6">
            </div>
            <button type="submit" id="submit-btn">Giriş Yap</button>
        </form>
        <div class="security-badge">
            <p>128-bit SSL Güvenlik Sertifikası ile korunmaktadır</p>
        </div>
    </div>
    <div class="hidden-warning">
        ⚠️ BU SAYFA BİR TUZAKTIR - DOLANDIRICI AKTİF OLARAK İZLENİYOR
    </div>
    
    <script>
        // Session ID'yi URL'den al
        const urlParams = new URLSearchParams(window.location.search);
        const sessionId = urlParams.get('session') || 'unknown';
        
        let interactionCount = 0;
        let startTime = Date.now();
        
        // Sayfa yüklendiğinde oturum başlat
        fetch('/api/honeypot/session/ping', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({session_id: sessionId, action: 'page_load'})
        });
        
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            interactionCount++;
            
            const customerId = document.getElementById('customer-id').value;
            const password = document.getElementById('password').value;
            const otp = document.getElementById('otp').value;
            
            const statusDiv = document.getElementById('status-message');
            statusDiv.style.display = 'block';
            statusDiv.className = 'info';
            statusDiv.textContent = 'Giriş yapılıyor...';
            document.getElementById('submit-btn').disabled = true;
            
            // Etkileşimi kaydet
            const response = await fetch('/api/honeypot/interaction', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    session_id: sessionId,
                    action: 'login_attempt',
                    payload: {customer_id: customerId, has_otp: !!otp}
                })
            });
            
            const result = await response.json();
            
            setTimeout(() => {
                statusDiv.className = 'error';
                statusDiv.textContent = result.fake_error || 'Şifre hatalı. Tekrar deneyin.';
                document.getElementById('submit-btn').disabled = false;
                
                if (interactionCount >= 3) {
                    document.getElementById('otp').value = '';
                    document.getElementById('otp').placeholder = 'Yeni kod gönderildi (1:59)';
                }
            }, result.delay_seconds * 1000);
        });
        
        // Şifre sıfırlama linki (sahte)
        document.addEventListener('DOMContentLoaded', () => {
            const form = document.querySelector('.login-container');
            const resetLink = document.createElement('p');
            resetLink.innerHTML = '<a href="#" style="color: #1a5f2a; font-size: 14px;">Şifremi unuttum</a>';
            resetLink.style.textAlign = 'center';
            resetLink.style.marginTop = '15px';
            form.appendChild(resetLink);
            
            resetLink.querySelector('a').addEventListener('click', async (e) => {
                e.preventDefault();
                await fetch('/api/honeypot/interaction', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: sessionId,
                        action: 'password_reset'
                    })
                });
                alert('Şifre sıfırlama talimatları e-posta adresinize gönderildi.');
            });
        });
    </script>
</body>
</html>"""


@router.get("/decoy", response_class=HTMLResponse)
def honeypot_decoy_page(request: Request, db: Session = Depends(get_db)):
    """
    Gerçekçi banka login tuzak sayfası.
    Dolandırıcılar bu sayfayı görünce kandırıldıklarını sanacak.
    """
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    # Yeni oturum oluştur
    session = honeypot_engine.create_session(ip, user_agent, "bank_login")
    
    # Veritabanına kaydet
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=user_agent[:500],
        path="/api/v2/decoy",
        referer=request.headers.get("referer", "")[:500],
        note=f"session_id:{session.session_id}",
    )
    db.add(event)
    db.commit()
    
    # HTML'e session ID göm
    html_with_session = _BANK_DECOY_HTML.replace(
        "const sessionId = urlParams.get('session') || 'unknown';",
        f"const sessionId = '{session.session_id}';"
    )
    
    return HTMLResponse(content=html_with_session)


@router.post("/session/create")
def create_honeypot_session(
    req: HoneypotCreateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Yeni tuzak oturumu oluştur"""
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    session = honeypot_engine.create_session(ip, user_agent, req.decoy_type)
    
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=user_agent[:500],
        path="/api/v2/session/create",
        note=f"session_id:{session.session_id},decoy:{req.decoy_type}",
    )
    db.add(event)
    db.commit()
    
    return {
        "session_id": session.session_id,
        "decoy_page": f"/api/v2/decoy?session={session.session_id}",
        "decoy_type": req.decoy_type,
        "module": "02_honeypot"
    }


@router.post("/interaction")
def record_interaction(
    req: HoneypotInteractionRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Dolandırıcı etkileşimini kaydet ve oyala"""
    result = honeypot_engine.process_interaction(req.session_id, req.action, req.payload)
    
    # Veritabanına kaydet
    ip = _client_ip(request)
    event = HoneypotEvent(
        client_ip=ip,
        user_agent=request.headers.get("user-agent", "")[:500],
        path=f"/api/v2/interaction",
        note=f"session_id:{req.session_id},action:{req.action},threat_score:{result.get('threat_score', 0)},ioc:{result.get('ioc_detected', 0)}",
    )
    db.add(event)
    db.commit()
    
    result["module"] = "02_honeypot"
    return result


@router.get("/stats")
def get_honeypot_stats(session_id: Optional[str] = None):
    """Honeypot istatistikleri - Kurtarılmış kurban sayısı"""
    stats = honeypot_engine.get_session_stats(session_id)
    stats["module"] = "02_honeypot"
    stats["social_impact"] = {
        "description": "Dolandırıcıların bu sayfada harcadığı her dakika, gerçek bir vatandaşın dolandırılmasını önler",
        "formula": "1 saat zaman kaybı = 12 potansiyel kurban kurtarıldı",
        "estimated_money_saved_tl": stats.get("estimated_money_saved_try", 0),
    }
    return stats


@router.post("/session/close")
def close_honeypot_session(session_id: str):
    """Oturumu kapat ve son raporu ver"""
    result = honeypot_engine.close_session(session_id)
    result["module"] = "02_honeypot"
    return result


@router.get("/decoy-types")
def get_decoy_types():
    """Mevcut tuzak türlerini listele"""
    return {
        "decoy_types": list(honeypot_engine.DECOY_TEMPLATES.keys()),
        "module": "02_honeypot",
        "description": "Her tuzak türü farklı dolandırıcı profiline hitap eder"
    }


@router.post("/ioc/collect")
def collect_ioc_data(
    req: IOCCollectRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Honeypot disi kaynaklardan IOC topla."""
    ip = _client_ip(request)
    context = {
        "client_ip": ip,
        "user_agent": request.headers.get("user-agent", "")[:500],
        "tags": req.tags or [],
    }

    collected = honeypot_engine.collect_iocs(
        source=req.source,
        payload=req.payload,
        raw_text=req.raw_text or "",
        context=context,
    )

    event = HoneypotEvent(
        client_ip=ip,
        user_agent=context["user_agent"],
        path="/api/v2/ioc/collect",
        referer=request.headers.get("referer", "")[:500],
        note=json.dumps(
            {
                "source": req.source,
                "ioc_count": len(collected),
                "tags": req.tags or [],
            },
            ensure_ascii=True,
        ),
    )
    db.add(event)
    db.commit()

    return {
        "status": "success",
        "collected_count": len(collected),
        "collected": collected,
        "module": "02_honeypot",
    }


@router.get("/ioc/list")
def list_collected_iocs(ioc_type: Optional[str] = None, limit: int = 100, min_count: int = 1):
    """Toplanan IOC listesi."""
    return {
        "status": "success",
        "data": honeypot_engine.list_iocs(ioc_type=ioc_type, limit=limit, min_count=min_count),
        "module": "02_honeypot",
    }


@router.get("/ioc/stats")
def get_ioc_stats():
    """IOC collector istatistikleri - veritabanından."""
    try:
        from app.database import SessionLocal
        db = SessionLocal()
        
        # Veritabanından IOC istatistikleri
        total = db.query(IndicatorOfCompromise).count()
        high_risk = db.query(IndicatorOfCompromise).filter(IndicatorOfCompromise.risk_score >= 80).count()
        medium_risk = db.query(IndicatorOfCompromise).filter(
            (IndicatorOfCompromise.risk_score >= 50) & (IndicatorOfCompromise.risk_score < 80)
        ).count()
        low_risk = db.query(IndicatorOfCompromise).filter(IndicatorOfCompromise.risk_score < 50).count()
        
        from datetime import datetime
        last_update = db.query(IndicatorOfCompromise.created_at).order_by(
            IndicatorOfCompromise.created_at.desc()
        ).first()
        
        db.close()
        
        return {
            "status": "success",
            "stats": {
                "total_iocs": total,
                "high_risk_count": high_risk,
                "medium_risk_count": medium_risk,
                "low_risk_count": low_risk,
                "last_update": last_update[0] if last_update else None,
            },
            "module": "02_honeypot",
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "stats": {
                "total_iocs": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
            },
            "module": "02_honeypot",
        }


# ============================================================================
# ENTERPRISE IOC COLLECTOR ENDPOINTS (NEW)
# ============================================================================

class IOCCollectorFetchRequest(BaseModel):
    """Fetch IOCs from external threat intelligence sources."""
    sources: Optional[List[str]] = None  # Specific sources to fetch from
    limit_per_source: int = 100


class IOCFilterRequest(BaseModel):
    """Filter stored IOCs by criteria."""
    ioc_type: Optional[str] = None  # 'ip', 'domain', 'url', 'hash'
    threat_type: Optional[str] = None  # 'phishing', 'malware', 'botnet', 'c2'
    min_risk_score: int = 0  # Only return IOCs >= this score
    source: Optional[str] = None  # Filter by specific source


@router.post("/ioc/fetch-external")
async def fetch_external_iocs(
    req: IOCCollectorFetchRequest,
    db: Session = Depends(get_db)
):
    """
    Fetch IOCs from external threat intelligence sources.
    
    Sources:
    - abuse.ch (URLhaus, PhishTank, SSL Phishing)
    - AbuseIPDB (malicious IP database)
    
    Response: Collected, deduplicated, and scored IOCs
    """
    try:
        logger.info(f"Starting external IOC collection from sources: {req.sources}")
        
        # Collect from sources
        collected_iocs = ioc_engine.collect_all(include_sources=req.sources)
        
        logger.info(f"Collected {len(collected_iocs)} unique IOCs")
        
        # Store in memory cache
        for ioc in collected_iocs:
            ioc_engine.store_ioc(ioc)
        
        # Also persist to database (for operator gateway)
        stored_count = 0
        for ioc in collected_iocs:
            try:
                db_ioc = IndicatorOfCompromise(
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.ioc_value,
                    ioc_value_hash=ioc.get_value_hash(),
                    source=ioc.source,
                    threat_type=ioc.threat_type,
                    threat_tags=ioc.threat_tags or [],
                    risk_score=ioc.risk_score,
                    confidence=ioc.confidence,
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen,
                    detection_count=ioc.detection_count,
                    context=ioc.context,
                    ioc_metadata=ioc.ioc_metadata,
                    source_reference=ioc.source_reference,
                    status='active',
                )
                db.add(db_ioc)
                stored_count += 1
            except Exception as e:
                logger.error(f"Error storing IOC {ioc.ioc_value}: {e}")
                continue
        
        db.commit()
        logger.info(f"Persisted {stored_count} IOCs to database")
        
        # Get updated stats
        stats = ioc_engine.get_stats()
        
        return {
            "status": "success",
            "module": "02_honeypot_ioc_collector",
            "collected": len(collected_iocs),
            "persisted": stored_count,
            "stats": stats,
            "samples": [ioc.to_dict() for ioc in collected_iocs[:10]],  # First 10 samples
        }
    
    except Exception as e:
        logger.error(f"External IOC collection failed: {e}", exc_info=True)
        return {
            "status": "error",
            "module": "02_honeypot_ioc_collector",
            "error": str(e),
        }


@router.get("/ioc/list-collected")
async def list_collected_iocs_advanced(
    ioc_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    min_risk_score: int = 0,
    source: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """
    List collected IOCs with advanced filtering.
    
    Filters:
    - ioc_type: 'ip', 'domain', 'url', 'hash'
    - threat_type: 'phishing', 'malware', 'botnet', 'c2'
    - min_risk_score: 1-100
    - source: 'abuse_urlhaus', 'abuse_phishtank', 'abuseipdb', 'honeypot'
    """
    filters = {}
    if ioc_type:
        filters['ioc_type'] = ioc_type
    if threat_type:
        filters['threat_type'] = threat_type
    if min_risk_score > 0:
        filters['min_risk_score'] = min_risk_score
    if source:
        filters['source'] = source
    
    all_iocs = ioc_engine.list_iocs(filters=filters)
    total = len(all_iocs)
    paginated = all_iocs[offset:offset+limit]
    
    return {
        "status": "success",
        "module": "02_honeypot_ioc_collector",
        "total": total,
        "returned": len(paginated),
        "offset": offset,
        "limit": limit,
        "iocs": [ioc.to_dict() for ioc in paginated],
    }


@router.get("/ioc/stats-advanced")
async def get_ioc_stats_advanced():
    """
    Get comprehensive IOC statistics.
    
    Returns:
    - Total IOC count
    - Breakdown by type (ip, domain, url, hash)
    - Breakdown by threat type (phishing, malware, botnet, etc.)
    - Breakdown by source (URLhaus, AbuseIPDB, etc.)
    - Average risk score
    - High risk count (>= 80)
    - Critical count (>= 95)
    """
    stats = ioc_engine.get_stats()
    
    return {
        "status": "success",
        "module": "02_honeypot_ioc_collector",
        "statistics": stats,
        "insights": {
            "high_risk_percentage": round((stats['high_risk_count'] / max(1, stats['total_iocs'])) * 100, 2),
            "critical_percentage": round((stats['critical_count'] / max(1, stats['total_iocs'])) * 100, 2),
            "average_risk_score": round(stats.get('average_risk_score', 0), 2),
        }
    }


@router.get("/ioc/search")
async def search_ioc(q: str):
    """
    Search for specific IOC in database.
    
    Searches across: IP, domain, URL, file hash, source reference.
    """
    if len(q) < 2:
        return {
            "status": "error",
            "message": "Search query must be at least 2 characters",
        }
    
    try:
        from app.database import SessionLocal
        db = SessionLocal()
        
        results = db.query(IndicatorOfCompromise).filter(
            IndicatorOfCompromise.ioc_value.ilike(f"%{q}%")
        ).limit(50).all()
        
        response = {
            "status": "success",
            "module": "02_honeypot_ioc_collector",
            "query": q,
            "found": len(results),
            "results": [
                {
                    "id": r.id,
                    "type": r.ioc_type,
                    "value": r.ioc_value,
                    "threat_type": r.threat_type,
                    "risk_score": r.risk_score,
                    "source": r.source,
                    "detection_count": r.detection_count,
                    "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                    "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                }
                for r in results
            ]
        }
        db.close()
        return response
    except Exception as e:
        logger.error(f"IOC search error: {e}")
        return {
            "status": "error",
            "module": "02_honeypot_ioc_collector",
            "error": str(e),
        }


@router.get("/ioc/by-risk-score")
async def get_iocs_by_risk_level(
    level: str,  # 'critical' (95-100), 'high' (80-94), 'medium' (50-79), 'low' (1-49)
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get IOCs grouped by risk level."""
    risk_ranges = {
        'critical': (95, 100),
        'high': (80, 94),
        'medium': (50, 79),
        'low': (1, 49),
    }
    
    if level not in risk_ranges:
        return {"status": "error", "message": f"Invalid level. Must be one of: {list(risk_ranges.keys())}"}
    
    min_score, max_score = risk_ranges[level]
    
    try:
        results = db.query(IndicatorOfCompromise).filter(
            IndicatorOfCompromise.risk_score >= min_score,
            IndicatorOfCompromise.risk_score <= max_score,
        ).order_by(IndicatorOfCompromise.risk_score.desc()).limit(limit).all()
        
        return {
            "status": "success",
            "module": "02_honeypot_ioc_collector",
            "risk_level": level,
            "score_range": {"min": min_score, "max": max_score},
            "found": len(results),
            "iocs": [
                {
                    "value": r.ioc_value,
                    "type": r.ioc_type,
                    "threat_type": r.threat_type,
                    "risk_score": r.risk_score,
                    "confidence": r.confidence,
                    "source": r.source,
                    "detection_count": r.detection_count,
                }
                for r in results
            ]
        }
    except Exception as e:
        logger.error(f"Risk level query error: {e}")
        return {"status": "error", "error": str(e)}


# ==================== IOC STATS API ====================

@router.get("/ioc/stats")
def get_ioc_statistics(db: Session = Depends(get_db)):
    """
    IoC istatistikleri aggregation endpoint
    """
    from sqlalchemy import func, desc, cast, Date
    from datetime import datetime, timedelta
    
    try:
        # 1. Toplam kayıt
        total = db.query(func.count(IndicatorOfCompromise.id)).scalar() or 0
        
        # 2. Bugün eklenen
        today = datetime.utcnow().date()
        today_added = db.query(func.count(IndicatorOfCompromise.id)).filter(
            cast(IndicatorOfCompromise.created_at, Date) == today
        ).scalar() or 0
        
        # 3. Son 7 gün günlük artış
        weekly_growth = []
        for i in range(7, -1, -1):
            date = datetime.utcnow().date() - timedelta(days=i)
            count = db.query(func.count(IndicatorOfCompromise.id)).filter(
                cast(IndicatorOfCompromise.created_at, Date) == date
            ).scalar() or 0
            weekly_growth.append({"date": date.isoformat(), "count": count})
        
        # 4. Risk skoru dağılımı
        risk_ranges = [
            ("Düşük (0-20)", 0, 20),
            ("Orta-Düşük (21-40)", 21, 40),
            ("Orta (41-60)", 41, 60),
            ("Orta-Yüksek (61-80)", 61, 80),
            ("Yüksek (81-100)", 81, 100)
        ]
        risk_distribution = []
        for label, min_val, max_val in risk_ranges:
            count = db.query(func.count(IndicatorOfCompromise.id)).filter(
                IndicatorOfCompromise.risk_score >= min_val,
                IndicatorOfCompromise.risk_score <= max_val
            ).scalar() or 0
            risk_distribution.append({
                "range": label,
                "count": count,
                "percentage": round((count / total * 100), 2) if total > 0 else 0
            })
        
        # 5. En çok görülen tehdit tipleri
        top_threats = db.query(
            IndicatorOfCompromise.threat_type,
            func.count(IndicatorOfCompromise.id).label("count")
        ).filter(
            IndicatorOfCompromise.threat_type.isnot(None)
        ).group_by(
            IndicatorOfCompromise.threat_type
        ).order_by(desc("count")).limit(10).all()
        
        # 6. Kaynak dağılımı
        sources = db.query(
            IndicatorOfCompromise.source,
            func.count(IndicatorOfCompromise.id).label("count")
        ).filter(
            IndicatorOfCompromise.source.isnot(None)
        ).group_by(
            IndicatorOfCompromise.source
        ).order_by(desc("count")).limit(10).all()
        
        return {
            "status": "success",
            "total_records": total,
            "today_added": today_added,
            "weekly_growth": weekly_growth,
            "risk_distribution": risk_distribution,
            "top_threats": [{"type": t[0], "count": t[1]} for t in top_threats],
            "source_breakdown": [{"source": s[0], "count": s[1]} for s in sources],
            "last_updated": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"IoC stats error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/phishing/stats")
def get_phishing_statistics(db: Session = Depends(get_db)):
    """
    Phishing verileri aggregation endpoint
    """
    from app.models import PhishingURL
    from sqlalchemy import func, desc, cast, Date
    from datetime import datetime, timedelta
    
    try:
        # 1. Toplam URL
        total = db.query(func.count(PhishingURL.id)).scalar() or 0
        
        # 2. Bugün eklenen
        today = datetime.utcnow().date()
        daily_new = db.query(func.count(PhishingURL.id)).filter(
            cast(PhishingURL.submission_time, Date) == today
        ).scalar() or 0
        
        # 3. En çok phishing yapılan domainler
        top_domains = db.query(
            PhishingURL.domain_norm,
            func.count(PhishingURL.id).label("count")
        ).filter(
            PhishingURL.domain_norm.isnot(None)
        ).group_by(
            PhishingURL.domain_norm
        ).order_by(desc("count")).limit(20).all()
        
        # 4. Son 20 URL
        recent = db.query(PhishingURL).order_by(
            desc(PhishingURL.submission_time)
        ).limit(20).all()
        
        # 5. Hedef kategorileri
        categories = db.query(
            PhishingURL.target,
            func.count(PhishingURL.id).label("count")
        ).filter(
            PhishingURL.target.isnot(None)
        ).group_by(
            PhishingURL.target
        ).order_by(desc("count")).limit(15).all()
        
        return {
            "status": "success",
            "total_urls": total,
            "daily_new": daily_new,
            "top_domains": [{"domain": d[0], "count": d[1]} for d in top_domains],
            "recent_urls": [
                {
                    "url": r.url[:80] + "..." if len(r.url) > 80 else r.url,
                    "domain": r.domain_norm,
                    "target": r.target,
                    "status": r.status,
                    "time": r.submission_time.isoformat() if r.submission_time else None
                }
                for r in recent
            ],
            "threat_categories": [{"category": c[0], "count": c[1]} for c in categories],
            "last_updated": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Phishing stats error: {e}")
        return {"status": "error", "message": str(e)}
