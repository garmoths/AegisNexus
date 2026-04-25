"""
IoC ve Phishing Verisi API Endpoints
Grafik ve istatistik verileri için aggregation sorguları
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, cast, Date
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pydantic import BaseModel

from shared.utils.db import get_db

router = APIRouter(tags=["IOC-Stats"])

# ==================== MODELS ====================

class IoCStatsResponse(BaseModel):
    total_records: int
    today_added: int
    weekly_growth: List[Dict]
    risk_distribution: List[Dict]
    top_threats: List[Dict]
    source_breakdown: List[Dict]
    last_updated: datetime

class PhishingDataResponse(BaseModel):
    total_urls: int
    daily_new: int
    top_domains: List[Dict]
    recent_urls: List[Dict]
    threat_categories: List[Dict]

# ==================== IOC STATS API ====================

@router.get("/stats", response_model=IoCStatsResponse)
def get_ioc_statistics(db: Session = Depends(get_db)):
    """
    IoC istatistikleri:
    - Toplam kayıt sayısı
    - Bugün eklenen kayıtlar
    - Haftalık büyüme trendi
    - Risk skoru dağılımı
    - En çok görülen tehditler
    - Kaynak dağılımı
    """
    try:
        from shared.models import IndicatorOfCompromise
        
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
            weekly_growth.append({
                "date": date.isoformat(),
                "count": count
            })
        
        # 4. Risk skoru dağılımı (0-20, 21-40, 41-60, 61-80, 81-100)
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
        
        top_threats_list = [
            {"threat_type": t[0], "count": t[1]} 
            for t in top_threats
        ]
        
        # 6. Kaynak dağılımı
        sources = db.query(
            IndicatorOfCompromise.source,
            func.count(IndicatorOfCompromise.id).label("count")
        ).filter(
            IndicatorOfCompromise.source.isnot(None)
        ).group_by(
            IndicatorOfCompromise.source
        ).order_by(desc("count")).limit(10).all()
        
        source_list = [
            {"source": s[0], "count": s[1]}
            for s in sources
        ]
        
        return {
            "total_records": total,
            "today_added": today_added,
            "weekly_growth": weekly_growth,
            "risk_distribution": risk_distribution,
            "top_threats": top_threats_list,
            "source_breakdown": source_list,
            "last_updated": datetime.utcnow()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stats error: {str(e)}")


# ==================== PHISHING DATA API ====================

@router.get("/phishing/data", response_model=PhishingDataResponse)
def get_phishing_data(
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Phishing verileri:
    - Toplam URL sayısı
    - Günlük yeni URL'ler
    - En çok phishing yapılan domainler
    - Son eklenen URL'ler
    - Tehdit kategorileri
    """
    try:
        from app.models import PhishingURL
        
        # 1. Toplam URL
        total = db.query(func.count(PhishingURL.id)).scalar() or 0
        
        # 2. Bugün eklenen
        today = datetime.utcnow().date()
        daily_new = db.query(func.count(PhishingURL.id)).filter(
            cast(PhishingURL.submission_time, Date) == today
        ).scalar() or 0
        
        # 3. En çok phishing yapılan domainler (domain_norm üzerinden)
        top_domains = db.query(
            PhishingURL.domain_norm,
            func.count(PhishingURL.id).label("count")
        ).filter(
            PhishingURL.domain_norm.isnot(None)
        ).group_by(
            PhishingURL.domain_norm
        ).order_by(desc("count")).limit(20).all()
        
        top_domains_list = [
            {"domain": d[0], "count": d[1]}
            for d in top_domains
        ]
        
        # 4. Son eklenen URL'ler
        recent = db.query(PhishingURL).order_by(
            desc(PhishingURL.submission_time)
        ).limit(limit).all()
        
        recent_list = [
            {
                "url": r.url[:100] + "..." if len(r.url) > 100 else r.url,
                "domain": r.domain_norm,
                "target": r.target,
                "status": r.status,
                "submission_time": r.submission_time.isoformat() if r.submission_time else None
            }
            for r in recent
        ]
        
        # 5. Tehdit kategorileri (target üzerinden)
        categories = db.query(
            PhishingURL.target,
            func.count(PhishingURL.id).label("count")
        ).filter(
            PhishingURL.target.isnot(None)
        ).group_by(
            PhishingURL.target
        ).order_by(desc("count")).limit(15).all()
        
        categories_list = [
            {"category": c[0], "count": c[1]}
            for c in categories
        ]
        
        return {
            "total_urls": total,
            "daily_new": daily_new,
            "top_domains": top_domains_list,
            "recent_urls": recent_list,
            "threat_categories": categories_list
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phishing data error: {str(e)}")


# ==================== REAL-TIME ENDPOINTS ====================

@router.get("/stats/live")
def get_live_ioc_count(db: Session = Depends(get_db)):
    """Canlı IoC sayısı (hızlı sorgu için)"""
    try:
        from shared.models import IndicatorOfCompromise
        count = db.query(func.count(IndicatorOfCompromise.id)).scalar() or 0
        return {"count": count, "timestamp": datetime.utcnow().isoformat()}
    except:
        return {"count": 0, "timestamp": datetime.utcnow().isoformat()}


@router.get("/phishing/live")
def get_live_phishing_count(db: Session = Depends(get_db)):
    """Canlı Phishing URL sayısı"""
    try:
        from app.models import PhishingURL
        count = db.query(func.count(PhishingURL.id)).scalar() or 0
        return {"count": count, "timestamp": datetime.utcnow().isoformat()}
    except:
        return {"count": 0, "timestamp": datetime.utcnow().isoformat()}
