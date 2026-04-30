"""Genişletilmiş istatistik endpoint'leri — overview, heatmap, weekly-digest.

GET /api/v2/victim-atlas/stats/overview       — Genel bakış
GET /api/v2/victim-atlas/stats/heatmap         — İl bazlı yoğunluk (GeoJSON)
GET /api/v2/victim-atlas/stats/weekly-digest   — Haftalık bülten
"""
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, extract
from sqlalchemy.orm import Session

from app.auth import resolve_api_key
from app.database import get_db
from app.models import APIKey, VictimCase

router = APIRouter(tags=["stats"])


@router.get("/overview", summary="Genel istatistik bakışı")
def stats_overview(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Toplam vaka, hot set, en yaygın 5 saldırı, haftalık trend."""
    total = db.query(func.count(VictimCase.id)).scalar()
    hot = db.query(func.count(VictimCase.id)).filter_by(is_hot=True).scalar()
    published = db.query(func.count(VictimCase.id)).filter_by(is_published=True).scalar()

    top_methods = (
        db.query(VictimCase.attack_method, func.count(VictimCase.id).label("c"))
        .group_by(VictimCase.attack_method)
        .order_by(func.count(VictimCase.id).desc())
        .limit(5)
        .all()
    )

    # Son 7 günlük trend
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    weekly_count = db.query(func.count(VictimCase.id)).filter(VictimCase.last_seen >= week_ago).scalar()

    return {
        "total_cases": total,
        "hot_cases": hot,
        "published_cases": published,
        "weekly_new_cases": weekly_count,
        "top_attack_methods": [{"method": r.attack_method, "count": r.c} for r in top_methods],
    }


@router.get("/heatmap", summary="İl bazlı vaka yoğunluğu (GeoJSON)")
def stats_heatmap(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Türkiye il bazlı vaka dağılımı — GeoJSON formatında."""
    region_counts = (
        db.query(VictimCase.region, func.count(VictimCase.id).label("c"))
        .filter(VictimCase.region.isnot(None), VictimCase.region != "")
        .group_by(VictimCase.region)
        .order_by(func.count(VictimCase.id).desc())
        .all()
    )

    features = [
        {
            "type": "Feature",
            "properties": {"name": r.region, "case_count": r.c},
            "geometry": None,  # GeoJSON koordinatları haritada client tarafında eşleştirilecek
        }
        for r in region_counts
    ]

    return {
        "type": "FeatureCollection",
        "features": features,
    }


@router.get("/weekly-digest", summary="Haftalık bülten")
def stats_weekly_digest(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Son haftanın özeti — Gemini ile üretilmiş bülten (yoksa istatistiksel özet)."""
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_cases = (
        db.query(VictimCase)
        .filter(VictimCase.last_seen >= week_ago, VictimCase.is_published == True)
        .order_by(VictimCase.severity_score.desc())
        .limit(10)
        .all()
    )

    # Gemini bülten üretimi (servis yoksa fallback)
    try:
        from modules.victim_atlas.gemini_service import generate_weekly_digest
        cases_data = [
            {"title": c.case_title, "method": c.attack_method, "severity": c.severity_score}
            for c in recent_cases
        ]
        digest_text = generate_weekly_digest(cases_data)
    except (ImportError, Exception):
        digest_text = None

    return {
        "period": {
            "from": week_ago.isoformat(),
            "to": datetime.now(timezone.utc).isoformat(),
        },
        "total_new_cases": len(recent_cases),
        "top_cases": [
            {
                "id": c.id,
                "title": c.case_title,
                "attack_method": c.attack_method,
                "severity_score": c.severity_score,
                "region": c.region,
            }
            for c in recent_cases[:5]
        ],
        "digest": digest_text or "Haftalık bülten şu an için kullanılamıyor.",
    }
