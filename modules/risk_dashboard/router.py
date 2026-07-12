"""
08 - Risk Dashboard Module Router
Tüm modüllerden gelen verileri birleştiren Risk Dashboard API
"""
from __future__ import annotations

import logging
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from .aggregator import aggregate_risk

router = APIRouter(tags=["08-risk-dashboard"])
logger = logging.getLogger(__name__)


class DashboardRequest(BaseModel):
    email: str
    region: Optional[str] = None


@router.post("/aggregate")
def get_risk_dashboard(req: DashboardRequest):
    """
    🛡️ **Risk Dashboard** — Birleşik Dijital Risk Analizi

    Tüm modüllerden (Breach Intel, Phishing Detector, Victim Atlas, Honeypot)
    gelen verileri ağırlıklı ortalama ile birleştirir.

    Yanıt:
    - composite_score: 0-100 arası risk skoru
    - risk_label: DÜŞÜK / ORTA / YÜKSEK / KRİTİK
    - modules: Her modülün detaylı katkısı
    - recommendations: Kişiselleştirilmiş öneriler
    - summary: Türkçe özet
    """
    try:
        result = aggregate_risk(email=req.email, region=req.region)
        return {
            "status": "success",
            "module": "08_risk_dashboard",
            **result,
        }
    except Exception as exc:
        logger.error(f"[RiskDashboard] aggregate_risk error: {exc}", exc_info=True)
        return {
            "status": "error",
            "message": str(exc),
            "module": "08_risk_dashboard",
        }


@router.get("/weights")
def get_dashboard_weights():
    """Risk Dashboard ağırlık konfigürasyonunu döner."""
    return {
        "status": "success",
        "weights": {
            "breach_intel": 0.35,
            "phishing_detector": 0.25,
            "victim_atlas": 0.20,
            "honeypot": 0.20,
        },
        "risk_thresholds": {
            "KRİTİK": "80-100",
            "YÜKSEK": "60-79",
            "ORTA": "35-59",
            "DÜŞÜK": "0-34",
        },
        "module": "08_risk_dashboard",
    }
