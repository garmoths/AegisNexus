"""
modules/risk_dashboard/aggregator.py

Tüm modüllerden veri çekerek birleşik dijital risk skoru hesaplar.
Kullanıcı tek ekranda "benim dijital ayak izim ne kadar riskli" sorusunu yanıtlar.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.risk_dashboard")


def _clamp(val: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, val))


# ── Risk seviyesi etiketleme ─────────────────────────────────────────────────

def _risk_label(score: float) -> str:
    if score >= 80:
        return "KRİTİK"
    if score >= 60:
        return "YÜKSEK"
    if score >= 35:
        return "ORTA"
    return "DÜŞÜK"


def _risk_color(score: float) -> str:
    if score >= 80:
        return "#d32f2f"
    if score >= 60:
        return "#f57c00"
    if score >= 35:
        return "#fbc02d"
    return "#388e3c"


# ── Modül ajanları ───────────────────────────────────────────────────────────

def _breach_intel_score(email: str) -> Dict[str, Any]:
    """Breach Intel: sızıntı sayısı → risk skoru (0-100)."""
    try:
        from modules.breach_intel.hibp_client import lookup_breaches
        from modules.breach_intel.domain_checker import check_email_domain

        hibp = lookup_breaches(email)
        breaches = hibp.get("breaches", [])
        breach_count = len(breaches)
        # Her sızıntı +12 puan, max 100
        score = _clamp(breach_count * 12)

        domain_risk = check_email_domain(email)
        domain_score = domain_risk.get("risk_score", 0)
        # Domain phishing varsa ek +20
        if domain_risk.get("is_suspicious"):
            score = _clamp(score + 20)

        return {
            "score": score,
            "breach_count": breach_count,
            "domain_risk": domain_risk,
            "breached": hibp.get("breached", False),
            "available": True,
        }
    except Exception as exc:
        logger.warning(f"[Dashboard] breach_intel_score error: {exc}")
        return {"score": 0, "available": False, "error": str(exc)}


def _phishing_detector_score(email: str) -> Dict[str, Any]:
    """Phishing Detector: email domain'i için son IOC sayısı → risk skoru."""
    try:
        from app.database import SessionLocal
        from app.models import IndicatorOfCompromise

        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return {"score": 0, "ioc_count": 0, "available": True}

        db = SessionLocal()
        try:
            ioc_count = (
                db.query(IndicatorOfCompromise)
                .filter(
                    IndicatorOfCompromise.ioc_value.ilike(f"%{domain}%"),
                    IndicatorOfCompromise.status == "active",
                )
                .count()
            )
        finally:
            db.close()

        score = _clamp(ioc_count * 15)
        return {"score": score, "ioc_count": ioc_count, "domain": domain, "available": True}
    except Exception as exc:
        logger.warning(f"[Dashboard] phishing_detector_score error: {exc}")
        return {"score": 0, "available": False, "error": str(exc)}


def _victim_atlas_score(region: Optional[str] = None) -> Dict[str, Any]:
    """Victim Atlas: bölgedeki aktif vaka yoğunluğu → risk skoru."""
    try:
        from modules.victim_atlas.database import get_attack_trends

        trends = get_attack_trends(days=30, region=region, top_n=5)
        total_cases = sum(t["count"] for t in trends)
        # 1-10 vaka: düşük, 10-50: orta, 50+: yüksek
        if total_cases == 0:
            score = 10.0
        elif total_cases < 10:
            score = 25.0
        elif total_cases < 50:
            score = 50.0
        else:
            score = _clamp(50.0 + (total_cases - 50) * 0.5)

        return {
            "score": score,
            "total_recent_cases": total_cases,
            "top_attack_methods": trends[:3],
            "region": region,
            "available": True,
        }
    except Exception as exc:
        logger.warning(f"[Dashboard] victim_atlas_score error: {exc}")
        return {"score": 0, "available": False, "error": str(exc)}


def _honeypot_score() -> Dict[str, Any]:
    """Honeypot: son 24 saatteki aktif IOC yoğunluğu → risk skoru."""
    try:
        from datetime import datetime, timedelta, timezone
        from app.database import SessionLocal
        from app.models import IndicatorOfCompromise

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        db = SessionLocal()
        try:
            recent_iocs = (
                db.query(IndicatorOfCompromise)
                .filter(
                    IndicatorOfCompromise.created_at >= cutoff,
                    IndicatorOfCompromise.status == "active",
                )
                .count()
            )
        finally:
            db.close()

        score = _clamp(recent_iocs * 2)
        return {"score": score, "iocs_last_24h": recent_iocs, "available": True}
    except Exception as exc:
        logger.warning(f"[Dashboard] honeypot_score error: {exc}")
        return {"score": 0, "available": False, "error": str(exc)}


# ── Ana aggregator ────────────────────────────────────────────────────────────

def aggregate_risk(
    email: str,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tüm modüllerin risk skorlarını ağırlıklı ortalama ile birleştirir.

    Ağırlıklar:
      - Breach Intel:       35%
      - Phishing Detector:  25%
      - Victim Atlas:       20%
      - Honeypot:           20%

    Returns tam dashboard payload.
    """
    breach = _breach_intel_score(email)
    phishing = _phishing_detector_score(email)
    victim = _victim_atlas_score(region)
    honeypot = _honeypot_score()

    w_breach = 0.35
    w_phishing = 0.25
    w_victim = 0.20
    w_honeypot = 0.20

    composite = (
        breach["score"] * w_breach
        + phishing["score"] * w_phishing
        + victim["score"] * w_victim
        + honeypot["score"] * w_honeypot
    )
    composite = round(_clamp(composite), 1)

    modules = [
        {
            "module": "breach_intel",
            "label": "Veri Sızıntısı",
            "score": breach["score"],
            "weight_pct": int(w_breach * 100),
            "detail": breach,
        },
        {
            "module": "phishing_detector",
            "label": "Phishing Tehdit İstihbaratı",
            "score": phishing["score"],
            "weight_pct": int(w_phishing * 100),
            "detail": phishing,
        },
        {
            "module": "victim_atlas",
            "label": "Bölgesel Saldırı Trendleri",
            "score": victim["score"],
            "weight_pct": int(w_victim * 100),
            "detail": victim,
        },
        {
            "module": "honeypot",
            "label": "Aktif IOC Yoğunluğu",
            "score": honeypot["score"],
            "weight_pct": int(w_honeypot * 100),
            "detail": honeypot,
        },
    ]

    recommendations = _build_recommendations(composite, breach, phishing, victim)

    return {
        "email": email,
        "region": region,
        "composite_score": composite,
        "risk_label": _risk_label(composite),
        "risk_color": _risk_color(composite),
        "modules": modules,
        "recommendations": recommendations,
        "summary": _build_summary(composite, breach, victim),
    }


def _build_recommendations(
    score: float,
    breach: Dict,
    phishing: Dict,
    victim: Dict,
) -> List[str]:
    recs: List[str] = []
    if breach.get("breached"):
        recs.append(
            f"📧 E-posta adresiniz {breach.get('breach_count', 0)} sızıntıda yer alıyor — "
            "şifrelerinizi hemen değiştirin."
        )
    if breach.get("domain_risk", {}).get("is_suspicious"):
        recs.append(
            "⚠️ E-posta domain'iniz phishing veritabanında şüpheli görünüyor — "
            "bu adresle işlem yapmayın."
        )
    if phishing.get("ioc_count", 0) > 0:
        recs.append(
            f"🔴 Phishing istihbarat veritabanında {phishing['ioc_count']} IOC kaydı mevcut."
        )
    top_methods = victim.get("top_attack_methods", [])
    if top_methods:
        method_names = ", ".join(m["attack_method_tr"] for m in top_methods[:2])
        recs.append(
            f"📊 Bölgenizde son 30 günde en çok {method_names} saldırıları görülüyor."
        )
    if score >= 60:
        recs.append("🛡️ Password Shield ile güçlü şifre oluşturun ve 2FA aktif edin.")
    if not recs:
        recs.append("✅ Dijital ayak iziniz şu an güvenli görünüyor. Düzenli kontrol yapmaya devam edin.")
    return recs


def _build_summary(score: float, breach: Dict, victim: Dict) -> str:
    risk = _risk_label(score)
    parts = []
    if breach.get("breach_count", 0) > 0:
        parts.append(f"{breach['breach_count']} veri sızıntısı")
    total_cases = victim.get("total_recent_cases", 0)
    if total_cases > 0:
        parts.append(f"son 30 günde {total_cases} bölgesel vaka")
    if parts:
        return f"Dijital risk seviyeniz {risk} ({score}/100). {', '.join(parts)} tespit edildi."
    return f"Dijital risk seviyeniz {risk} ({score}/100). Belirgin bir tehdit tespit edilmedi."
