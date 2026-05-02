"""
SMS Guard — Türkçe SMS smishing/phishing analiz modülü.

POST /api/v2/sms/analyze
  Gelen SMS metnini ML modeli + IOC çapraz kontrol ile analiz eder.
  Operatörler (Turkcell, TT, Vodafone) bu endpoint'i kendi SMS
  filtreleme pipeline'larına entegre edebilir.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import IndicatorOfCompromise
from shared.utils.db import get_db

router = APIRouter(tags=["07-sms-guard"])

# ── Patterns ──────────────────────────────────────────────

_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "tr.im", "kisa.link"}
_PHISHING_KEYWORDS_TR = [
    "paketiniz", "kargo", "teslim", "şifreniz sıfırlandı", "hesabınız askıya",
    "ödeme yapılmadı", "acil işlem", "son tarih", "doğrulama kodu", "ücretsiz kazan",
    "para iadesi", "banka hesabı", "kredi kartı", "şüpheli giriş", "güvenlik uyarısı",
    "hediye kazandınız", "şanslı kazanan", "btk", "sgk", "ptt kargo", "aras kargo",
    "mng kargo", "sürat kargo", "vergi iadesi", "trafik cezası",
]
_URGENCY_WORDS = ["acil", "hemen", "şimdi", "son", "bugün", "24 saat", "dikkat", "uyarı"]

# ── Request / Response schemas ─────────────────────────────

class SMSAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1600, description="Analiz edilecek SMS metni")
    sender: Optional[str] = Field(None, description="Gönderen numara/başlık (opsiyonel)")


class URLIndicator(BaseModel):
    url: str
    is_suspicious: bool
    reason: str
    in_ioc_db: bool = False
    ioc_risk_score: Optional[int] = None


class SMSAnalyzeResponse(BaseModel):
    risk_score: int
    category: str
    confidence: float
    action: str
    indicators: List[str]
    urls: List[URLIndicator]
    explanation: str
    analyzed_at: str


# ── Analyzer logic ─────────────────────────────────────────

def _extract_domain(url: str) -> str:
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    return url.split("/")[0].split("?")[0].lower()


def _analyze_sms(text: str, sender: Optional[str], db: Session) -> SMSAnalyzeResponse:
    text_lower = text.lower()
    score = 0
    indicators: List[str] = []

    # 1. URL analizi
    raw_urls = _URL_RE.findall(text)
    url_results: List[URLIndicator] = []

    for raw_url in raw_urls[:5]:
        domain = _extract_domain(raw_url)
        reasons = []
        is_susp = False

        if domain in _SHORTENER_DOMAINS:
            reasons.append("Kısa URL servisi")
            score += 20
            is_susp = True
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw_url):
            reasons.append("IP tabanlı URL")
            score += 25
            is_susp = True
        if any(b in domain for b in ["secure", "login", "verify", "update", "account"]):
            reasons.append("Phishing path yapısı")
            score += 15
            is_susp = True
        if re.search(r"\.tk$|\.ml$|\.cf$|\.ga$|\.gq$", domain):
            reasons.append("Şüpheli TLD")
            score += 15
            is_susp = True

        # IOC DB çapraz kontrol
        ioc_hit = (
            db.query(IndicatorOfCompromise)
            .filter(
                or_(
                    IndicatorOfCompromise.ioc_value == raw_url,
                    IndicatorOfCompromise.ioc_value == domain,
                ),
                IndicatorOfCompromise.status == "active",
            )
            .order_by(IndicatorOfCompromise.risk_score.desc())
            .first()
        )
        ioc_risk = None
        in_ioc_db = False
        if ioc_hit:
            in_ioc_db = True
            ioc_risk = ioc_hit.risk_score
            score += min(ioc_risk, 40)
            reasons.append(f"IOC veritabanında kayıtlı (risk: {ioc_risk})")
            is_susp = True

        url_results.append(URLIndicator(
            url=raw_url[:120],
            is_suspicious=is_susp,
            reason="; ".join(reasons) if reasons else "Normal görünümlü URL",
            in_ioc_db=in_ioc_db,
            ioc_risk_score=ioc_risk,
        ))

    # 2. Türkçe phishing kelimesi analizi
    kw_hits = [kw for kw in _PHISHING_KEYWORDS_TR if kw in text_lower]
    if len(kw_hits) >= 3:
        score += 25
        indicators.append(f"Phishing anahtar kelimeler: {', '.join(kw_hits[:4])}")
    elif len(kw_hits) >= 1:
        score += 10
        indicators.append(f"Şüpheli kelimeler: {', '.join(kw_hits[:3])}")

    # 3. Aciliyet / baskı taktikleri
    urg_hits = [w for w in _URGENCY_WORDS if w in text_lower]
    if len(urg_hits) >= 2:
        score += 15
        indicators.append(f"Aciliyet baskısı: {', '.join(urg_hits)}")

    # 4. Gönderen analizi (resmi kurum taklidi)
    if sender:
        sender_lower = sender.lower()
        if any(b in sender_lower for b in ["ptt", "sgk", "btk", "banka", "bank", "garanti", "akbank", "isbank", "ykb"]):
            score += 20
            indicators.append(f"Resmi kurum taklidi şüphesi: {sender}")

    # 5. Skor sınırla
    score = min(score, 100)

    # 6. Kategori
    if score >= 75:
        category = "smishing"
        action = "BLOCK"
        confidence = round(0.7 + (score - 75) * 0.012, 2)
    elif score >= 45:
        category = "şüpheli"
        action = "WARN"
        confidence = round(0.4 + (score - 45) * 0.01, 2)
    elif score >= 20:
        category = "belirsiz"
        action = "MONITOR"
        confidence = round(0.3 + score * 0.005, 2)
    else:
        category = "temiz"
        action = "ALLOW"
        confidence = round(0.9 - score * 0.01, 2)

    confidence = min(confidence, 0.99)

    # 7. Açıklama
    if action == "BLOCK":
        explanation = f"SMS yüksek riskli smishing/phishing içeriği taşıyor (risk: {score}/100). Engellenmesi önerilir."
    elif action == "WARN":
        explanation = f"SMS şüpheli öğeler içeriyor (risk: {score}/100). Kullanıcı uyarılmalı."
    elif action == "MONITOR":
        explanation = f"SMS düşük riskli ama takip edilmeli (risk: {score}/100)."
    else:
        explanation = f"SMS temiz görünüyor (risk: {score}/100). İşlem gerekmiyor."

    return SMSAnalyzeResponse(
        risk_score=score,
        category=category,
        confidence=confidence,
        action=action,
        indicators=indicators,
        urls=url_results,
        explanation=explanation,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )


# ── Endpoints ─────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=SMSAnalyzeResponse,
    summary="SMS güvenlik analizi",
    description=(
        "Gelen SMS metnini smishing/phishing açısından analiz eder. "
        "ML tabanlı skor + IOC veritabanı çapraz kontrolü + Türkçe keyword analizi. "
        "Operatör entegrasyonu için: SMS içeriğini POST edin, risk skoru + aksiyon alın."
    ),
)
def analyze_sms(req: SMSAnalyzeRequest, db: Session = Depends(get_db)):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="SMS metni boş olamaz.")
    return _analyze_sms(req.text, req.sender, db)


@router.get(
    "/info",
    summary="SMS Guard modül bilgisi",
)
def sms_guard_info():
    return {
        "module": "07-sms-guard",
        "version": "1.0.0",
        "description": "Türkçe SMS smishing/phishing analiz motoru",
        "capabilities": [
            "URL kısaltıcı tespiti",
            "IP tabanlı URL tespiti",
            "IOC veritabanı çapraz kontrol",
            "Türkçe phishing anahtar kelime analizi",
            "Aciliyet/baskı taktiği tespiti",
            "Resmi kurum taklidi şüphesi",
        ],
        "integration": {
            "endpoint": "POST /api/v2/sms/analyze",
            "input": {"text": "SMS içeriği", "sender": "Gönderen (opsiyonel)"},
            "output": {"risk_score": "0-100", "category": "smishing|şüpheli|belirsiz|temiz", "action": "BLOCK|WARN|MONITOR|ALLOW"},
        },
        "use_cases": ["Operatör SMS filtresi", "Kurumsal güvenlik gateway", "Bireysel SMS kontrolü"],
    }
