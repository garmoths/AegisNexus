"""SMS Guard analysis: explainable rules + IOC cross-check for Turkish smishing.

Pure functions over the request and the IOC table; see router.py for the API.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import IndicatorOfCompromise

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
    sender: str | None = Field(None, max_length=64, description="Gönderen numara/başlık (opsiyonel)")


class URLIndicator(BaseModel):
    url: str
    is_suspicious: bool
    reason: str
    in_ioc_db: bool = False
    ioc_risk_score: int | None = None


class SMSAnalyzeResponse(BaseModel):
    risk_score: int
    category: str
    confidence: float
    action: str
    indicators: list[str]
    urls: list[URLIndicator]
    explanation: str
    analyzed_at: str


# ── Analyzer logic ─────────────────────────────────────────

def _extract_domain(url: str) -> str:
    return (urlsplit(url if '://' in url else 'https://' + url).hostname or '').lower().rstrip('.')


def _normalized(text: str) -> str:
    return ''.join(c for c in unicodedata.normalize('NFKD', text.lower().replace('ı', 'i')) if not unicodedata.combining(c))



def _analyze_sms(text: str, sender: str | None, db: Session) -> SMSAnalyzeResponse:
    text_lower = _normalized(text)
    score = 0
    indicators: list[str] = []

    # 1. URL analizi
    raw_urls = _URL_RE.findall(text)
    url_results: list[URLIndicator] = []

    for raw_url in raw_urls[:5]:
        raw_url = raw_url.rstrip('.,;!?)')
        try:
            domain = _extract_domain(raw_url)
            if not domain:
                raise ValueError('Missing host')
        except ValueError:
            score += 20
            url_results.append(URLIndicator(url=raw_url[:120], is_suspicious=True,
                                            reason='Geçersiz bağlantı yapısı; hedef doğrulanamadı'))
            continue
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
            score = max(score, min(100, ioc_risk))
            reasons.append(f"IOC veritabanında kayıtlı (risk: {ioc_risk})")
            is_susp = True

        url_results.append(URLIndicator(
            url=raw_url[:120],
            is_suspicious=is_susp,
            reason="; ".join(reasons) if reasons else "Yalnızca yerel kurallar kontrol edildi; güvenliği doğrulanmadı",
            in_ioc_db=in_ioc_db,
            ioc_risk_score=ioc_risk,
        ))

    # 2. Türkçe phishing kelimesi analizi
    kw_hits = [kw for kw in _PHISHING_KEYWORDS_TR if _normalized(kw) in text_lower]
    if len(kw_hits) >= 3:
        score += 25
        indicators.append(f"Phishing anahtar kelimeler: {', '.join(kw_hits[:4])}")
    elif len(kw_hits) >= 1:
        score += 10
        indicators.append(f"Şüpheli kelimeler: {', '.join(kw_hits[:3])}")

    # 3. Aciliyet / baskı taktikleri
    urg_hits = [w for w in _URGENCY_WORDS if re.search(r'\b' + re.escape(_normalized(w)) + r'\b', text_lower)]
    if re.search(r'\b\d+\s*(dakika|saat)\s*(icinde|kaldi)', text_lower):
        urg_hits.append('kısa süre baskısı')
    if len(urg_hits) >= 2:
        score += 15
        indicators.append(f"Aciliyet baskısı: {', '.join(urg_hits)}")

    # Combine requested actions with pressure; ordinary delivery/OTP notices are not proof of fraud.
    sensitive_request = re.search(r'(kart\s*bilgi|sifre|parola|dogrulama\s*kodu).{0,45}\b(gir(?:in|iniz)?|paylas(?:in|iniz)?|gonder(?:in|iniz)?|ilet(?:in|iniz)?|dogrula(?:yin|yiniz)?)\b', text_lower)
    payment_request = re.search(r'(odeme|ucret|borc).{0,35}(yap|gir|tamamla|ode)|\bodeyin', text_lower)
    account_threat = re.search(r'hesab.{0,20}(kapan|aski|bloke|kisit)', text_lower)
    if sensitive_request:
        score += 45
        indicators.append('Hassas bilgi girme veya paylaşma talebi')
        if urg_hits:
            score += 15
    if payment_request and (urg_hits or account_threat):
        score += 30
        indicators.append('Baskı altında ödeme talebi')
    if account_threat:
        score += 20
        indicators.append('Hesap kapatma veya kısıtlama tehdidi')

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
        explanation = f"Yerel kurallarda belirgin tehdit sinyali bulunmadı (risk: {score}/100). Göndereni bağımsız olarak doğrulayın; bu sonuç güvenlik garantisi değildir."

    return SMSAnalyzeResponse(
        risk_score=score,
        category=category,
        confidence=confidence,
        action=action,
        indicators=indicators,
        urls=url_results,
        explanation=explanation,
        analyzed_at=datetime.now(UTC).isoformat(),
    )


