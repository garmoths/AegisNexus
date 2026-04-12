"""Have I Been Pwned (v3) ile e-posta sızıntı sorgusu + Türkçe özet (API anahtarı gerekir)."""
from __future__ import annotations

import re
from urllib.parse import quote

import requests

from app.config import get_settings

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _brief_breach(b: dict) -> dict:
    return {
        "name": b.get("Name"),
        "title": b.get("Title"),
        "domain": b.get("Domain"),
        "breach_date": b.get("BreachDate"),
        "data_classes": b.get("DataClasses") or [],
    }


def _turkish_report(breaches: list[dict]) -> str:
    n = len(breaches)
    if n == 0:
        return (
            "Bu e-posta adresi Have I Been Pwned kayıtlarında bilinen bir sızıntıda görünmüyor. "
            "Yine de güçlü ve benzersiz şifre kullanmaya devam edin."
        )
    names = ", ".join(b.get("Title") or b.get("Name") or "?" for b in breaches[:5])
    extra = f" ve {n - 5} kayıt daha" if n > 5 else ""
    classes: set[str] = set()
    for b in breaches:
        for c in b.get("data_classes") or []:
            classes.add(str(c))
    class_hint = ""
    if classes:
        class_hint = " Sızıntılarda geçen veri türleri arasında şunlar olabilir: " + ", ".join(sorted(classes)[:8]) + "."

    return (
        f"E-posta adresiniz {n} ayrı olayda ({names}{extra}) sızmış görünüyor. "
        f"Bu hesapta ve aynı şifreyi kullandığınız diğer sitelerde şifrenizi derhal değiştirin; mümkünse çok faktörlü doğrulama açın."
        + class_hint
    )


def lookup_breaches(email: str) -> dict:
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return {
            "ok": False,
            "error": "E-posta adresi geçerli görünmüyor.",
            "hint": "Örnek biçim: isim@ornek.com — boşluk ve yazım hatası olmadığından emin olun.",
        }

    key = get_settings()["hibp_api_key"]
    if not key:
        return {
            "ok": False,
            "error": "Have I Been Pwned API anahtarı yapılandırılmamış.",
            "hint": "Projede .env dosyasına HIBP_API_KEY=... satırını ekleyin. Anahtar haveibeenpwned.com üzerinden ücretli API aboneliği ile alınır.",
        }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
    headers = {
        "hibp-api-key": key,
        "user-agent": "AegisNexus-Security-Platform",
    }
    params = {"truncateResponse": "false"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        return {
            "ok": False,
            "error": "Dış servise bağlanılamadı.",
            "hint": f"Ağ veya güvenlik duvarı engeli olabilir. Teknik ayrıntı: {e}",
        }

    if r.status_code == 404:
        return {
            "ok": True,
            "breached": False,
            "breach_count": 0,
            "breaches": [],
            "report_tr": _turkish_report([]),
        }

    if r.status_code == 401:
        return {
            "ok": False,
            "error": "API anahtarı reddedildi.",
            "hint": "HIBP_API_KEY değerini kontrol edin; süresi dolmuş veya yanlış kopyalanmış olabilir.",
        }

    if r.status_code == 429:
        return {
            "ok": False,
            "error": "İstek limiti aşıldı.",
            "hint": "Have I Been Pwned dakikada sınırlı sayıda sorguya izin verir. Bir süre bekleyip tekrar deneyin.",
        }

    if r.status_code != 200:
        return {
            "ok": False,
            "error": f"Servis beklenmeyen bir kod döndürdü (HTTP {r.status_code}).",
            "hint": "HIBP durum sayfasını veya anahtar kotanızı kontrol edin.",
        }

    raw = r.json()
    if not isinstance(raw, list):
        return {"ok": False, "error": "Yanıt işlenemedi.", "hint": "API formatı değişmiş olabilir."}

    brief = [_brief_breach(b) for b in raw]
    return {
        "ok": True,
        "breached": len(brief) > 0,
        "breach_count": len(brief),
        "breaches": brief,
        "report_tr": _turkish_report(brief),
    }
