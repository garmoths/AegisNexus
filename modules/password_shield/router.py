"""
04 - Password Shield Module Router (Kriptografik Kalkan)
Güvenli şifre üretimi ve güçlülük analizi endpointleri
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from .generator import PasswordShield, generate_password, generate_memorable_password, check_password
from .pwned_check import check_pwned

router = APIRouter(tags=["04-password-shield"])


class PasswordGenerateRequest(BaseModel):
    length: int = 20
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True
    category: Optional[str] = None  # ultra_secure, high_security, standard, memorable


class MemorablePasswordRequest(BaseModel):
    word_count: int = 4
    separator: str = "-"


class PasswordCheckRequest(BaseModel):
    password: str


@router.post("/generate")
def generate_secure_password(req: PasswordGenerateRequest):
    """
    Kriptografik olarak güçlü şifre üret.
    Kırılması yüzyıllar/yüzbinlerce yıl süren şifreler.
    """
    password, meta = PasswordShield.generate(
        length=req.length,
        uppercase=req.uppercase,
        lowercase=req.lowercase,
        digits=req.digits,
        symbols=req.symbols,
        category=req.category,
    )
    
    return {
        "status": "success",
        "password": password,
        "metadata": meta,
        "module": "04_password_shield",
        "usage_warning": "Bu şifreyi güvenli bir şifre yöneticisine kaydedin. Ekran görüntüsü almayın.",
        "next_steps": [
            "Şifreyi 1Password/Bitwarden'e kaydet",
            "Hesapta 2FA aktif et",
            "Eski zayıf şifreyi değiştir",
        ]
    }


@router.post("/generate-memorable")
def generate_memorable(req: MemorablePasswordRequest):
    """
    Akılda kalıcı ama güvenli şifre üret.
    Türkçe kelimeler + rakam + sembol kombinasyonu.
    """
    password, meta = PasswordShield.generate_memorable(
        word_count=req.word_count,
        separator=req.separator,
    )
    
    return {
        "status": "success",
        "password": password,
        "metadata": meta,
        "module": "04_password_shield",
        "example": "atlas-buzul-çınar-123!",
        "memorization_tip": "Kelime dizisini bir cümle gibi hayal edin: 'Atlas buzul çınarının altında 123 var!''",
    }


@router.post("/check-strength")
def check_password_strength(req: PasswordCheckRequest):
    """
    Mevcut şifre güçlülüğünü analiz et.
    Kırılma süresi ve iyileştirme önerileri.
    """
    analysis = PasswordShield.check_password_strength(req.password)
    
    return {
        "status": "success",
        "password_analyzed": "*" * len(req.password),
        "analysis": analysis,
        "module": "04_password_shield",
        "recommendation": "Yeni şifre üretin" if analysis["security_level"].startswith("WEAK") or analysis["security_level"].startswith("MODERATE") else "Şifre güçlü ✓",
    }


@router.get("/categories")
def get_password_categories():
    """Şifre güvenlik kategorilerini listele"""
    return {
        "categories": PasswordShield.CATEGORIES,
        "module": "04_password_shield",
        "recommendation": {
            "banka_hesaplari": "ultra_secure (32 karakter)",
            "email_sosyal": "high_security (20 karakter)",
            "gunluk_site": "standard (16 karakter)",
            "wifi_sifre": "memorable (akılda kalıcı)",
        }
    }


@router.post("/check-pwned")
def check_password_pwned(req: PasswordCheckRequest):
    """
    Şifrenin HIBP Pwned Passwords veritabanında görülüp görülmediğini kontrol eder.

    k-Anonymity kullanılır — şifrenin kendisi hiçbir zaman dışarı gönderilmez.
    Yalnızca SHA-1 hash'inin ilk 5 karakteri API'ye iletilir.
    """
    result = check_pwned(req.password)
    return {
        "status": "success",
        "password_length": len(req.password),
        "pwned_check": result,
        "module": "04_password_shield",
        "note": "k-Anonymity: Şifreniz API'ye gönderilmez, yalnızca hash prefix kullanılır.",
    }


@router.post("/check-strength-full")
def check_strength_full(req: PasswordCheckRequest):
    """
    Hem güçlülük analizi hem de HIBP sızıntı kontrolünü birleştirir.

    'Şifren güçlü ama daha önce sızdırılmış' senaryosunu yakalar.
    """
    strength = PasswordShield.check_password_strength(req.password)
    pwned = check_pwned(req.password)

    combined_recommendation = []
    if strength["security_level"].startswith(("WEAK", "MODERATE")):
        combined_recommendation.append("Şifre zayıf — yeni şifre oluşturun.")
    if pwned["pwned"]:
        combined_recommendation.append(pwned["warning"])
    if not combined_recommendation:
        combined_recommendation.append("Şifre güçlü ve sızıntı veritabanında görülmemiş ✓")

    return {
        "status": "success",
        "password_analyzed": "*" * len(req.password),
        "strength_analysis": strength,
        "pwned_check": pwned,
        "combined_recommendation": combined_recommendation,
        "overall_safe": (
            not pwned["pwned"]
            and not strength["security_level"].startswith(("WEAK", "MODERATE"))
        ),
        "module": "04_password_shield",
    }


@router.get("/stats")
def get_shield_stats():
    """Kriptografik Kalkan istatistikleri"""
    return {
        "algorithm": "Python secrets.SystemRandom (CSPRNG)",
        "safe_symbols": PasswordShield.SAFE_SYMBOLS,
        "memorable_word_count": len(PasswordShield.MEMORABLE_WORDS),
        "max_length": 128,
        "min_length": 8,
        "module": "04_password_shield",
        "mathematical_guarantee": "Kriptografik olarak rastgele - tahmin edilemez",
        "social_impact": "Her güçlü şifre = Bir hack girişiminin engellenmesi",
    }
