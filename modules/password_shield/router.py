"""
04 - Password Shield Module Router (Kriptografik Kalkan)
Güvenli şifre üretimi ve güçlülük analizi endpointleri
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from .generator import PasswordShield, generate_password, generate_memorable_password, check_password, get_word_rotation_manager, get_user_preferences_manager

router = APIRouter(tags=["04-password-shield"])

# PasswordShield instance'ı - kullanıcı bazlı tracking için
_password_shield_instance = None

def get_password_shield_instance() -> PasswordShield:
    """PasswordShield instance'ını döndür (singleton)"""
    global _password_shield_instance
    if _password_shield_instance is None:
        _password_shield_instance = PasswordShield()
    return _password_shield_instance


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


class UserPreferencesRequest(BaseModel):
    user_id: str
    preferences: dict


class PasswordPolicyRequest(BaseModel):
    policy: dict


class PasswordValidationRequest(BaseModel):
    password: str
    policy_hash: str


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
    
    Kullanıcı bazlı tracking:
    - Bir kelime en fazla 2 kez üst üste kullanılabilir
    - Aynı şifre kombinasyonu tekrar sunulmaz
    """
    shield = get_password_shield_instance()
    password, meta = shield.generate_memorable(
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
        "tracking_info": {
            "word_consecutive_limit": "Bir kelime en fazla 2 kez üst üste kullanılabilir",
            "password_uniqueness": "Aynı şifre kombinasyonu tekrar sunulmaz",
        },
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


@router.get("/stats")
def get_shield_stats():
    """Kriptografik Kalkan istatistikleri"""
    word_manager = get_word_rotation_manager()
    rotation_stats = word_manager.get_rotation_stats()
    
    return {
        "algorithm": "Python secrets.SystemRandom (CSPRNG)",
        "safe_symbols": PasswordShield.SAFE_SYMBOLS,
        "memorable_word_count": len(PasswordShield.get_memorable_words()),
        "max_length": 128,
        "min_length": 8,
        "module": "04_password_shield",
        "mathematical_guarantee": "Kriptografik olarak rastgele - tahmin edilemez",
        "social_impact": "Her güçlü şifre = Bir hack girişiminin engellenmesi",
        "word_rotation": rotation_stats,
    }


# =========================================================
# KELİME ROTASYON YÖNETİMİ ENDPOINTLERİ
# =========================================================

@router.get("/word-rotation/active-words")
def get_active_words():
    """
    Aktif kelime listesini döndür.
    Bu kelimeler bu hafta şifre üretiminde kullanılacak.
    """
    word_manager = get_word_rotation_manager()
    active_words = word_manager.get_active_words()
    
    return {
        "status": "success",
        "active_words": active_words,
        "word_count": len(active_words),
        "module": "04_password_shield",
        "info": "Bu kelimeler bu hafta şifre üretiminde kullanılacak",
    }


@router.get("/word-rotation/stats")
def get_word_rotation_stats():
    """
    Kelime rotasyon istatistiklerini döndür.
    """
    word_manager = get_word_rotation_manager()
    stats = word_manager.get_rotation_stats()
    
    return {
        "status": "success",
        "stats": stats,
        "module": "04_password_shield",
        "info": {
            "current_week": "Mevcut hafta (ISO formatı)",
            "active_word_count": "Aktif kelime sayısı (40)",
            "total_word_pool": "Toplam kelime havuzu (120+)",
            "last_rotation": "Son rotasyon tarihi",
            "unique_words_used": "Toplam kullanılan benzersiz kelime sayısı",
        },
    }


@router.get("/word-rotation/word-info/{word}")
def get_word_info(word: str):
    """
    Belirli bir kelimenin kullanım bilgisini döndür.
    """
    word_manager = get_word_rotation_manager()
    word_info = word_manager.get_word_usage_info(word)
    
    return {
        "status": "success",
        "word_info": word_info,
        "module": "04_password_shield",
        "info": {
            "usage_count": "Kelimenin kaç hafta kullanıldığı",
            "last_used": "Son kullanım haftası",
            "available": "Kelimenin şu an kullanılabilir olup olmadığı",
            "usage_history": "Kullanım haftaları listesi",
        },
    }


# =========================================================
# KULLANICI TERCİHLERİ YÖNETİMİ ENDPOINTLERİ
# =========================================================

@router.post("/user-preferences/save")
def save_user_preferences(req: UserPreferencesRequest):
    """
    Kullanıcı tercihlerini kaydet (hash ile anonimleştirilmiş).
    Şifreler asla düz metin olarak saklanmaz.
    """
    pref_manager = get_user_preferences_manager()
    pref_hash = pref_manager.save_user_preferences(req.user_id, req.preferences)
    
    return {
        "status": "success",
        "preferences_hash": pref_hash,
        "module": "04_password_shield",
        "info": {
            "user_id_anonymized": "Kullanıcı ID'si SHA-256 ile anonimleştirildi",
            "preferences_hashed": "Tercihler hash ile saklandı",
            "no_passwords_stored": "Şifreler asla düz metin olarak saklanmaz",
        },
    }


@router.get("/user-preferences/{user_id}")
def get_user_preferences(user_id: str):
    """
    Kullanıcı tercihlerini getir (anonimleştirilmiş).
    """
    pref_manager = get_user_preferences_manager()
    preferences = pref_manager.get_user_preferences(user_id)
    
    return {
        "status": "success",
        "user_id_hashed": pref_manager._hash_user_id(user_id),
        "preferences": preferences,
        "module": "04_password_shield",
        "info": {
            "user_id_anonymized": "Kullanıcı ID'si hash ile saklandı",
            "preferences_count": len(preferences),
        },
    }


@router.post("/password-policies/save")
def save_password_policy(req: PasswordPolicyRequest):
    """
    Şifre politikasını kaydet (hash ile).
    """
    pref_manager = get_user_preferences_manager()
    policy_hash = pref_manager.save_password_policy(req.policy)
    
    return {
        "status": "success",
        "policy_hash": policy_hash,
        "module": "04_password_shield",
        "info": {
            "policy_hashed": "Politika hash ile saklandı",
            "secure_storage": "Politika güvenli şekilde depolandı",
        },
    }


@router.get("/password-policies")
def get_password_policies():
    """
    Tüm şifre politikalarını getir.
    """
    pref_manager = get_user_preferences_manager()
    policies = pref_manager.get_password_policies()
    
    return {
        "status": "success",
        "policies": policies,
        "policy_count": len(policies),
        "module": "04_password_shield",
        "info": {
            "total_policies": len(policies),
            "secure_storage": "Politikalar hash ile saklandı",
        },
    }


@router.post("/password-policies/validate")
def validate_password_against_policy(req: PasswordValidationRequest):
    """
    Şifreyi politikaya göre doğrula.
    """
    pref_manager = get_user_preferences_manager()
    validation = pref_manager.validate_password_against_policy(req.password, req.policy_hash)
    
    return {
        "status": "success",
        "validation": validation,
        "module": "04_password_shield",
        "info": {
            "password_analyzed": "*" * len(req.password),
            "policy_hash": req.policy_hash,
            "validation_result": "Geçerli" if validation["valid"] else "Geçersiz",
        },
    }
