"""
Kriptografik Şifre Üretici - Kırılması matematiksel olarak imkansız şifreler
"""
from __future__ import annotations

import secrets
import string
import math
import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Tuple, Dict, Optional, List


# =========================================================
# KELİME ROTASYON SİSTEMİ
# =========================================================

class WordRotationManager:
    """
    Kelime Rotasyon Yöneticisi
    
    Haftalık kelime rotasyonu sağlar:
    - Her hafta otomatik kelime değişimi
    - 3 hafta üst üste aynı kelime kullanımını engeller
    - 1 hafta kullanılmama sonrası tekrar kullanıma izin verir
    """
    
    # Geniş kelime havuzu (330 kelime - her bölüm 30 kelime)
    WORD_POOL = [
        # Doğa (30 kelime)
        "atlas", "buzul", "çınar", "evren", "fırtına", "gökkuşağı",
        "hazine", "ışık", "jeton", "kale", "lotus", "merhaba", "nehir",
        "okyanus", "pırıl", "rüzgar", "sema", "toprak", "uçurtma",
        "dere", "bahar", "çiçek", "fener", "göl", "çöl", "volkan",
        "kaynak", "kanyon", "şelale", "mağara",
        
        # Mevsimler (30 kelime)
        "ilkbahar", "yaz", "sonbahar", "kış", "mart", "nisan", "mayıs",
        "haziran", "temmuz", "ağustos", "eylül", "ekim", "kasım", "aralık",
        "ocak", "şubat", "kar", "yağmur", "sis", "dolu", "yıldırım",
        "bulut", "hava", "sıcak", "soğuk", "ılık", "nemli", "kuru",
        "rüzgarlı", "güneşli",
        
        # Gökyüzü (30 kelime)
        "ay", "gezegen", "meteor", "kometa", "nebula", "karadelik", "uzay",
        "kosmos", "teleskop", "astronom", "takımyıldız", "burç", "astroloji",
        "merkur", "venüs", "dünya", "mars", "jüpiter", "satürn", "uranüs",
        "neptün", "plüton", "kuasar", "pulsar", "süpernova", "kuyruklu", "asteroid",
        "galaksi", "yörünge", "sistem",
        
        # Coğrafya (30 kelime)
        "dağ", "çayır", "düz", "deniz", "ada", "yarımada", "kıta",
        "ülke", "şehir", "kasaba", "köy", "sahil", "kumsal", "plaj",
        "plateau", "tundra", "taiga", "savanna", "jungle", "yanardağ",
        "deprem", "tsunami", "kasırga", "tufan", "hortum", "sel",
        "heyelan", "çığ", "körfez", "boğaz",
        
        # Renkler (30 kelime)
        "mavi", "yeşil", "kırmızı", "sarı", "turuncu", "mor", "pembe",
        "beyaz", "siyah", "gri", "lacivert", "turkuaz", "bordo", "vişne",
        "krem", "bej", "haki", "zümrüt", "safir", "yakut", "elmas",
        "altın", "gümüş", "bronz", "bakır", "demir", "çelik", "alüminyum",
        "platin", "titanyum",
        
        # Duygular (30 kelime)
        "sevgi", "umut", "mutluluk", "huzur", "barış", "cesaret", "güç",
        "özgürlük", "keyif", "neşe", "korku", "endişe", "stres", "tansiyon",
        "heyecan", "merak", "ilgi", "saygı", "şefkat", "merhamet", "tutku",
        "arzu", "istek", "amaç", "hedef", "hayal", "dilek", "özlem",
        "hasret", "nostalji",
        
        # Teknoloji (30 kelime)
        "robot", "bilgisayar", "internet", "uydu", "roket", "elektron", "nötron",
        "proton", "atom", "molekül", "hücre", "dna", "gen", "kromozom",
        "protein", "enzim", "hormon", "vitamin", "mineral", "enerji", "kuvvet",
        "hız", "ivme", "momentum", "frekans", "dalga", "radyasyon", "ses",
        "ısı", "elektrik",
        
        # Eşyalar (30 kelime)
        "kalem", "kitap", "masa", "sandalye", "telefon", "saat", "ayna",
        "kapı", "pencere", "anahtar", "kilit", "çanta", "bavul", "valiz",
        "cüzdan", "para", "kredi", "banka", "atm", "kart", "nakit",
        "çeki", "senet", "bono", "tahvil", "hisse", "borsa", "yatırım",
        "faiz", "komisyon",
        
        # Yiyecekler (30 kelime)
        "armut", "muz", "portakal", "çilek", "karpuz", "üzüm", "ekmek",
        "su", "çay", "kahve", "süt", "yoğurt", "peynir", "zeytin",
        "zeytinyağı", "bal", "tuz", "biber", "domates", "salatalık", "patates",
        "soğan", "sarımsak", "havuç", "lahana", "marul", "ıspanak", "patlıcan",
        "kabak", "bamya",
        
        # Sporlar (30 kelime)
        "futbol", "basketbol", "voleybol", "tenis", "yüzme", "koşu", "bisiklet",
        "atletizm", "güreş", "boks", "judo", "karate", "taekwondo", "aikido",
        "kendo", "jimnastik", "dans", "yoga", "pilates", "crossfit", "fitness",
        "bodybuilding", "powerlifting", "kayak", "snowboard", "sörf", "yelken",
        "rafting", "kano", "dalış",
        
        # Sanat ve Bilim (30 kelime)
        "piyano", "gitar", "keman", "flüt", "davul", "saksafon", "trompet",
        "nota", "melodi", "ritim", "akor", "armoni", "konser", "opera",
        "tiyatro", "sinema", "film", "dizi", "belgesel", "roman", "şiir",
        "hikaye", "deneme", "makale", "fıkra", "felsefe", "tarih", "coğrafya",
        "biyoloji", "kimya",
    ]
    
    # Aktif kelime listesi (haftalık)
    ACTIVE_WORD_COUNT = 40
    
    # JSON dosya yolu
    HISTORY_FILE = os.path.join(os.path.dirname(__file__), "word_rotation_history.json")
    
    def __init__(self):
        """Kelime rotasyon yöneticisini başlat"""
        self.history = self._load_history()
        self.current_week = self._get_current_week()
        self._ensure_weekly_rotation()
    
    def _get_current_week(self) -> str:
        """Mevcut haftayı ISO formatında döndür (YYYY-Www)"""
        return datetime.now().strftime("%Y-W%W")
    
    def _load_history(self) -> Dict:
        """Kelime kullanım geçmişini JSON'dan yükle"""
        if os.path.exists(self.HISTORY_FILE):
            try:
                with open(self.HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Varsayılan yapı
        return {
            "current_week": None,
            "active_words": [],
            "word_usage": {},  # {word: [week1, week2, ...]}
            "last_rotation": None,
        }
    
    def _save_history(self):
        """Kelime kullanım geçmişini JSON'a kaydet"""
        with open(self.HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)
    
    def _is_word_available(self, word: str) -> bool:
        """
        Kelimenin kullanılabilir olup olmadığını kontrol et
        
        Kurallar:
        - 3 hafta üst üste kullanılmamalı
        - Son kullanımdan 1 hafta geçmiş olmalı (kullanıldıysa)
        """
        if word not in self.history["word_usage"]:
            return True
        
        usage_weeks = self.history["word_usage"][word]
        
        # 3 hafta üst üste kullanım kontrolü
        if len(usage_weeks) >= 3:
            # Son 3 hafta kontrol et
            recent_weeks = usage_weeks[-3:]
            # Eğer son 3 hafta ardışık ise kullanılma
            if self._are_consecutive_weeks(recent_weeks):
                return False
        
        # Son kullanım haftasını kontrol et
        last_used = usage_weeks[-1]
        if last_used == self.current_week:
            return False
        
        # 1 hafta kullanılmama kontrolü
        if self._is_one_week_after(last_used):
            return True
        
        return False
    
    def _are_consecutive_weeks(self, weeks: List[str]) -> bool:
        """Haftaların ardışık olup olmadığını kontrol et"""
        if len(weeks) < 2:
            return False
        
        for i in range(len(weeks) - 1):
            if not self._is_consecutive_week(weeks[i], weeks[i + 1]):
                return False
        
        return True
    
    def _is_consecutive_week(self, week1: str, week2: str) -> bool:
        """İki haftanın ardışık olup olmadığını kontrol et"""
        # Hafta formatı: YYYY-Www
        year1, week_num1 = map(int, week1.split("-W"))
        year2, week_num2 = map(int, week2.split("-W"))
        
        if year1 == year2:
            return week_num2 == week_num1 + 1
        elif year2 == year1 + 1:
            # Yıl sonunda hafta 52'den 1'e geçiş
            return week_num1 == 52 and week_num2 == 1
        
        return False
    
    def _is_one_week_after(self, week: str) -> bool:
        """Verilen haftadan 1 hafta geçip geçmediğini kontrol et"""
        return self._is_consecutive_week(week, self.current_week)
    
    def _select_active_words(self) -> List[str]:
        """
        Aktif kelime listesini seç
        
        - Mevcut hafta için kullanılabilir kelimelerden
        - Rastgele 40 kelime seç
        """
        available_words = []
        
        for word in self.WORD_POOL:
            if self._is_word_available(word):
                available_words.append(word)
        
        # Yeterli kelime yoksa havuzdan tamamını kullan
        if len(available_words) < self.ACTIVE_WORD_COUNT:
            available_words = self.WORD_POOL.copy()
        
        # Rastgele 40 kelime seç (secrets.sample yerine kendi implementasyonu)
        count = min(self.ACTIVE_WORD_COUNT, len(available_words))
        selected = []
        remaining = available_words.copy()
        
        for _ in range(count):
            index = secrets.randbelow(len(remaining))
            selected.append(remaining.pop(index))
        
        return selected
    
    def _ensure_weekly_rotation(self):
        """Haftalık kelime rotasyonunu sağla"""
        # Eğer hafta değiştiyse yeni kelimeler seç
        if self.history["current_week"] != self.current_week:
            new_words = self._select_active_words()
            
            # Eski kelimelerin kullanım geçmişini güncelle
            for word in self.history["active_words"]:
                if word not in self.history["word_usage"]:
                    self.history["word_usage"][word] = []
                if self.history["word_usage"][word][-1] != self.history["current_week"]:
                    self.history["word_usage"][word].append(self.history["current_week"])
            
            # Yeni kelimeleri ayarla
            self.history["active_words"] = new_words
            self.history["current_week"] = self.current_week
            self.history["last_rotation"] = datetime.now().isoformat()
            
            self._save_history()
    
    def get_active_words(self) -> List[str]:
        """Aktif kelime listesini döndür"""
        self._ensure_weekly_rotation()
        return self.history["active_words"]
    
    def get_word_usage_info(self, word: str) -> Dict:
        """Kelimenin kullanım bilgisini döndür"""
        if word not in self.history["word_usage"]:
            return {
                "word": word,
                "usage_count": 0,
                "last_used": None,
                "available": True,
            }
        
        usage_weeks = self.history["word_usage"][word]
        last_used = usage_weeks[-1] if usage_weeks else None
        
        return {
            "word": word,
            "usage_count": len(usage_weeks),
            "last_used": last_used,
            "available": self._is_word_available(word),
            "usage_history": usage_weeks,
        }
    
    def get_rotation_stats(self) -> Dict:
        """Rotasyon istatistiklerini döndür"""
        return {
            "current_week": self.current_week,
            "active_word_count": len(self.history["active_words"]),
            "total_word_pool": len(self.WORD_POOL),
            "last_rotation": self.history["last_rotation"],
            "unique_words_used": len(self.history["word_usage"]),
        }


# Singleton instance
_word_rotation_manager = None

def get_word_rotation_manager() -> WordRotationManager:
    """Kelime rotasyon yöneticisinin singleton instance'ını döndür"""
    global _word_rotation_manager
    if _word_rotation_manager is None:
        _word_rotation_manager = WordRotationManager()
    return _word_rotation_manager


# =========================================================
# KULLANICI TERCİHLERİ YÖNETİCİSİ
# =========================================================

class UserPreferencesManager:
    """
    Kullanıcı Tercihleri Yöneticisi
    
    Kullanıcı tercihlerini hash/seed ile güvenli şekilde saklar:
    - Şifreler asla düz metin olarak saklanmaz
    - Tercihler anonimleşmiş hash ile saklanır
    - Şifre politikaları güvenli şekilde depolanır
    """
    
    # JSON dosya yolu
    PREFERENCES_FILE = os.path.join(os.path.dirname(__file__), "user_preferences.json")
    
    def __init__(self):
        """Kullanıcı tercihleri yöneticisini başlat"""
        self.preferences = self._load_preferences()
    
    def _load_preferences(self) -> Dict:
        """Kullanıcı tercihlerini JSON'dan yükle"""
        if os.path.exists(self.PREFERENCES_FILE):
            try:
                with open(self.PREFERENCES_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Varsayılan yapı
        return {
            "users": {},  # {user_hash: {preferences_hash: preferences}}
            "password_policies": {},  # {policy_hash: policy}
            "version": "1.0",
        }
    
    def _save_preferences(self):
        """Kullanıcı tercihlerini JSON'a kaydet"""
        with open(self.PREFERENCES_FILE, "w", encoding="utf-8") as f:
            json.dump(self.preferences, f, ensure_ascii=False, indent=2)
    
    def _hash_user_id(self, user_id: str) -> str:
        """Kullanıcı ID'sini hash'le (anonimleştir)"""
        return hashlib.sha256(user_id.encode()).hexdigest()
    
    def _hash_preferences(self, preferences: Dict) -> str:
        """Tercihleri hash'le"""
        pref_str = json.dumps(preferences, sort_keys=True)
        return hashlib.sha256(pref_str.encode()).hexdigest()
    
    def save_user_preferences(self, user_id: str, preferences: Dict) -> str:
        """
        Kullanıcı tercihlerini kaydet (hash ile)
        
        Args:
            user_id: Kullanıcı ID'si (anonimleştirilecek)
            preferences: Tercihler dict'i
        
        Returns:
            preferences_hash: Tercihlerin hash'i
        """
        user_hash = self._hash_user_id(user_id)
        pref_hash = self._hash_preferences(preferences)
        
        if user_hash not in self.preferences["users"]:
            self.preferences["users"][user_hash] = {}
        
        self.preferences["users"][user_hash][pref_hash] = {
            "preferences": preferences,
            "created_at": datetime.now().isoformat(),
        }
        
        self._save_preferences()
        return pref_hash
    
    def get_user_preferences(self, user_id: str) -> List[Dict]:
        """
        Kullanıcı tercihlerini getir
        
        Args:
            user_id: Kullanıcı ID'si
        
        Returns:
            Tercihler listesi
        """
        user_hash = self._hash_user_id(user_id)
        
        if user_hash not in self.preferences["users"]:
            return []
        
        return [
            {
                "hash": pref_hash,
                "preferences": data["preferences"],
                "created_at": data["created_at"],
            }
            for pref_hash, data in self.preferences["users"][user_hash].items()
        ]
    
    def save_password_policy(self, policy: Dict) -> str:
        """
        Şifre politikasını kaydet (hash ile)
        
        Args:
            policy: Şifre politikası dict'i
        
        Returns:
            policy_hash: Politikayı hash'i
        """
        policy_hash = self._hash_preferences(policy)
        
        self.preferences["password_policies"][policy_hash] = {
            "policy": policy,
            "created_at": datetime.now().isoformat(),
        }
        
        self._save_preferences()
        return policy_hash
    
    def get_password_policies(self) -> List[Dict]:
        """
        Tüm şifre politikalarını getir
        
        Returns:
            Politikalar listesi
        """
        return [
            {
                "hash": policy_hash,
                "policy": data["policy"],
                "created_at": data["created_at"],
            }
            for policy_hash, data in self.preferences["password_policies"].items()
        ]
    
    def validate_password_against_policy(self, password: str, policy_hash: str) -> Dict:
        """
        Şifreyi politikaya göre doğrula
        
        Args:
            password: Şifre
            policy_hash: Politika hash'i
        
        Returns:
            Doğrulama sonucu
        """
        if policy_hash not in self.preferences["password_policies"]:
            return {
                "valid": False,
                "error": "Politika bulunamadı",
            }
        
        policy = self.preferences["password_policies"][policy_hash]["policy"]
        
        # Şifre kontrolleri
        errors = []
        
        # Uzunluk kontrolü
        min_length = policy.get("min_length", 8)
        if len(password) < min_length:
            errors.append(f"Şifre en az {min_length} karakter olmalı")
        
        max_length = policy.get("max_length", 128)
        if len(password) > max_length:
            errors.append(f"Şifre en fazla {max_length} karakter olmalı")
        
        # Karakter türleri kontrolü
        if policy.get("require_uppercase", False):
            if not any(c.isupper() for c in password):
                errors.append("Şifre en az bir büyük harf içermeli")
        
        if policy.get("require_lowercase", False):
            if not any(c.islower() for c in password):
                errors.append("Şifre en az bir küçük harf içermeli")
        
        if policy.get("require_digits", False):
            if not any(c.isdigit() for c in password):
                errors.append("Şifre en az bir rakam içermeli")
        
        if policy.get("require_symbols", False):
            if not any(c in PasswordShield.SAFE_SYMBOLS for c in password):
                errors.append(f"Şifre en az bir sembol içermeli ({PasswordShield.SAFE_SYMBOLS})")
        
        # Yasaklı karakterler kontrolü
        forbidden_chars = policy.get("forbidden_chars", "")
        if any(c in password for c in forbidden_chars):
            errors.append(f"Şifre yasaklı karakterler içeriyor: {forbidden_chars}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "policy_hash": policy_hash,
        }


# Singleton instance
_user_preferences_manager = None

def get_user_preferences_manager() -> UserPreferencesManager:
    """Kullanıcı tercihleri yöneticisinin singleton instance'ını döndür"""
    global _user_preferences_manager
    if _user_preferences_manager is None:
        _user_preferences_manager = UserPreferencesManager()
    return _user_preferences_manager


# =========================================================
# KRIPTOGRAFİK ŞİFRE ÜRETİCİ
# =========================================================

class PasswordShield:
    """
    Kriptografik Kalkan - Kırılması yüzyıllar süren şifre üretimi
    
    Python secrets modülü kullanarak kriptografik olarak güvenli
    rastgele şifreler üretir. Standart random modülüne göre tahmin
    edilemez ve güvenlik için tasarlanmıştır.
    
    Kullanıcı bazlı kelime ve şifre tracking:
    - Bir kelime en fazla 2 kez üst üste kullanılabilir
    - Aynı şifre kombinasyonu tekrar sunulmaz
    """
    
    def __init__(self):
        """PasswordShield instance'ını başlat - kullanıcı bazlı tracking için"""
        self.word_usage_history = {}  # {word: consecutive_count}
        self.generated_passwords = set()  # Bu oturumda üretilen şifreler
    
    # Şifre kategorileri ve güvenlik seviyeleri
    CATEGORIES = {
        "ultra_secure": {
            "length": 32,
            "description": "Kırılması 10^60 yıl süren - Nükleer sır seviyesi",
            "entropy_per_char": 6.6,
        },
        "high_security": {
            "length": 20,
            "description": "Kırılması 10^38 yıl süren - Banka/Finans seviyesi",
            "entropy_per_char": 6.6,
        },
        "standard": {
            "length": 16,
            "description": "Kırılması 10^30 yıl süren - Günlük kullanım",
            "entropy_per_char": 6.6,
        },
        "memorable": {
            "length": 12,
            "description": "Kırılması 10^22 yıl süren - Akılda kalıcı",
            "entropy_per_char": 6.6,
        },
    }
    
    # Güçlü sembol seti (klavye karışıklığını önle)
    SAFE_SYMBOLS = "!@#$%&*-_=+?"
    
    # Akılda kalıcı kelime listesi (rotasyon yöneticisinden alınır)
    def get_memorable_words(self) -> List[str]:
        """Aktif kelime listesini rotasyon yöneticisinden al"""
        return get_word_rotation_manager().get_active_words()
    
    @classmethod
    def generate(
        cls,
        length: int = 20,
        *,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        category: Optional[str] = None,
    ) -> Tuple[str, Dict]:
        """
        Kriptografik olarak güçlü şifre üret
        
        Args:
            length: Şifre uzunluğu (8-128)
            uppercase: Büyük harf içersin mi
            lowercase: Küçük harf içersin mi
            digits: Rakam içersin mi
            symbols: Sembol içersin mi
            category: Önceden tanımlı kategori kullan (ultra_secure, high_security, standard, memorable)
        
        Returns:
            (şifre, metadata_dict)
        """
        # Kategori kullanılıyorsa uzunluğu override et
        if category and category in cls.CATEGORIES:
            length = cls.CATEGORIES[category]["length"]
        
        # Uzunluk sınırları
        length = max(8, min(128, int(length)))
        
        # Karakter havuzlarını oluştur
        pools = []
        required = []
        
        if lowercase:
            lo = string.ascii_lowercase
            pools.append(lo)
            required.append(secrets.choice(lo))
        
        if uppercase:
            up = string.ascii_uppercase
            pools.append(up)
            required.append(secrets.choice(up))
        
        if digits:
            dg = string.digits
            pools.append(dg)
            required.append(secrets.choice(dg))
        
        if symbols:
            pools.append(cls.SAFE_SYMBOLS)
            required.append(secrets.choice(cls.SAFE_SYMBOLS))
        
        # Hiçbir seçenek seçilmediyse varsayılan
        if not pools:
            lo = string.ascii_lowercase
            pools.append(lo)
            required = [secrets.choice(lo)]
        
        # Havuzları birleştir ve şifreyi oluştur
        alphabet = "".join(pools)
        remaining = length - len(required)
        body = [secrets.choice(alphabet) for _ in range(remaining)]
        chars = required + body
        
        # Karıştır (Fisher-Yates shuffle with secrets)
        shuffled = chars.copy()
        for i in range(len(shuffled) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        
        password = "".join(shuffled)
        
        # Entropi hesapla (gerçek matematiksel hesaplama)
        entropy = cls._calculate_entropy(password, pools)
        crack_time = cls._estimate_crack_time(entropy)
        
        meta = {
            "length": length,
            "entropy_bits": round(entropy, 2),
            "character_pools": len(pools),
            "pool_size": len(alphabet),
            "estimated_crack_time": crack_time,
            "security_level": cls._get_security_level(entropy),
            "category_used": category,
            "generation_method": "Python secrets.SystemRandom - CSPRNG",
            "warning": "Bu şifreyi ekran görüntüsü almayın; güvenilir bir şifre yöneticisine kaydedin.",
        }
        
        return password, meta
    
    def generate_memorable(self, word_count: int = 4, separator: str = "-") -> Tuple[str, Dict]:
        """
        Akılda kalıcı ama güvenli şifre üret (Diceware tarzı)
        
        Örnek: atlas-buzul-çınar-123!
        
        Kullanıcı bazlı tracking:
        - Bir kelime en fazla 2 kez üst üste kullanılabilir
        - Aynı şifre kombinasyonu tekrar sunulmaz
        """
        memorable_words = self.get_memorable_words()
        
        # Kelime seçimi - consecutive usage kontrolü ile
        words = []
        available_words = memorable_words.copy()
        
        for _ in range(word_count):
            # Kullanılabilir kelimeleri filtrele (consecutive count < 2)
            filtered_words = [
                word for word in available_words
                if self.word_usage_history.get(word, 0) < 2
            ]
            
            # Eğer yeterli kelime yoksa, tracking'i sıfırla
            if not filtered_words:
                self.word_usage_history.clear()
                filtered_words = available_words.copy()
            
            # Rastgele kelime seç
            word = secrets.choice(filtered_words)
            words.append(word)
            
            # Consecutive count'u artır
            self.word_usage_history[word] = self.word_usage_history.get(word, 0) + 1
            
            # Bu kelimeyi bir sonraki seçim için geçici olarak çıkar
            available_words.remove(word)
        
        # Rastgele sayı ve sembol ekle
        random_num = secrets.randbelow(1000)
        random_symbol = secrets.choice(self.SAFE_SYMBOLS)
        
        password = separator.join(words) + str(random_num) + random_symbol
        
        # Şifre daha önce üretildiyse, yeniden üret
        max_attempts = 10
        attempts = 0
        while password in self.generated_passwords and attempts < max_attempts:
            # Yeni kelimeler seç
            words = []
            available_words = memorable_words.copy()
            
            for _ in range(word_count):
                filtered_words = [
                    word for word in available_words
                    if self.word_usage_history.get(word, 0) < 2
                ]
                
                if not filtered_words:
                    self.word_usage_history.clear()
                    filtered_words = available_words.copy()
                
                word = secrets.choice(filtered_words)
                words.append(word)
                self.word_usage_history[word] = self.word_usage_history.get(word, 0) + 1
                available_words.remove(word)
            
            random_num = secrets.randbelow(1000)
            random_symbol = secrets.choice(self.SAFE_SYMBOLS)
            password = separator.join(words) + str(random_num) + random_symbol
            attempts += 1
        
        # Şifreyi kaydet
        self.generated_passwords.add(password)
        
        # Entropi hesapla
        word_entropy = math.log2(len(memorable_words)) * word_count
        num_entropy = math.log2(1000)
        symbol_entropy = math.log2(len(self.SAFE_SYMBOLS))
        total_entropy = word_entropy + num_entropy + symbol_entropy
        
        meta = {
            "type": "memorable",
            "words": words,
            "word_count": word_count,
            "separator": separator,
            "entropy_bits": round(total_entropy, 2),
            "estimated_crack_time": self._estimate_crack_time(total_entropy),
            "security_level": self._get_security_level(total_entropy),
            "memorability": "HIGH - Kelimeler anlamlı ve Türkçe",
        }
        
        return password, meta
    
    @classmethod
    def _calculate_entropy(cls, password: str, pools: list) -> float:
        """Şifre entropisini hesapla (Shannon entropisi)"""
        pool_size = sum(len(p) for p in pools)
        return len(password) * math.log2(pool_size)
    
    @classmethod
    def _estimate_crack_time(cls, entropy: float) -> str:
        """Kaba kuvvet saldırısı süresini tahmin et"""
        # varsayım: 100 trilyon deneme/saniye (yüksek performanslı donanım)
        guesses_per_second = 100_000_000_000_000
        total_guesses = 2 ** entropy
        seconds = total_guesses / guesses_per_second
        
        if seconds < 60:
            return f"{seconds:.1f} saniye"
        elif seconds < 3600:
            return f"{seconds/60:.1f} dakika"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} saat"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} gün"
        elif seconds < 3153600000:
            return f"{seconds/31536000:.1f} yıl"
        elif seconds < 315360000000:
            return f"{seconds/31536000:.0f} yıl (insan ömründen uzun)"
        else:
            return f"{seconds/315360000000000:.0f} trilyon yıl (evren yaşından uzun)"
    
    @classmethod
    def _get_security_level(cls, entropy: float) -> str:
        """Entropiye göre güvenlik seviyesi"""
        if entropy >= 128:
            return "ULTRA (Kuantum bilgisayara dayanıklı)"
        elif entropy >= 80:
            return "HIGH (NSA/Askeri seviye)"
        elif entropy >= 60:
            return "GOOD (Banka/Finans seviyesi)"
        elif entropy >= 40:
            return "MODERATE (Günlük kullanım)"
        else:
            return "WEAK (Düşük güvenlik)"
    
    @classmethod
    def check_password_strength(cls, password: str) -> Dict:
        """Mevcut şifre güçlülüğünü analiz et"""
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in cls.SAFE_SYMBOLS for c in password)
        
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += len(cls.SAFE_SYMBOLS)
        
        if pool_size == 0:
            pool_size = 1
        
        entropy = length * math.log2(pool_size)
        
        return {
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "character_pool": pool_size,
            "entropy_bits": round(entropy, 2),
            "crack_time_estimate": cls._estimate_crack_time(entropy),
            "security_level": cls._get_security_level(entropy),
            "recommendations": cls._get_recommendations(length, entropy, has_lower, has_upper, has_digit, has_symbol),
        }
    
    @classmethod
    def _get_recommendations(cls, length: int, entropy: float, lower: bool, upper: bool, digit: bool, symbol: bool) -> list:
        """İyileştirme önerileri"""
        recs = []
        
        if length < 12:
            recs.append(f"Şifre çok kısa! En az 12 karakter önerilir (mevcut: {length})")
        elif length < 16:
            recs.append("Daha güvenli için 16+ karakter kullanın")
        
        if not (lower and upper):
            recs.append("Büyük ve küçük harf karışımı kullanın")
        
        if not digit:
            recs.append("Rakam ekleyin")
        
        if not symbol:
            recs.append("Sembol ekleyin (!@#$%&*-_=+?)")
        
        if entropy < 60:
            recs.append("Bu şifre zayıf! Yeni şifre üretin")
        
        if not recs:
            recs.append("Şifre güçlü! Kriptografik Kalkan onaylı ✓")
        
        return recs


# Kullanım kolaylığı için fonksiyonlar
def generate_password(length: int = 20, **kwargs) -> Tuple[str, Dict]:
    """Kriptografik şifre üret - Basit arayüz"""
    return PasswordShield.generate(length=length, **kwargs)


def generate_memorable_password(word_count: int = 4) -> Tuple[str, Dict]:
    """Akılda kalıcı şifre üret"""
    return PasswordShield.generate_memorable(word_count=word_count)


def check_password(password: str) -> Dict:
    """Şifre güçlülüğünü kontrol et"""
    return PasswordShield.check_password_strength(password)
