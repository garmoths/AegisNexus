"""
Honeypot Engine - Dolandırıcı avlama motoru
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class HoneypotSession:
    """Bir dolandırıcı oturumunu temsil eder"""
    session_id: str
    ip_address: str
    user_agent: str
    start_time: datetime
    last_activity: datetime
    interaction_count: int = 0
    time_wasted_seconds: float = 0.0
    captured_data: Dict = None
    threat_score: int = 0
    
    def __post_init__(self):
        if self.captured_data is None:
            self.captured_data = {}
    
    def add_interaction(self, action: str, data: dict = None):
        """Yeni etkileşim kaydet"""
        self.interaction_count += 1
        self.last_activity = datetime.utcnow()
        if data:
            self.captured_data[action] = data
        # Her etkileşimde zaman kaybı artar
        self.time_wasted_seconds += 5.0  # Bot cevap bekleme süresi
    
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "interaction_count": self.interaction_count,
            "time_wasted_seconds": round(self.time_wasted_seconds, 2),
            "captured_data_keys": list(self.captured_data.keys()),
            "threat_score": self.threat_score,
        }


@dataclass
class IOCRecord:
    """Tek bir IOC girdisinin toplu görünümü."""
    ioc_type: str
    value: str
    source: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": round(self.confidence, 2),
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "context": self.context or {},
        }


class HoneypotEngine:
    """
    Aktif savunma motoru - Dolandırıcıları oyalayan ve bilgi toplayan sistem
    """
    
    # Banka login sayfalarına benzeyen tuzak içerikleri
    DECOY_TEMPLATES = {
        "bank_login": {
            "title": "Ziraat Bankası - İnternet Şubesi",
            "fields": ["Müşteri/TCKN", "Şifre", "Onay Kodu"],
            "delay_response": True,
            "fake_errors": ["Şifre hatalı, tekrar deneyin", "Onay kodu gönderildi (1:59)", "Hesap kilitlendi, müşteri hizmetlerini arayın"],
        },
        "social_login": {
            "title": "Instagram - Giriş",
            "fields": ["Telefon, e-posta veya kullanıcı adı", "Şifre"],
            "delay_response": True,
            "fake_errors": ["Şifren yanlış", "Hesabın askıya alındı", "Doğrulama kodu gönderildi"],
        },
        "shopping_login": {
            "title": "Trendyol - Giriş Yap",
            "fields": ["E-posta", "Şifre"],
            "delay_response": True,
            "fake_errors": ["E-posta veya şifre hatalı", "Hesabınızı doğrulayın", "Güvenlik kodu gönderildi"],
        },
    }
    
    def __init__(self):
        self.active_sessions: Dict[str, HoneypotSession] = {}
        self.captured_ips: set = set()
        self.total_time_wasted: float = 0.0
        self.total_sessions: int = 0
        self.ioc_store: Dict[str, IOCRecord] = {}

    @staticmethod
    def _flatten_payload_values(payload: Any) -> List[str]:
        """Nested payload icindeki tum string degerleri toplar."""
        values: List[str] = []
        if payload is None:
            return values

        if isinstance(payload, dict):
            for k, v in payload.items():
                values.extend(HoneypotEngine._flatten_payload_values(k))
                values.extend(HoneypotEngine._flatten_payload_values(v))
            return values

        if isinstance(payload, list):
            for item in payload:
                values.extend(HoneypotEngine._flatten_payload_values(item))
            return values

        if isinstance(payload, (str, int, float, bool)):
            values.append(str(payload))

        return values

    def _upsert_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float,
        context: Optional[Dict[str, Any]] = None,
    ) -> IOCRecord:
        """IOC kaydini ekler veya mevcut kaydi gunceller."""
        key = f"{ioc_type}:{value.lower()}"
        now = datetime.utcnow()
        existing = self.ioc_store.get(key)

        if existing:
            existing.last_seen = now
            existing.count += 1
            existing.confidence = max(existing.confidence, confidence)
            if context:
                merged = dict(existing.context or {})
                merged.update(context)
                existing.context = merged
            return existing

        record = IOCRecord(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
            context=context or {},
        )
        self.ioc_store[key] = record
        return record

    def extract_iocs(self, payload: Optional[Dict[str, Any]] = None, raw_text: str = "") -> List[Dict[str, Any]]:
        """Payload ve serbest metinden temel IOC tiplerini cikarir."""
        corpus_parts = self._flatten_payload_values(payload)
        if raw_text:
            corpus_parts.append(raw_text)
        corpus = "\n".join(corpus_parts)

        if not corpus.strip():
            return []

        patterns = {
            "url": (r"https?://[^\s\"'<>]+", 0.95),
            "email": (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", 0.9),
            "ipv4": (r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 0.85),
            "domain": (r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", 0.75),
            "sha256": (r"\b[a-fA-F0-9]{64}\b", 0.95),
            "md5": (r"\b[a-fA-F0-9]{32}\b", 0.8),
        }

        found: Dict[str, Dict[str, Any]] = {}
        for ioc_type, (pattern, confidence) in patterns.items():
            for match in re.finditer(pattern, corpus):
                value = match.group(0).strip().rstrip(",.;")
                key = f"{ioc_type}:{value.lower()}"
                if key not in found:
                    found[key] = {
                        "type": ioc_type,
                        "value": value,
                        "confidence": confidence,
                    }

        return list(found.values())

    def collect_iocs(
        self,
        source: str,
        payload: Optional[Dict[str, Any]] = None,
        raw_text: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """IOC cikarimi yapip collector store'a ekler."""
        extracted = self.extract_iocs(payload=payload, raw_text=raw_text)
        collected: List[Dict[str, Any]] = []

        for item in extracted:
            record = self._upsert_ioc(
                ioc_type=item["type"],
                value=item["value"],
                source=source,
                confidence=item["confidence"],
                context=context,
            )
            collected.append(record.to_dict())

        return collected

    def list_iocs(self, ioc_type: Optional[str] = None, limit: int = 100, min_count: int = 1) -> List[Dict[str, Any]]:
        """Toplanan IOC kayitlarini filtreleyip listeler."""
        records = [r for r in self.ioc_store.values() if r.count >= max(min_count, 1)]
        if ioc_type:
            records = [r for r in records if r.ioc_type == ioc_type]

        records.sort(key=lambda r: (r.count, r.last_seen), reverse=True)
        return [r.to_dict() for r in records[: max(limit, 1)]]

    def ioc_stats(self) -> Dict[str, Any]:
        """IOC collector ozet istatistikleri."""
        by_type: Dict[str, int] = {}
        total_hits = 0
        for record in self.ioc_store.values():
            by_type[record.ioc_type] = by_type.get(record.ioc_type, 0) + 1
            total_hits += record.count

        return {
            "unique_iocs": len(self.ioc_store),
            "total_ioc_hits": total_hits,
            "ioc_types": by_type,
        }
    
    def create_session(self, ip: str, user_agent: str, decoy_type: str = "bank_login") -> HoneypotSession:
        """Yeni tuzak oturumu oluştur"""
        session_id = f"HONEY-{int(time.time())}-{hash(ip) % 10000}"
        session = HoneypotSession(
            session_id=session_id,
            ip_address=ip,
            user_agent=user_agent,
            start_time=datetime.utcnow(),
            last_activity=datetime.utcnow(),
        )
        self.active_sessions[session_id] = session
        self.captured_ips.add(ip)
        self.total_sessions += 1
        return session
    
    def get_decoy_page(self, decoy_type: str = "bank_login") -> dict:
        """Tuzak sayfa şablonunu getir"""
        template = self.DECOY_TEMPLATES.get(decoy_type, self.DECOY_TEMPLATES["bank_login"])
        return {
            "type": decoy_type,
            "title": template["title"],
            "fields": template["fields"],
            "requires_delay": template["delay_response"],
        }
    
    def process_interaction(self, session_id: str, action: str, payload: dict = None) -> dict:
        """Dolandırıcı etkileşimini işle"""
        session = self.active_sessions.get(session_id)
        if not session:
            return {"error": "Oturum bulunamadı", "status": "expired"}
        
        # Oyalama taktikleri
        response_delay = 2.0  # Saniye cinsinden yapay gecikme
        fake_error = None
        
        if action == "login_attempt":
            session.add_interaction("login_attempt", payload)
            fake_error = "Hatalı şifre. Tekrar deneyin. (Kalan deneme: 2)"
            session.threat_score += 10
        
        elif action == "otp_request":
            session.add_interaction("otp_request", payload)
            fake_error = "Onay kodu gönderildi. Lütfen 2 dakika içinde girin."
            response_delay = 5.0  # Daha uzun bekleme
        
        elif action == "password_reset":
            session.add_interaction("password_reset", payload)
            fake_error = "Hesap doğrulaması gerekiyor. Müşteri temsilcisine bağlanıyorsunuz..."
            response_delay = 8.0  # En uzun bekleme
            session.threat_score += 15
        
        # Toplam zaman kaybını güncelle
        self.total_time_wasted += response_delay
        session.time_wasted_seconds += response_delay

        collected_iocs = self.collect_iocs(
            source=f"honeypot:{action}",
            payload=payload,
            context={
                "session_id": session_id,
                "action": action,
                "threat_score": session.threat_score,
            },
        )
        
        return {
            "session_id": session_id,
            "action": action,
            "fake_error": fake_error,
            "delay_seconds": response_delay,
            "time_wasted_total": round(session.time_wasted_seconds, 2),
            "threat_score": session.threat_score,
            "ioc_detected": len(collected_iocs),
            "status": "active",
        }
    
    def get_session_stats(self, session_id: str = None) -> dict:
        """Oturum istatistiklerini getir"""
        if session_id and session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            return {
                "session": session.to_dict(),
                "estimated_victims_saved": round(session.time_wasted_seconds / 300, 2),  # 5 dakika = 1 kurban
                "money_saved_try": round(session.time_wasted_seconds / 300 * 5000, 2),  # Tahmini
            }
        
        # Tüm istatistikler
        all_sessions = [s.to_dict() for s in self.active_sessions.values()]
        total_interactions = sum(s.interaction_count for s in self.active_sessions.values())
        
        return {
            "total_sessions": self.total_sessions,
            "active_sessions": len(self.active_sessions),
            "unique_ips": len(self.captured_ips),
            "total_time_wasted_seconds": round(self.total_time_wasted, 2),
            "total_interactions": total_interactions,
            "estimated_victims_saved": round(self.total_time_wasted / 300, 2),
            "estimated_money_saved_try": round(self.total_time_wasted / 300 * 5000, 2),
            "ioc": self.ioc_stats(),
            "recent_sessions": all_sessions[-10:] if all_sessions else [],
        }
    
    def close_session(self, session_id: str) -> dict:
        """Oturumu kapat ve raporla"""
        session = self.active_sessions.pop(session_id, None)
        if session:
            return {
                "session_closed": True,
                "final_stats": session.to_dict(),
                "impact": {
                    "time_wasted_minutes": round(session.time_wasted_seconds / 60, 2),
                    "potential_victims_protected": round(session.time_wasted_seconds / 300, 2),
                }
            }
        return {"error": "Oturum zaten kapalı"}


# Global engine instance
honeypot_engine = HoneypotEngine()
