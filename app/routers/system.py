from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["system"])


@router.get("/api/health")
def health():
    return {
        "durum": "çalışıyor",
        "servis_adi": get_settings()["app_name"],
        "aciklama": "API ayakta; veritabanı bağlantısı bu uçtan doğrulanmaz.",
    }


@router.get("/api/meta")
def meta():
    """Sunum ve entegrasyon için modül kartları (Türkçe açıklamalı)."""
    return {
        "urun": get_settings()["app_name"],
        "moduller": [
            {
                "kimlik": "threat_db",
                "baslik": "Tehdit veritabanı",
                "aciklama": "Şüpheli bağlantıları yerel liste ve dış akışlarla karşılaştırır; çok katmanlı skor ve açıklamalar üretir.",
            },
            {
                "kimlik": "infra",
                "baslik": "Altyapı denetimi",
                "aciklama": "İzin verilen bir hostname için sertifika, yönlendirme ve birkaç yaygın port üzerinde özet güvenlik görünümü sunar.",
            },
            {
                "kimlik": "breach",
                "baslik": "Sızıntı radarı",
                "aciklama": "Have I Been Pwned API ile e-postanın bilinen halka açık sızıntılarda geçip geçmediğini kontrol eder; Türkçe özet metin üretir.",
            },
            {
                "kimlik": "shield",
                "baslik": "Şifre kalkanı",
                "aciklama": "Tahmin edilmesi zor, rastgele parolalar üretir (Python secrets); kullanıcıya şifre yöneticisi kullanması önerilir.",
            },
            {
                "kimlik": "honeypot",
                "baslik": "Tuzak sayfası (demo)",
                "aciklama": "Yalnızca bu uygulamaya gelen istekleri kaydeden eğitim amaçlı sahte arayüz; kötüye kullanım için tasarlanmamıştır.",
            },
        ],
        "gelecek_plani_v2": [
            "Tarayıcı eklentisi ile anlık uyarı (Chrome / Safari)",
            "WhatsApp veya Telegram üzerinden şüpheli link ihbarı ve otomatik özet",
            "USOM vb. resmi kurumlara koşullara uygun otomatik ihbar köprüsü",
        ],
        "toplumsal_etki": [
            "Karmaşık teknik dil yerine anlaşılır uyarılarla yaşlı ve savunmasız kullanıcıları korumaya yardım",
            "Sızıntı farkındalığı ile şifre değişimi ve çok faktörlü doğrulamayı teşvik",
            "Bütçesi kısıtlı KOBİ’lerin domain ve tehdit kontrolüne ücretsiz erişim",
        ],
        "not": "Bu JSON; jüri, dokümantasyon veya başka sistemlerle entegrasyon için makine tarafından okunabilir özet sağlar.",
    }
