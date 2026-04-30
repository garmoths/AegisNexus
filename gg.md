# gg.md — Durum Raporu

## Yapılanlar
- `threat_intel.py` içinden URLScan entegrasyonu kaldırıldı (fonksiyonlar + skor etkisi + ilgili bloklar temizlendi).
- `modules/phishing_detector/screenshot_analyzer.py` oluşturuldu:
  - Playwright Chromium ile headless full-page screenshot alıyor.
  - PNG -> base64 çevirip **Google Gemini Vision** (`gemini-2.0-flash`) çağrısı yapıyor.
  - Beklenen çıktı şemasını döndürüyor: `risk_score`, `risk_level`, `verdict`, `screenshot_analysis`, `threat_indicators`, `recommendation`.
  - Hata durumunda fallback dönüyor (`risk_score=50`, `risk_level=UNKNOWN`, `verdict=Ekran görüntüsü alınamadı`).
- **Claude → Gemini migrasyonu tamamlandı:**
  - `ANTHROPIC_API_KEY` → `GEMINI_API_KEY`
  - `claude-sonnet-4-20250514` → `gemini-2.0-flash`
  - `anthropic` package → `google.generativeai` package
  - Tüm Claude/Anthropic referansları kod ve dokümanlardan temizlendi.
- `threat_intel.py` içinde screenshot analyzer entegrasyonu yapıldı:
  - `run_threat_intelligence(..., http_meta, page_text)` akışına bağlandı.
  - Screenshot `risk_score` toplam cezaya %40 ağırlıkla yansıtıldı.
  - `threat_indicators` IOC yazım akışına aktarıldı.
- **Yeni Threat Intel kaynakları entegre edildi:**
  - Spamhaus Intel API (login-based JWT auth, std tier: 150 req/s, 200K req/saat)
  - abuse.ch URLhaus (`Auth-Key` header, URL kara liste sorgulama)
  - abuse.ch ThreatFox (`Auth-Key` header, IOC sorgulama + toplu ingest)
  - Paralel sorgulama (ThreadPoolExecutor, 4 worker)
  - SQLite cache (12 saat TTL)
- **Celery Beat schedule güncellendi:**
  - `fetch_threatfox_iocs` — Her 4 saatte bir ThreatFox IOC çekme
  - `fetch_spamhaus_iocs` — Her 6 saatte bir Spamhaus sorgulama
  - `update_phishing_feeds` — Her 2 saatte tüm kaynaklardan phishing URL çekme
  - `refresh_ip_blacklists` — Günde 1 kez IP blacklist güncelleme
- **AbuseIPDB API collector'dan kaldırıldı** (free plan: 1000 check/gün limiti aşıldığı için, local blacklist kullanılıyor).
- Dokümanlar güncellendi:
  - `docs/04-TEKNIK-DETAYLAR/ENVIRONMENT_VARIABLES.md`
  - `docs/04-TEKNIK-DETAYLAR/API_KEY_ROTATION.md`
  - `docs/04-TEKNIK-DETAYLAR/API_INTEGRATION_GUIDE.md`
  - `docs/03-DEPLOYMENT/PHISHING_TROUBLESHOOTING_RUNBOOK.md`
  - `docs/00-ANA-DOKUMANLAR/MODUL_ACIKLAMASI.md`
- Kod GitHub `main` branch'e pushlandı.
- Sunucuda (`/var/www/aegis_nexus`) güncel kod çekildi ve test edildi.

## Test Sonuçları

### Sunucu (Frankfurt 104.248.45.198)
- ✅ Spamhaus: Login auth + IP/domain query çalışıyor
- ✅ URLhaus: `Auth-Key` header ile URL query çalışıyor (google.com → clean)
- ✅ ThreatFox: `Auth-Key` header ile IOC query çalışıyor (google.com → found)
- ✅ ThreatFox ingest: 470 IOC normalize edildi, 469 PostgreSQL'e yazıldı
- ✅ URLhaus CSV: 3000 URL alındı
- ✅ Celery worker + beat çalışıyor
- ✅ Screenshot analyzer: Gemini import OK

### Yapılması Gerekenler
1. Sunucuda `.env` dosyasına `GEMINI_API_KEY=AIza...` ekle (screenshot analizinin gerçek çalışması için).
2. `force_fresh=true` ile `check-url` çağır ve gerçek Gemini analiz çıktısı geldiğini doğrula.
3. Opsiyonel: dependency setini stabilize etmek için server venv'i temizleyip `pip install -r requirements.txt` ile yeniden kur.

## Not
- Screenshot pipeline aktif; `GEMINI_API_KEY` olmadan güvenli fallback modunda çalışıyor.
- Tüm threat intel kaynakları (Spamhaus, URLhaus, ThreatFox) API key'leri ile doğrulanmış ve çalışıyor.
- Sürüm: 2.1 (Threat Intel Integration + Gemini Vision)
