"""
06 - Security Plugin Module (AegisNexus Shield)
Chrome uzantısı — 3 katmanlı phishing/URL güvenlik tarama sistemi

Bu modül bir Python backend modülü değil, AegisNexus platformunun
Chrome tarayıcı uzantısı (extension) bileşenidir. Python tarafında
doğrudan çalıştırılabilir kod içermez; uzantının sunucu tarafı
gereksinimleri ve entegrasyon noktaları bu dosyada belgelenmiştir.

============================================================
UZANTI MİMARİSİ
============================================================

Katman 1 — Local (0ms gecikme):
  - heuristic.js    : URL risk skorlaması (14 kural, 0-100 puan)
  - bloom_filter.js : Bilinen şüpheli domain'ler için Bloom filtresi

Katman 2 — External API (~3-5sn):
  - dns_check.js    : Cloudflare Security DNS + Quad9 DNS-over-HTTPS
  - gsb_check.js    : Google Safe Browsing v4 Lookup API

Katman 3 — AegisNexus Sunucu:
  - service_worker.js → POST /api/v2/phishing/check-url

============================================================
DOSYA YAPISİ
============================================================

security_plugin/
├── __init__.py              ← Bu dosya
├── manifest.json            ← Manifest V3 tanımı
├── README.md                ← Kurulum/test/paketleme kılavuzu
├── background/
│   └── service_worker.js    ← Ana kontrol merkezi (cache, mesaj, alarm)
├── content/
│   └── content_script.js    ← Sayfa uyarı banner'ı (Shadow DOM)
├── popup/
│   ├── popup.html           ← Popup arayüzü
│   ├── popup.css            ← Koyu tema stilleri
│   └── popup.js             ← Popup mantığı
├── options/
│   ├── options.html         ← Ayarlar sayfası (3 sekme)
│   ├── options.css          ← Options stilleri
│   └── options.js           ← Options mantığı
└── utils/
    ├── heuristic.js         ← URL risk analiz motoru
    ├── bloom_filter.js      ← Bloom filtresi implementasyonu
    ├── dns_check.js         ← DNS-over-HTTPS sorgulama
    ├── gsb_check.js         ← Google Safe Browsing API istemcisi
    ├── field_classifier.js  ← Form alan tipi sınıflandırıcı
    ├── form_detector.js     ← Form risk analiz motoru
    └── whitelist.js         ← Whitelist yönetimi (personal + global)

============================================================
SUNUCU TARAFI GEREKSİNİMLERİ (AegisNexus Backend)
============================================================

Uzantının çalışabilmesi için AegisNexus backend'inde şu endpoint'ler
bulunmalıdır:

1. POST /api/v2/phishing/check-url
   - Body: { "url": str, "force_fresh": bool }
   - Yanıt: { "score": int, "risk_level": str, "details": dict }
   - Katman 3 derin analiz için kullanılır

2. GET /api/v2/phishing/export-domains
   - Yanıt: düz text, her satır bir domain
   - Bloom filtresi güncellemesi için (24 saatte bir)

3. POST /api/v2/phishing/report
   - Body: { "url": str, "reported_by": "extension", "reason": str }
   - Rate limit: 10 req/dk (IP bazlı)
   - Kullanıcı phishing raporu gönderir

4. POST /api/v2/phishing/report-form
   - Body: { "url": str, "domain": str, "form_data": { "action_url": str, "field_types": [str], "risk_score": int, "flags": [str] } }
   - Rate limit: 20 req/dk (IP bazlı)
   - Form tespit raporları `app.models.PhishingForm` tablosuna yazılır

5. GET /api/v2/whitelist/global
   - Yanıt: { "domains": [str] }
   - Global güvenilir domain listesi (aylık yenilenir)

6. POST /api/v2/whitelist/verify-user
   - Body: { "domains": [str] }
   - Yanıt: { "results": [{ "domain": str, "is_safe": bool, "reason": str }] }
   - Personal whitelist doğrulama

============================================================
CHROME API GEREKSİNİMLERİ
============================================================

Permissions:
  - tabs            : Aktif tab URL'sini okuma
  - storage         : local/session veri saklama (cache, whitelist, ayarlar)
  - webNavigation   : Sayfa navigasyon event'larını dinleme
  - webRequest      : İstekleri dinleme (main_frame)
  - alarms          : Periyodik görevler (bloom_refresh, whitelist_refresh)
  - notifications   : Risk bildirimleri

Host Permissions:
  - <all_urls>      : Tüm sitelerde content script çalıştırma

============================================================
DAHİLİ DEPOLAMA ANAHTARLARI (chrome.storage.local)
============================================================

  api_base_url           : AegisNexus API sunucu adresi
  gsb_api_key            : Google Safe Browsing API anahtarı
  aegis_key              : X-AegisNexus-Key (opsiyonel auth)
  whitelist              : Personal whitelist [{ domain, added_at }]
  global_whitelist       : Global whitelist [str]
  global_whitelist_updated : Son güncelleme tarihi (ISO)
  domain_cache           : { domain: { result, timestamp } } (24h TTL)
  bloom_data             : Bloom filtresi bit array verisi
  stats                  : { scanned, risky, notifications, lastRiskUrl }
  lastScan               : Son tarama sonucu
"""

# Bu modül Python çalıştırılabilir kodu içermez.
# Chrome uzantısı bağımsız olarak yüklenir ve çalışır.
