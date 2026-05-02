# AegisNexus Shield — Chrome Eklentisi (3 Katmanlı Doğrulama)

AegisNexus backend'ine entegre 3 katmanlı URL doğrulama sistemi ile Chrome eklentisi ve sunucu tarafı endpoint'lerinin oluşturulması.

---

## Klasör Yapısı

```
aegisnexus-extension/
├── manifest.json
├── background/
│   └── service_worker.js
├── content/
│   └── content_script.js
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── utils/
│   ├── heuristic.js
│   ├── bloom_filter.js
│   ├── dns_check.js
│   └── gsb_check.js
├── assets/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── data/
    └── bloom_cache.json
```

---

## Uygulama Adımları

### 01 — manifest.json (Manifest V3)
- `manifest_version: 3`, `name: "AegisNexus Shield"`, `version: "1.0.0"`
- Permissions: `tabs`, `storage`, `webNavigation`, `webRequest`, `alarms`, `notifications`
- `host_permissions: ["<all_urls>"]`
- Background: `service_worker.js`, Content scripts: `content_script.js` (`document_start`), Action: `popup.html`

### 02 — utils/heuristic.js (Katman 1 — Tamamen Local)
- `analyzeURL(url)` → 0-100 risk skoru + flags + risk_level
- Kontroller ve puanlar:
  - IP adresi URL'de: +25
  - Şüpheli TLD (.xyz, .top, .tk, .ml, .ga, .cf, .gq, .pw, .cc): +20
  - URL uzunluğu >75: +15
  - @ işareti: +20
  - Subdomain >3: +15
  - Marka subdomain spoof (paypal, google, microsoft, apple, amazon, facebook, instagram, netflix, twitter, linkedin, bankofamerica, wellsfargo, chase, steam, discord, binance, coinbase): +30
  - Hex encoding (%XX): +10
  - Double encoding (%25XX): +20
  - Homograph karakter (Kiril/Yunan): +25
  - HTTP + login/password/account/verify/secure kelimesi: +20
  - Şüpheli kelimeler (secure, login, verify, update, confirm, account, banking, signin): her biri +5 (max +20)
  - Standart dışı port (80, 443 hariç): +15
  - Nokta sayısı >5: +10
- Sonuç: `{ score, flags, risk_level: "SAFE|LOW|MEDIUM|HIGH|CRITICAL" }`

### 03 — utils/bloom_filter.js (Katman 1 — Local kötü domain filtresi)
- `BloomFilter(size, hashCount)` sınıfı
- `add(domain)`, `mightContain(domain)` → boolean (false negative asla yok)
- FNV-1a veya polynomial rolling hash, hashCount kadar seed
- `loadFromArray(domains)`, `saveToStorage()`, `loadFromStorage()`
- Veri: `chrome.storage.local` → `"bloom_data"`
- **Not**: Sadece şüpheli işaretleme için, asla direkt engelleme

### 04 — utils/dns_check.js (Katman 2 — Ücretsiz External API)
- `checkDomainViaDNS(domain)` async
- Cloudflare Security DNS + Quad9 DNS-over-HTTPS paralel sorgu
- REFUSED/SERVFAIL → malware listesinde
- Sonuç: `{ cloudflare_blocked, quad9_blocked, consensus_blocked, source: "dns" }`
- Timeout: 3sn, hata durumunda exception fırlatma

### 05 — utils/gsb_check.js (Katman 2 — Google Safe Browsing v4)
- `checkURL(url)` async
- Endpoint: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}`
- Threat types: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION
- API key: `chrome.storage.local` → `"gsb_api_key"`
- Sonuç: `{ threat_found, threat_type, source: "gsb" }`
- Timeout: 5sn, API key yoksa `{ skipped: true }`

### 06 — background/service_worker.js (Ana Kontrol Merkezi)
- **A) Domain Cache**: `chrome.storage.local` → `"domain_cache"`, TTL: 86400000ms (24h)
- **B) checkDomain(domain, url)**:
  1. Cache hit → direkt döndür
  2. Cache miss → Katman 1 (heuristic, senkron)
  3. Paralel Katman 2 (dns_check + gsb_check, Promise.allSettled)
  4. Karar: heuristic >=70 VEYA dns consensus VEYA gsb threat → Katman 3 (sunucu)
  5. Heuristic 40-69 → şüpheli, <40 ve temiz → güvenli
  6. Katman 3: `POST {API_BASE_URL}/api/v2/phishing/check-url`
  7. Sonuçları birleştir, cache'e yaz
- **C) Alarm**: `bloom_refresh` günde 1 kez → `/api/v2/phishing/export-domains` çek, bloom güncelle
- **D) webNavigation.onCommitted**: checkDomain çalıştır, HIGH/CRITICAL → content_script'e `show_warning` mesajı

### 07 — content/content_script.js (Sayfa Uyarı Banner'ı)
- `show_warning` mesajı → Shadow DOM ile banner inject
- Fixed, top:0, full width, z-index: 2147483647
- Renkler: CRITICAL #dc2626, HIGH #ea580c, MEDIUM #ca8a04
- İçerik: uyarı metni + "Yine de Devam Et" + "Geri Dön" (history.back())
- Kapatınca `chrome.storage.session` → `dismissed:{domain}`

### 08 — popup/popup.html + popup.css
- Koyu tema (#0f172a arka plan, #38bdf8 accent), 360px genişlik
- Header: logo + isim
- Site durumu kartı: conic-gradient risk skoru dairesi, risk badge, domain
- Detay accordion'ları: Heuristic / DNS / GSB / AegisNexus
- Butonlar: Derin Tara, Güvenilir İşaretle, Rapor Et
- Ayarlar: API Base URL, GSB API Key, Kaydet

### 09 — popup/popup.js
- Aktif tab → domain parse → service_worker'a `get_result` mesajı
- Sonucu UI'a render et (animasyonlu conic-gradient)
- Derin Tara → `force_scan` mesajı + loading spinner
- Güvenilir İşaretle → `whitelist` array'ine ekle
- Kaydet → `api_base_url` + `gsb_api_key` storage'a yaz

### 10 — Sunucu: GET /api/v2/phishing/export-domains
- PhishingURL tablosundan son 30 gün domain listesi
- Düz text (her satır bir domain), streaming response
- Cache-Control: public, max-age=3600
- İsteğe bağlı X-AegisNexus-Key auth
- 100.000+ domain desteği

### 11 — Sunucu: POST /api/v2/phishing/report
- Body: `{ url, reported_by: "extension", reason }`
- PhishingURL'e `user_reported` flag'iyle yaz, duplicate kontrol
- Rate limit: aynı IP'den dakikada max 10
- Başarı: `{ success: true, message: "Rapor alındı" }`

### 12 — README.md (Kurulum, Test, Paketleme)
- Kurulum: chrome://extensions → Developer mode → Load unpacked → Ayarlar
- Test senaryoları: IP URL, marka subdomain, bilinen phishing, google.com (SAFE)
- Paketleme: `zip -r aegisnexus-extension.zip aegisnexus-extension/ --exclude "*.DS_Store"`

---

## Whitelist Sistemi

| Tip | Kaynak | Tarama |
|-----|--------|--------|
| **Global Whitelist** | AegisNexus DB (`WhitelistDomain` tablosu) | Her ay otomatik güvenlik taraması |
| **Kullanıcı Local Whitelist** | `chrome.storage.local` → `"whitelist"` | Kullanıcının kendi güvenilir siteleri, tarama yapılmaz |
| **Aylık Yenileme** | Alarm ile tetiklenir | Güvenli olmayan siteler kullanıcı whitelist'inden çıkarılır |

---

## Dosya Konumları

| Dosya | Yol |
|-------|-----|
| Chrome Eklentisi | `aegisnexus-extension/` |
| Sunucu Router | `modules/phishing_detector/router.py` |
| Plan Dokümanı | `docs/plan.md` |
