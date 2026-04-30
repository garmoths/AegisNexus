# 🛡️ AegisNexus Shield

**AegisNexus Shield**, 3 katmanlı phishing koruması sunan bir Manifest V3 Chrome uzantısıdır: **Local → DNS/GSB → Sunucu**.

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---

## Mimari Özeti

1. **Katman 1 (Local):** Heuristic + Bloom Filter (tamamen local, 0ms gecikme)
2. **Katman 2 (External):** DNS-over-HTTPS (Cloudflare + Quad9) + Google Safe Browsing
3. **Katman 3 (Sunucu):** AegisNexus API ile derin analiz

```text
security_plugin/
├── manifest.json
├── background/
│   └── service_worker.js
├── content/
│   └── content_script.js
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
└── utils/
    ├── heuristic.js
    ├── bloom_filter.js
    ├── dns_check.js
    └── gsb_check.js
```

---

## Kurulum Adımları

1. Repoyu klonla veya ZIP'i indir.
2. Chrome'da `chrome://extensions` aç.
3. Sağ üstten **Developer mode**'u aç.
4. **Load unpacked** → `security_plugin/` klasörünü seç.
5. Uzantı yüklendiğinde toolbar'da **AegisNexus Shield** ikonu görünür.
6. İkona tıkla, **Ayarlar** bölümünde:
   - API Base URL gir (örn: `https://api.aegisnexus.io`)
   - İsteğe bağlı GSB API Key gir (Google Cloud Console'dan alınır)
   - **💾 Kaydet** butonuna tıkla

---

## Test Senaryoları

| # | Test URL | Beklenen Sonuç | Kontrol Edilen Kural |
|---|---|---|---|
| 1 | `http://192.168.1.1/login` | HIGH/CRITICAL | IP URL +25, HTTP+login +20 |
| 2 | `http://paypal.secure-login.verify.xyz/account` | CRITICAL | Marka spoof +30, şüpheli TLD +20, şüpheli kelimeler +20 |
| 3 | `http://g00gle.com/signin` | HIGH | Homograph +25, HTTP+signin +20 |
| 4 | Bilinen phishing domain | CRITICAL | Bloom +20, DNS consensus +40 |
| 5 | `https://google.com` | SAFE | Tüm kontroller temiz |
| 6 | GSB'de kayıtlı malware URL | CRITICAL | GSB threat +50 |
| 7 | `https://subdomain.sub.sub.sub.example.com` | MEDIUM | Subdomain >3 +15, nokta >5 +10 |

---

## Geliştirici Notları

- Bloom filter ilk çalışmada boş gelebilir; `bloom_refresh` alarm'ı 24 saatte bir günceller.
- Manuel güncelleme için: `chrome://extensions` → Service Worker → Console:
  ```js
  chrome.alarms.create("bloom_refresh")
  ```
- GSB API Key olmadan Katman 2 kısmen çalışır, DNS kontrolleri aktif kalır.
- Katman 3 API URL girilmezse sistem Katman 1+2 ile çalışır.

---

## Paketleme

```bash
# Gereksiz dosyaları temizle
find security_plugin/ -name "*.DS_Store" -delete
find security_plugin/ -name "*.map" -delete

# ZIP oluştur
zip -r aegisnexus-extension.zip security_plugin/ \
  --exclude "*.DS_Store" \
  --exclude "*/.git/*" \
  --exclude "*/node_modules/*" \
  --exclude "*.map"

# Kontrol et
unzip -l aegisnexus-extension.zip
```

---

## Chrome Web Store'a Yükleme

1. Chrome Web Store Developer Dashboard'a git.
2. **New Item** → `aegisnexus-extension.zip` yükle.
3. Store listing, ekran görüntüleri ve gizlilik politikasını doldur.
4. Review için gönder.

---

## Lisans

**MIT**
