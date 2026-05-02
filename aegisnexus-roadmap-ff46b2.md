# AegisNexus — Büyüme Yol Haritası (STIX + SMS API + Şehir Haritası)

3 somut özellik ekleyerek platformu USOM'a bildirilebilir, operatörlere demo'lanabilir ve medyaya viral hale getiriyoruz.

---

## 1. STIX 2.1 Export — IOC Ekranı

**Ne:** IOC kayıtlarını STIX 2.1 bundle olarak indiren bir export akışı.  
**Neden:** IOC verisini standart formatta sunmak, hem entegrasyonu hem de demo değerini yükseltir.

**Backend**
- Endpoint yolu, mevcut router yapısına göre `GET /api/v2/ioc/export/stix`
- Query parametreleri: `threat_type`, `min_risk_score`, `limit`
- Her `IndicatorOfCompromise` satırı bir STIX `indicator` nesnesine çevrilir
- Response tipi `application/stix+json` olur

**Frontend (`frontend-react`)**
- IOC sayfasında mevcut `ModulesApp.jsx` içindeki `HoneypotIOC` bloğuna export butonu eklenir
- Buton, `GET /api/v2/ioc/export/stix?min_risk_score=...` çağırır ve dosyayı indirir
- API taban yolu `VITE_API_BASE_URL` üzerinden okunur; ayrı origin varsa CORS ayarı yapılır

---

## 2. SMS Analiz API — Operatör Demo'su

**Ne:** Gelen SMS içeriğini analiz eden, risk skoru + kategori döndüren REST endpoint.  
**Neden:** Operatör demo'su ve kurumsal entegrasyon için hızlı bir gösterim sağlar.

**Backend — `modules/sms_guard/` modülü**
- `POST /api/v2/sms/analyze`
  ```json
  { "text": "Paketiniz bekliyor, tıklayın: bit.ly/abc" }
  ```
  Returns:
  ```json
  {
    "risk_score": 87,
    "category": "smishing",
    "confidence": 0.91,
    "indicators": ["kısaltılmış URL", "sahte kargo"],
    "action": "BLOCK",
    "explanation": "..."
  }
  ```
- Kural tabanlı analiz + IOC çapraz kontrol; isterse daha sonra Gemini katmanı eklenir
- IOC veritabanıyla çapraz kontrol (URL içindeyse risk artır)
- OpenAPI/Swagger dokümantasyonu otomatik gelir

**Frontend (`frontend-react`)**
- Mevcut `AnalyzePage.jsx` altına SMS widget eklenir
- `smsGuardAPI.analyze(text, sender)` çağrısı kullanılır
- Sonuç kartı, risk skoruna göre BLOCK/WARN/ALLOW görünümü verir

---

## 3. Şehir Bazlı Vaka Haritası — Viral Potansiyel

**Ne:** Türkiye illerini renk yoğunluğuyla gösteren interaktif dolandırıcılık haritası.  
**Neden:** "İstanbul'da bu ay en çok hangi dolandırıcılık yapıldı" haberi kendiliğinden yazar.

**Backend (zaten hazır)**
- `/api/v2/stats/heatmap` endpoint mevcut — `region` field ile il bazlı sayım yapıyor

**Frontend (`frontend-react`)**
- Harita sayfası `HaritaPage.jsx` içinde render edilir
- Şimdilik il kartlarıyla çalışan bir heatmap yeterli; gerçek SVG/TopoJSON haritası sonradan eklenebilir
- `region` verisi boş olan kayıtlar haritada `0` olarak görünür
- `react-simple-maps` kullanılacaksa gerçek GeoJSON/TopoJSON dosyası ayrıca eklenmelidir; boş `geometry` ile promise edilmemelidir

---

## Frontend Build ve Deploy

- Frontend dizini: `frontend-react/`
- Yerel doğrulama: `npm run build`
- Sunucuya kopyalama: `dist/` çıktısı `/var/www/aegis_nexus/frontend-react/dist/` altına alınır
- Nginx statik servis için build çıktısını servis eder; deploy sonrası gerekirse `sudo systemctl reload nginx`
- Ayrı origin kullanılıyorsa `VITE_API_BASE_URL` ve `CORS_ALLOW_ORIGINS` birlikte kontrol edilir

---

## Uygulama Sırası

| # | Özellik | Süre | Etki |
|---|---------|------|------|
| 1 | STIX export + IOC butonu | ~1 saat | Standart entegrasyon |
| 2 | SMS Guard widget + API | ~2 saat | Operatör demo'su |
| 3 | Harita sayfası iyileştirme | ~2 saat | Görsel etki |

---

## Notlar

- `region` alanı çoğu vakada `NULL`; harita için veri doldurma ayrı bir backend işi olarak ele alınmalı
- STIX export'ta TLP renklendirmesi risk skorundan türetilmeli
- SMS API için rate limit ve abuse koruması ayrıca planlanmalı
