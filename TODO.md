# AegisNexus TODO Listesi

## Yüksek Öncelik (High Priority)

- [ ] Subdomain için SSL sertifikası al
- [ ] Modülleri subdomain'e aktar

## Orta Öncelik (Medium Priority)

### AI Analyzer
- [ ] quick-scan endpoint'ini frontende ekle
- [ ] check-url endpoint'ini frontende ekle
- [ ] extract-urls endpoint'ini frontende ekle
- [ ] health endpoint'ini frontende ekle

### Honeypot (IOC Collector)
- [ ] decoy endpoint'ini frontende ekle
- [ ] session/create endpoint'ini frontende ekle
- [ ] interaction endpoint'ini frontende ekle
- [ ] session/close endpoint'ini frontende ekle

### Breach Intel
- [ ] full-analysis endpoint'ini frontende ekle
- [ ] zombie-detector endpoint'ini frontende ekle
- [ ] generate-kvkk-report endpoint'ini frontende ekle
- [ ] risk-levels endpoint'ini frontende ekle

### Password Shield
- [ ] generate-memorable endpoint'ini frontende ekle
- [ ] check-strength endpoint'ini frontende ekle
- [ ] categories endpoint'ini frontende ekle
- [ ] stats endpoint'ini frontende ekle

### Threat Responder
- [ ] analyze-threat endpoint'ini frontende ekle
- [ ] create-case endpoint'ini frontende ekle
- [ ] cases/{case_id} endpoint'ini frontende ekle
- [ ] generate-report endpoint'ini frontende ekle
- [ ] resources endpoint'ini frontende ekle

## Tamamlanan İşlemler

- [x] Projeyi incele - tüm modülleri kontrol et
- [x] Frontende alınmamış ama backend'de hazır modülleri bul
- [x] Honeypot modülünü IOC collector olarak güncelle

## Proje Özeti

### Backend Modülleri
1. AI Analyzer - AI Güvenlik Asistanı (LLM tabanlı analiz)
2. Phishing Detector - Phishing ve zararlı URL tespiti
3. Honeypot (IOC Collector) - IP Avcısı ve IOC toplayıcı
4. Breach Intel - Veri sızıntısı istihbaratı
5. Password Shield - Kriptografik şifre üretimi
6. Threat Responder - Tehdit göstergelerini yanıt verme

### Frontende Kullanılan API'ler
- /api/v2/contact
- /api/v2/infra/analyze
- /api/v2/breach/check-email
- /api/v2/ai-analyzer/analyze
- /api/v2/shield/generate
- /api/v2/honeypot/stats
- /api/v2/honeypot/ioc/stats
- /api/v2/honeypot/ioc/search
- /api/v2/phishing/add-site
- /api/v2/phishing/check-url
- /api/v2/phishing/stats
- /api/v2/phishing/latest
- /api/v2/phishing/search

### Frontende Kullanılmayan Özellikler
Birçok endpoint backend'de hazır ama frontende kullanılmıyor. Yukarıdaki TODO listesinde detaylı olarak listelenmiştir.
