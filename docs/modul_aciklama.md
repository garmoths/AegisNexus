# Aegis Nexus Modül Açıklamaları

Aegis Nexus, bireylerin ve KOBİ'lerin dijital dünyadaki tehlikelere karşı proaktif korunmasını sağlayan 6 modüllü bir güvenlik kalkanıdır.

---

## 01 - Phishing Detector (Phishing Tespit Modülü)

**Açıklama:** Tehdit veritabanı ve URL tarama modülü. Zararlı URL'leri tespit eder, phishing sitelerini izler ve kullanıcıları uyarır.

**Özellikler:**
- Çoklu tehdit kaynağı entegrasyonu (GitHub, OpenPhish, URLHaus, Kaggle, CertStream, OTX)
- URL güvenlik skor hesaplama (0-100 arası)
- SSL/domain analizi
- Rate limiting (60 istek/dakika)
- Tarama geçmişi takibi
- Tehdit tipi dağılım analizi

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/phishing/check-url` | POST | URL güvenlik skorunu hesaplar |
| `/api/v2/phishing/add-site` | POST | Yeni phishing sitesi ekler (admin) |
| `/api/v2/phishing/stats` | GET | Toplam zararlı site sayısı |
| `/api/v2/phishing/latest-paged` | GET | Son eklenen tehditler (sayfalı) |
| `/api/v2/phishing/search` | GET | URL içinde arama yapar |
| `/api/v2/phishing/fetch-all` | POST | Tüm kaynaklardan phishing verisi çeker (admin) |
| `/api/v2/phishing/history` | GET | URL tarama geçmişini getirir |
| `/api/v2/phishing/scan-history` | GET | Sayfalı tarama geçmişi |
| `/api/v2/phishing/latest` | GET | Son phishing URL'leri |
| `/api/v2/phishing/threat-types` | GET | Tehdit tipi dağılımı |

**Kullanım Örneği:**
```bash
curl -X POST https://api.aegisnexus.dev/api/v2/phishing/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'
```

**Dönüş Örneği:**
```json
{
  "status": "success",
  "url": "https://suspicious-site.com/login",
  "score": 15,
  "risk_level": "critical",
  "details": ["Phishing veritabanında bulundu", "SSL sertifikası geçersiz"],
  "sources": ["phishtank", "urlhaus"],
  "module": "01_phishing_detector"
}
```

---

## 02 - Honeypot (IP Avcısı ve IOC Toplayıcı)

**Açıklama:** Dolandırıcıları tersine mühendislik ile avlayan tuzak modülü. Gerçekçi sahte login sayfaları ile dolandırıcıların zamanını tüketir ve IOC (Indicator of Compromise) toplar.

**Özellikler:**
- Gerçekçi banka login tuzak sayfası
- Dolandırıcı etkileşim takibi
- IOC toplama (IP, domain, URL, hash)
- Dış tehdit istihbaratı kaynakları entegrasyonu (abuse.ch, AbuseIPDB)
- Risk skor hesaplama (1-100)
- Toplumsal etki ölçümü (kurtarılan kurban sayısı)

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/honeypot/decoy` | GET | Gerçekçi banka login tuzak sayfası |
| `/api/v2/honeypot/session/create` | POST | Yeni tuzak oturumu oluşturur |
| `/api/v2/honeypot/interaction` | POST | Dolandırıcı etkileşimini kaydeder |
| `/api/v2/honeypot/stats` | GET | Honeypot istatistikleri |
| `/api/v2/honeypot/session/close` | POST | Oturumu kapatır |
| `/api/v2/honeypot/decoy-types` | GET | Tuzak türlerini listeler |
| `/api/v2/honeypot/ioc/collect` | POST | Honeypot dışı kaynaklardan IOC toplar |
| `/api/v2/honeypot/ioc/list` | GET | Toplanan IOC listesi |
| `/api/v2/honeypot/ioc/fetch-external` | POST | Dış tehdit kaynaklarından IOC çeker (admin) |
| `/api/v2/honeypot/ioc/list-collected` | GET | Gelişmiş IOC listesi (filtreleme ile) |
| `/api/v2/honeypot/ioc/stats-advanced` | GET | Kapsamlı IOC istatistikleri |
| `/api/v2/honeypot/ioc/search` | GET | IOC arama |
| `/api/v2/honeypot/ioc/by-risk-score` | GET | Risk seviyesine göre IOC |
| `/api/v2/honeypot/ioc/stats` | GET | IoC istatistikleri aggregation |
| `/api/v2/honeypot/phishing/stats` | GET | Phishing verileri aggregation |

**Kullanım Örneği:**
```bash
curl -X POST https://api.aegisnexus.dev/api/v2/honeypot/session/create \
  -H "Content-Type: application/json" \
  -d '{"decoy_type": "bank_login"}'
```

**Dönüş Örneği:**
```json
{
  "session_id": "hp-abc123xyz",
  "decoy_page": "/api/v2/honeypot/decoy?session=hp-abc123xyz",
  "decoy_type": "bank_login",
  "module": "02_honeypot"
}
```

**Toplumsal Etki:**
- 1 saat zaman kaybı = 12 potansiyel kurban kurtarıldı
- Dolandırıcıların bu sayfada harcadığı her dakika, gerçek bir vatandaşın dolandırılmasını önler

---

## 03 - Breach Intelligence (Veri Radarı)

**Açıklama:** Deep Web sızıntı takibi ve erken uyarı sistemi. E-posta adreslerinin veri ihlallerinde sızdırılıp sızdırılmadığını kontrol eder.

**Özellikler:**
- HaveIBeenPwned (HIBP) entegrasyonu
- OSINT Zombi Hesap Temizleyici
- Psychology Profiler (Dark Web analizi)
- Veri Radarı Görselleştirmesi (D3.js)
- LLM tabanlı raporlama (Groq)
- KVKK başvuru raporu oluşturma
- Şantaj riski analizi
- Risk skor hesaplama

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/breach/full-analysis` | POST | Tam breach analizi (Aegis Imperius) |
| `/api/v2/breach/check-email` | POST | Hızlı e-posta sızıntı kontrolü |
| `/api/v2/breach/generate-kvkk-report` | POST | KVKK başvuru raporu oluşturur |
| `/api/v2/breach/youth-protection` | POST | Genç kullanıcılar için koruma |
| `/api/v2/breach/stats` | GET | Sızıntı istihbaratı istatistikleri |
| `/api/v2/breach/generate-llm-report` | POST | LLM tabanlı rapor oluşturur |
| `/api/v2/breach/dark-web-scan` | POST | Dark Web taraması |
| `/api/v2/breach/psychology-analysis` | POST | Psikoloji analizi |

**Kullanım Örneği:**
```bash
curl -X POST https://api.aegisnexus.dev/api/v2/breach/check-email \
  -H "Content-Type: application/json" \
  -d '{"email": "ornek@email.com"}'
```

**Dönüş Örneği:**
```json
{
  "status": "success",
  "email": "ornek@email.com",
  "breached": true,
  "breach_count": 3,
  "breaches": [
    {
      "name": "LinkedIn",
      "domain": "linkedin.com",
      "breach_date": "2021-06",
      "data_classes": ["Email", "Password", "Name"]
    }
  ],
  "shantaj_risk_analysis": {
    "risk_level": "high",
    "compromised_accounts": 3
  },
  "kvkk_report": "...",
  "module": "03_breach_intel"
}
```

---

## 04 - Password Shield (Kriptografik Kalkan)

**Açıklama:** Kırılması yüzyıllar süren güvenli şifre üretimi ve güçlülük analizi modülü.

**Özellikler:**
- Kriptografik olarak rastgele şifre üretimi (CSPRNG)
- Güvenlik kategorileri (ultra_secure, high_security, standard, memorable)
- Akılda kalıcı şifre üretimi (Türkçe kelimeler)
- Şifre güçlülük analizi
- Kırılma süresi tahmini
- İyileştirme önerileri

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/shield/generate` | POST | Güvenli şifre üretir |
| `/api/v2/shield/generate-memorable` | POST | Akılda kalıcı şifre üretir |
| `/api/v2/shield/check-strength` | POST | Şifre güçlülüğünü analiz eder |
| `/api/v2/shield/categories` | GET | Şifre güvenlik kategorilerini listeler |
| `/api/v2/shield/stats` | GET | Kriptografik Kalkan istatistikleri |

**Kullanım Örneği:**
```bash
curl -X POST https://api.aegisnexus.dev/api/v2/shield/generate \
  -H "Content-Type: application/json" \
  -d '{"length": 32, "category": "ultra_secure"}'
```

**Dönüş Örneği:**
```json
{
  "status": "success",
  "password": "Xk9#mP2$vL8@nQ4!rW6&zT3*",
  "metadata": {
    "length": 32,
    "entropy": 208,
    "crack_time": "centuries",
    "security_level": "ULTRA_SECURE"
  },
  "module": "04_password_shield",
  "usage_warning": "Bu şifreyi güvenli bir şifre yöneticisine kaydedin. Ekran görüntüsü almayın."
}
```

**Toplumsal Etki:**
- Her güçlü şifre = Bir hack girişiminin engellenmesi

---

## 05 - AI Analyzer (AI Güvenlik Asistanı)

**Açıklama:** LLM tabanlı phishing, dolandırıcılık ve sosyal mühendislik analizi modülü. Metinleri analiz eder ve tehditleri tespit eder.

**Özellikler:**
- LLM tabanlı phishing/scam tespiti
- URL güvenlik kontrolü (veritabanı + API)
- Psikolojik manipülasyon analizi
- Kişiselleştirilmiş öneriler
- Hızlı tarama modu
- Analiz geçmişi takibi
- ML Random Forest sınıflandırıcı

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/ai-analyzer/analyze` | POST | Tam AI analizi |
| `/api/v2/ai-analyzer/quick-scan` | POST | Hızlı tarama |
| `/api/v2/ai-analyzer/check-url` | POST | URL güvenlik kontrolü |
| `/api/v2/ai-analyzer/extract-urls` | POST | Metinden URL çıkarır |
| `/api/v2/ai-analyzer/health` | GET | Sağlık kontrolü |
| `/api/v2/ai-analyzer/examples` | GET | Örnek analizler |
| `/api/v2/ai-analyzer/history` | GET | Analiz geçmişi |
| `/api/v2/ai-analyzer/history/{history_id}` | GET | Analiz detayları |

**Kullanım Örneği:**
```bash
curl -X POST https://api.aegisnexus.dev/api/v2/ai-analyzer/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Banka hesabınız askıya alındı! Hemen tıklayın...",
    "context": "email",
    "sender": "fake-banka@example.com",
    "subject": "Acil: Hesap Durumu"
  }'
```

**Dönüş Örneği:**
```json
{
  "analysis_id": "ai-xyz123",
  "timestamp": "2026-04-26T15:30:00Z",
  "security_assessment": {
    "is_phishing": true,
    "confidence": 0.92,
    "threat_level": "high"
  },
  "detailed_analysis": {
    "indicators": ["aciliyet", "tehdit", "link"],
    "manipulation_techniques": ["urgency", "fear"]
  },
  "recommendations": [
    "Bu mesaja yanıt vermeyin",
    "Göndereni doğrulayın",
    "Linklere tıklamayın"
  ],
  "summary": "Bu mesaj yüksek olasılıkla phishing içeriyor.",
  "module": "07_ai_analyzer"
}
```

---

## 06 - Victim Atlas (Siber Mağduriyet Atlası)

**Özet:** Victim Atlas, siber mağduriyet vakalarının sistematik arşivlenmesi ve analiz edildiği insan odaklı bir modüldür. Bireysel düzeyde, kullanıcıların karşılaştığı phishing, smishing, sahte mobil uygulama gibi saldırı yöntemlerini sınıflandırır; banka hesabı, kimlik, kredi kartı gibi kayıp tiplerini analiz eder ve benzer mağduriyetlerden korunmasına rehberlik eder. Sosyal düzeyde, toplumda görülen siber tehdit trendlerini izler, kritik vakaları hot set yönetimi ile önceliklendirir ve LLM tabanlı vaka çıkarımı ile otomatik veri işleme yaparak politika yapıcılara ve güvenlik ekiplerine istihbarat sağlar. Bu çift yönlü yaklaşım, hem bireysel kullanıcıların farkındalığını artırır hem de toplumsal siber güvenlik stratejilerinin geliştirilmesine katkıda bulunur.

**Açıklama:** İnsan odaklı siber mağduriyet arşivi ve savunma rehberi modülü. Siber mağduriyet vakalarını takip eder ve analiz eder.

**Özellikler:**
- Vaka takip sistemi
- Saldırı yöntemi sınıflandırması (phishing, smishing, sahte mobil uygulama vb.)
- Kayıp tipi analizi (banka hesabı, kimlik, kredi kartı vb.)
- Güvenlik skor hesaplama
- Hot set yönetimi (kritik vakalar)
- Otomatik veri işleme (Celery)
- LLM tabanlı vaka çıkarımı

**API Endpoint'leri:**

| Endpoint | Method | Açıklama |
|---------|--------|----------|
| `/api/v2/victim-atlas/cases` | GET | Vaka listesi (filtreleme ile) |
| `/api/v2/victim-atlas/cases/{case_id}` | GET | Vaka detayları |
| `/api/v2/victim-atlas/stats` | GET | Mağduriyet atlası istatistikleri |
| `/api/v2/victim-atlas/ingest/health` | GET | Veri işleme sağlık durumu (admin) |
| `/api/v2/victim-atlas/ingest/run` | POST | Manuel veri işleme çalıştırma (admin) |
| `/api/v2/victim-atlas/ingest/prune` | POST | Hot set bakımı (admin) |

**Kullanım Örneği:**
```bash
curl "https://api.aegisnexus.dev/api/v2/victim-atlas/cases?page=1&limit=20&attack_method=phishing"
```

**Dönüş Örneği:**
```json
{
  "data": [
    {
      "id": 1,
      "case_slug": "smishing-bank-2024-001",
      "case_title": "SMS ile banka hesabı şantajı",
      "attack_method": "smishing",
      "loss_type": "bank_account",
      "severity_score": 85,
      "confidence_score": 92
    }
  ],
  "page": 1,
  "total": 150,
  "module": "07_victim_atlas"
}
```

---

## Modül İlişkileri

```
┌─────────────────────────────────────────────────────────────┐
│                    Aegis Nexus Platform                    │
├─────────────────────────────────────────────────────────────┤
│  01. Phishing Detector  →  URL tarama ve tehdit veritabanı │
│  02. Honeypot           →  Dolandırıcı avlama ve IOC toplama │
│  03. Breach Intelligence →  Veri sızıntısı takibi            │
│  04. Password Shield    →  Güvenli şifre üretimi            │
│  05. AI Analyzer        →  LLM tabanlı tehdit analizi       │
│  06. Victim Atlas       →  Mağduriyet vakası takibi         │
└─────────────────────────────────────────────────────────────┘
```

**Ortak Özellikler:**
- Tüm modüller FastAPI ile RESTful API sunar
- SQLAlchemy ile veritabanı entegrasyonu
- Rate limiting ve güvenlik kontrolü
- Loglama ve hata yönetimi
- Türkçe dil desteği
- Toplumsal etki odaklı tasarım

---

## Teknik Stack

- **Backend:** FastAPI, Python 3.12
- **Veritabanı:** SQLite (development), PostgreSQL (production)
- **ML/AI:** Scikit-learn, Groq LLM
- **Async:** Celery (veri işleme)
- **Frontend:** React, TailwindCSS
- **Deployment:** Docker, systemd

---

## Lisans ve Kullanım

Bu proje açık kaynaklıdır ve eğitim amaçlı kullanıma uygundur. Üretim ortamında kullanmadan önce güvenlik testleri yapılmalıdır.

**İletişim:** aegisnexus@example.com
**GitHub:** https://github.com/garmoths/AegisNexus
