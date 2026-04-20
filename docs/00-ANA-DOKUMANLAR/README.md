# 📚 AegisNexus Dokümantasyon Rehberi

**Proje:** 6 Katmanlı Güvenlik Kalkanı  
**Son Güncelleme:** 20 Nisan 2026  
**Toplam:** 19 Doküman  
**Dil:** Türkçe

---

## 📁 DOKÜMAN YAPISI

```
docs/
├── 00-ANA-DOKUMANLAR/          # Proje genel bilgileri
├── 01-PROJE-YONETIMI/          # Git ve ekip yönetimi
├── 02-GELISTIRME/              # Geliştirme rehberleri
├── 03-DEPLOYMENT/              # Sunucu ve kurulum
├── 04-TEKNIK-DETAYLAR/         # Kod ve API dokümantasyonu
└── 05-MODULLER/                # Modül spesifikasyonları
```

---

## 📖 ANA DOKÜMANLAR (00)

| Dosya | Açıklama | Hedef Kitle |
|-------|----------|-------------|
| **README.md** | Ana indeks ve navigasyon | Herkes |
| **AegisNexus_KAPSAMLI_RAPOR.md** | Executive summary ve mimari | Yönetim, mimarlar |
| **MODUL_ACIKLAMASI.md** | 6 modülün detaylı açıklaması | Geliştiriciler |
| **TAMAMLANANLAR.md** | Yapılan işlerin listesi | Proje yönetimi |

---

## 🔄 PROJE YÖNETİMİ (01)

| Dosya | Açıklama |
|-------|----------|
| **DALLANMA_REHBERI.md** | Git branch stratejisi |
| **PR_INCELEME_REHBERI.md** | Pull request inceleme kriterleri |

---

## 💻 GELİŞTİRME (02)

*Boş - Geliştirme standartları için kullanılabilir*

---

## 🚀 DEPLOYMENT (03)

| Dosya | Açıklama |
|-------|----------|
| **Frankfurt_Sunucusu_Deployment_Guide.md** | DigitalOcean FRA-1 kurulumu |
| **FRANKFURT_DEPLOYMENT_STEPS.md** | Adım adım deployment |
| **POSTGRES_PASSWORD_FIX.md** | PostgreSQL şifre çözümü |
| **IOC_DEPLOYMENT_CHECKLIST.md** | IOC deployment kontrol listesi |

---

## 🔧 TEKNİK DETAYLAR (04)

| Dosya | Açıklama |
|-------|----------|
| **Code_Technical_Reference.md** | Kod mimarisi detayları |
| **API_INTEGRATION_GUIDE.md** | API entegrasyon rehberi |
| **API_KEY_ROTATION.md** | API key rotasyon mekanizması |
| **API_SUBDOMAIN_SETUP.md** | Alt domain kurulumu |
| **API_USAGE.md** | API kullanım örnekleri |

---

## 🧩 MODÜLLER (05)

| Dosya | Açıklama |
|-------|----------|
| **IOC_COLLECTOR_SETUP.md** | IOC Collector kurulumu |
| **IOC_COLLECTOR_GUIDE.md** | IOC Collector kullanımı |
| **IOC_COLLECTOR_RAPOR_TR.md** | IOC raporları |
| **IOC_FETCHER_SETUP.md** | IOC Fetcher yapılandırması |

---

## 🎯 HIZLI ERİŞİM

**Yeni başlayanlar için:**
1. `00-ANA-DOKUMANLAR/README.md` → Genel bakış
2. `00-ANA-DOKUMANLAR/MODUL_ACIKLAMASI.md` → Modülleri öğren

**Geliştiriciler için:**
1. `04-TEKNIK-DETAYLAR/Code_Technical_Reference.md` → Kod yapısı
2. `04-TEKNIK-DETAYLAR/API_USAGE.md` → API kullanımı

**DevOps için:**
1. `03-DEPLOYMENT/Frankfurt_Sunucusu_Deployment_Guide.md` → Sunucu kurulumu
2. `03-DEPLOYMENT/IOC_DEPLOYMENT_CHECKLIST.md` → Kontrol listesi

---

## 📊 PROJE ÖZETİ

| Modül | Durum |
|-------|-------|
| 01 - Phishing Detector | ✅ Aktif (1.1M+ URL) |
| 02 - Honeypot | ✅ Aktif |
| 03 - Breach Intel | ✅ Aktif |
| 04 - Password Shield | ✅ Aktif |
| 05 - Infra Guard | ✅ Aktif |
| 06 - Cyber Guardian | ✅ Aktif |

**Sunucu:** DigitalOcean FRA-1 (Frankfurt)  
**IP:** 104.248.45.198  
**Status:** 🟢 Production Ready
