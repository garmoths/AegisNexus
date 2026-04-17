# AegisNexus Modül Açıklamaları

Bu doküman, sistemdeki modüllerin ne işe yaradığını, ne yaptığını ve hangi versiyonla çalıştığını kısa şekilde özetler.

## Genel Bilgi
- Uygulama versiyonu: 2.0.0
- API versiyonu: v2
- Temel prefix: /api/v2

## 01 - Phishing Detector
- API prefix: /api/v2/phishing
- Modül amacı: Zararlı/phishing URL tespiti ve tehdit veritabanı yönetimi.
- Ne yapar:
  - URL güvenlik skoru hesaplar (/check-url)
  - Zararlı URL kaydı ekler (/add-site)
  - Kayıt arama, listeleme ve istatistik sağlar (/search, /latest, /stats)
  - Çoklu tehdit kaynaklarından veri çeker (/fetch-all)
- Versiyon: v2 (AegisNexus 2.0.0 ile uyumlu)

## 02 - Honeypot + IOC Collector
- API prefix: /api/v2/honeypot
- Modül amacı: Saldırganı oyalarken IOC toplamak ve istihbarata dönüştürmek.
- Ne yapar:
  - Decoy (tuzak) oturum/sayfa üretir (/session/create, /decoy)
  - Etkileşimleri kaydeder ve threat score üretir (/interaction)
  - IOC toplar (url, domain, ip, email, hash) (/ioc/collect)
  - IOC liste ve istatistik sunar (/ioc/list, /ioc/stats)
- Versiyon: v2 (IOC Collector genişletmesi aktif)

## 03 - Breach Intelligence
- API prefix: /api/v2/breach
- Modül amacı: E-posta/veri sızıntısı analizi ve risk raporlama.
- Ne yapar:
  - HIBP tabanlı sızıntı kontrolü yapar (/check-email)
  - Tam analiz akışı çalıştırır (/full-analysis)
  - OSINT/zombi hesap ve dark web risk profil bileşenleriyle rapor üretir
- Versiyon: v2 (çok katmanlı analiz akışı)

## 04 - Password Shield
- API prefix: /api/v2/shield
- Modül amacı: Kriptografik olarak güçlü şifre üretmek ve değerlendirmek.
- Ne yapar:
  - Güçlü şifre üretir (/generate)
  - Akılda kalıcı şifre üretir (/generate-memorable)
  - Mevcut şifre güç analizi yapar (/check-strength)
- Versiyon: v2

## 05 - Infrastructure Guard
- API prefix: /api/v2/infra
- Modül amacı: Domain/SSL/port güvenlik sağlığını ölçmek.
- Ne yapar:
  - Tam altyapı analizi yapar (/analyze)
  - SSL sertifika geçerlilik ve kalan gün kontrolü yapar (/ssl-check)
  - Port taraması yapar (/port-scan)
  - Güvenlik header referansları sunar (/security-headers)
- Versiyon: v2

## 06 - Threat Responder
- API prefix: /api/v2/responder
- Modül amacı: Siber zorbalık/şantaj içeriklerini analiz etmek ve mağdur destek akışı sunmak.
- Ne yapar:
  - Tehdit mesaj analizi yapar (/analyze-threat)
  - Destek vakası oluşturur ve yönetir (/create-case, /cases/{case_id})
  - Olay raporu üretir (/generate-report)
  - Destek kaynakları ve eğitim içerikleri sunar (/resources, /education)
- Versiyon: v2

## Notlar
- Tüm modüller FastAPI router mimarisi ile ayrıştırılmıştır.
- Veritabanı katmanında temel olarak phishing_urls ve honeypot_events tabloları kullanılmaktadır.
- Modüller birlikte çalışarak tehdit tespiti + önleme + yanıt akışını tamamlar.
