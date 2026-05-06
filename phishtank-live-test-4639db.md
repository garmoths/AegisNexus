# PhishTank Canlı TI Entegrasyon Testi

PhishTank'ın onaylanmış phishing URL listesinden 5-10 URL çekerek `run_threat_intelligence` üzerinden gerçek API çağrıları yapıp, Bayesian scoring çıktısını analiz eder ve tuning önerileri üretir.

## Adımlar

### 1. PhishTank veri çekimi
- `https://data.phishtank.com/data/online-valid.csv` adresinden CSV indir (opsiyonel `PHISHTANK_API_KEY` ile, yoksa public endpoint)
- En güncel 10 URL seç (online/active olanlar)
- `.env`'e `PHISHTANK_API_KEY` ekleme adımı dokümante edilecek

### 2. Test scripti — `tests/phishtank_live_test.py`
Her URL için `run_threat_intelligence` çağır ve şu alanları topla:

| Alan | Kaynak |
|------|--------|
| `combined_risk_probability` | Bayesian + boost sonrası |
| `pre_boost_probability` | boost öncesi |
| `correlation_boosts` | hangi kurallar tetiklendi |
| `risk_level` | legacy |
| `legacy_penalty` | eski model skoru |
| `penalty_events` | kaynak bazlı katkılar |

### 3. Çıktı formatı
- Terminal: renkli tablo (tabulate)
- Sonunda özet:
  - Kaç URL `combined_risk_probability > 0.5` / `> 0.7` / `> 0.9`?
  - Hangi kaynaklar en çok tetiklendi?
  - Düşük skorlu (< 0.3) URL varsa → kayıp sinyal analizi

### 4. Tuning önerileri (otomatik)
Sonuçlara göre script şunları önerir:
- Herhangi kaynak hiç tetiklenmediyse → ağırlık yetersiz mi?
- `correlation_boosts` boşsa → sinyal eşiği çok mu yüksek?
- `legacy_penalty` yüksek ama `combined_risk` düşükse → `to_probability` kalibrasyonu

## Bağımlılıklar
- `tabulate` (zaten projede var mı kontrol edilecek)
- `requests` (mevcut)
- `.env` → `PHISHTANK_API_KEY` (opsiyonel)
- Gerçek API key'ler aktif olmalı: `VT_API_KEY`, `GSB_API_KEY`, `ABUSEIPDB_API_KEY`

## Notlar
- Her URL arasında 3s bekle (rate limit)
- Maksimum 10 URL (API key koruma)
- Sonuçlar `tests/phishtank_results_<tarih>.json` olarak kaydedilir
