curl -s http://127.0.0.1:8000/api/v2/phishing/stats | jq# Phishing Skorlama Motoru Refaktör Planı (A-B-C-D-E)

Bu plan, mevcut doğrusal ceza toplama modelini (toplam ceza) üretim seviyesinde, olasılık tabanlı ve bağlam farkındalığı olan bir yapıya taşımak için hazırlanmıştır.

## Durum

| Faz | Açıklama | Durum | Branch |
|-----|----------|-------|--------|
| **A** | Bayesian kombinasyon katmanı | ✅ Tamamlandı | `feature/phishing-bayesian-scoring` |
| **B** | Kaynak ağırlıklandırma (tiered source reliability) | ✅ Tamamlandı | `feature/phishing-bayesian-scoring` |
| **C** | Korelasyon boost motoru | ✅ Tamamlandı | `feature/phishing-bayesian-scoring` |
| **D** | Domain yaşı + screenshot belirsizlik cezası | ⬜ Bekliyor | — |
| **E** | Sınıflandırma + güven aralığı + üretim geçişi | ⬜ Bekliyor | — |

**Test durumu:** 98/98 ✅ (Faz A+B+C sonrası)

## Hedef

- Ceza aşımını ve çifte sayımı kaldırmak
- Kaynak güvenilirliğine göre ağırlıklandırma yapmak
- Sinyal korelasyonu ile riski bağlamsal artırmak
- Domain yaşı ve belirsizlik modelini sisteme entegre etmek
- Her faz sonunda test + commit + push ile ilerlemek

## Kapsam

- `modules/phishing_detector/threat_intel.py`
- `modules/phishing_detector/scanner.py`
- `modules/phishing_detector/router.py` (çıktı sözleşmesi gerekiyorsa)
- `tests/test_parallel_threat_intel.py`
- `tests/test_phishing_celery.py`
- Gerekirse yeni test dosyaları (`tests/test_phishing_scoring_*.py`)

## Dal Stratejisi

- Branch: `feature/phishing-bayesian-scoring`
- Faz bazlı commit + push
- Her faz sonunda CI/yerel testler yeşil olmadan sonraki faza geçilmez

---

## A) Bayesian Kombinasyon Katmanı (Ceza Toplama Rework)

### Amaç

Mevcut `total_penalty += X` modelini, `[0,1]` arası risk sinyalleri ile çalışan birleşik olasılık modeline geçirmek:

- `P(malicious_combined) = 1 - Π(1 - p_i)`
- Final güvenlik skoru: `score = round((1 - P) * 100)`

### Teknik Tasarım

1. Yeni yardımcı fonksiyonlar:
   - `combine_probabilities(probabilities: list[float]) -> float`
   - `to_probability(raw_penalty_0_100: int|float) -> float`
2. Mevcut ceza kaynaklarının önce olasılığa çevrilmesi
3. Eski `total_penalty` alanı geriye uyumluluk için korunacaksa:
   - Geçiş sürecinde `legacy_penalty` adıyla tutulur
4. Risk seviyesi eşikleri yeni `score` üzerinden hesaplanır

### Uygulama Adımları

1. Threat-intel pipeline içinde `penalty_events` listesi oluştur
2. Her kaynak sonucu için:
   - `source_key`
   - `probability`
   - `reason`
   - `raw_evidence`
3. Final `combined_probability` hesapla
4. API response’a:
   - `combined_risk_probability`
   - `scoring_model: "bayesian-v1"`
   - `scoring_details.penalty_events`
   alanlarını ekle

### Test Planı (A Fazı)

- Unit:
  - `[0.8, 0.7] -> 0.94` (yaklaşık)
  - `[0.3, 0.2] -> 0.44` (yaklaşık)
  - Boş giriş -> 0.0
  - Sınır değerler (0,1)
- Regression:
  - Whitelist URL skoru korunmalı (yüksek güvenli)
  - Kritik URL’ler düşük güvenlik skorunda kalmalı

### Faz Sonu Gate (Test + Push)

```bash
pytest -q tests/test_parallel_threat_intel.py tests/test_phishing_celery.py
git add -A
git commit -m "feat(scoring): add Bayesian probability combiner for phishing risk"
git push origin feature/phishing-bayesian-scoring
```

---

## B) Kaynak Ağırlıklandırma (Tiered Source Reliability)

### Amaç

Bütün kaynakları eşit kabul etmek yerine güvenilirlik bazlı ağırlık şeması kullanmak.

### Kaynak Ağırlık Haritası (İlk Sürüm)

```python
SOURCE_WEIGHTS = {
    "virustotal_malicious": 1.00,
    "google_safe_browsing": 0.95,
    "phishtank_verified": 0.90,
    "urlhaus": 0.75,
    "spamhaus_dbl": 0.70,
    "threatfox": 0.65,
    "spamhaus_xbl": 0.60,
    "abuseipdb": 0.45,
    "spamhaus_zrd": 0.30,
    "screenshot_high": 0.70,
    "screenshot_suspicious": 0.35,
    "ml_model": 0.40
}
```

### Teknik Tasarım

1. Yeni modül sabiti: `SOURCE_WEIGHTS`
2. Her sinyal için:
   - `base_probability` x `source_weight` ile normalize risk
3. Kaynak yoksa default fallback:
   - `DEFAULT_SOURCE_WEIGHT = 0.35`

### Uygulama Adımları

1. Threat-intel sinyallerini `source_key` bazında standardize et
2. `weighted_probability = min(1.0, base_probability * weight_factor)` hesapla
3. `penalty_events` içinde raw + weighted değerleri birlikte tut

### Test Planı (B Fazı)

- Unit:
  - Aynı base sinyalde VT > AbuseIPDB etkisi
  - Bilinmeyen source fallback ağırlıkla çalışmalı
- Scenario:
  - Tek güçlü kaynak (VT malicious) yüksek risk üretmeli
  - Çok zayıf kaynak birleşimi orta risk üretmeli

### Faz Sonu Gate (Test + Push)

```bash
pytest -q tests/test_parallel_threat_intel.py tests/test_phishing_celery.py
git add -A
git commit -m "feat(scoring): add tiered source reliability weights"
git push origin feature/phishing-bayesian-scoring
```

---

## C) Korelasyon Boost Motoru (Context-Aware Boosts)

### Amaç

Bağımsız sinyalleri kör toplamak yerine kritik kombinasyonlarda çarpan uygulamak.

### İlk Kural Seti

1. `typosquatting + suspicious_tld + credential_form` -> `x1.4`
2. `ti_brand == visual_brand` -> `x1.3`
3. `domain_age<30 + abuseipdb_high + urlhaus_listed` -> `x1.35`
4. `screenshot_failed + structural_penalty_high` -> `x1.2`

### Teknik Tasarım

1. Fonksiyon:
   - `apply_correlation_boost(signals: dict) -> list[tuple[str, float]]`
2. Boost uygulama sırası:
   - Önce Bayesian combine
   - Sonra boostlar
   - `min(1.0, combined * multiplier)` ile clamp
3. Response’a eklenir:
   - `scoring_details.correlation_boosts`

### Uygulama Adımları

1. `signals` şeması netleştirme (brand, tld, form, age, blacklist)
2. Rule evaluator yazımı
3. Boost audit trail (hangi kural tetiklendi) ekleme

### Test Planı (C Fazı)

- Unit:
  - Her boost kuralı tek tek tetiklenmeli
  - Yanlış pozitif durumlarda tetiklenmemeli
- Property:
  - Boost sonrası risk azalmamalı
  - Sonuç 1.0’ı aşmamalı

### Faz Sonu Gate (Test + Push)

```bash
pytest -q tests/test_parallel_threat_intel.py tests/test_phishing_celery.py
git add -A
git commit -m "feat(scoring): add correlation-based risk boost rules"
git push origin feature/phishing-bayesian-scoring
```

---

## D) Domain Yaşı + Screenshot Belirsizlik Cezası Revizyonu

### Amaç

Domain age sinyalini katmak ve screenshot failure cezasını sabit +10 yerine bağlamsal yapmak.

### Domain Yaşı Katmanı

1. WHOIS entegrasyonu:
   - `age_days < 7` -> yüksek risk
   - `< 30` -> orta-yüksek
   - `< 90` -> düşük-orta
2. WHOIS başarısızsa düşük belirsizlik cezası

### Screenshot Failure Revizyonu

`current_risk_probability` bazlı:

- `< 0.2` -> 0.00
- `< 0.5` -> 0.08
- `>= 0.5` -> 0.18

### Uygulama Adımları

1. Domain age helper ekle
2. Screenshot fail penalty fonksiyonunu yeni modele taşı
3. API response’da:
   - `domain_age_days`
   - `uncertainty_penalty_applied`
   alanlarını dön

### Test Planı (D Fazı)

- Unit:
  - Domain yaşı eşik testleri
  - WHOIS exception fallback
  - Screenshot fail dynamic penalty
- Integration:
  - High risk + screenshot fail -> risk artmalı
  - Low risk + screenshot fail -> ceza minimal

### Faz Sonu Gate (Test + Push)

```bash
pytest -q tests/test_parallel_threat_intel.py tests/test_phishing_celery.py
git add -A
git commit -m "feat(scoring): add domain-age signal and dynamic screenshot uncertainty penalty"
git push origin feature/phishing-bayesian-scoring
```

---

## E) Sınıflandırma + Güven Aralığı + Üretim Geçişi

### Amaç

Sınır skorları daha doğru yönetmek için güven aralığı ve confidence seviyesi eklemek.

### Yeni Sınıflandırma

- `score >= 80` -> Güvenli
- `60-79` -> Şüpheli
- `35-59` -> Riskli
- `<35` -> Tehlikeli

Ek:
- `uncertainty = max(5, 15 - signal_count * 2)`
- `range = [score-uncertainty, score+uncertainty]`
- Sınır bölgelerde `Belirsiz` etiketi

### Geçiş Stratejisi

1. Feature flag: `PHISHING_SCORING_MODEL=bayesian-v1`
2. Shadow mode (opsiyonel):
   - Eski ve yeni skoru birlikte logla
3. Observability:
   - model sürümü
   - signal_count
   - confidence dağılımı

### Uygulama Adımları

1. `classify_with_confidence` fonksiyonu ekle
2. API contract güncellemesi:
   - `confidence`
   - `score_range`
   - `scoring_model`
3. Frontend uyumluluğunu doğrula (minimum: mevcut alanlar kırılmasın)

### Test Planı (E Fazı)

- Contract test:
  - Yeni alanlar response’da mevcut
  - Eski alanlar geriye uyumlu
- Boundary test:
  - 59/60/61 skor sınır davranışları
  - düşük signal_count -> geniş aralık

### Faz Sonu Gate (Test + Push)

```bash
pytest -q tests/test_parallel_threat_intel.py tests/test_phishing_celery.py
git add -A
git commit -m "feat(scoring): add confidence-aware classification and rollout controls"
git push origin feature/phishing-bayesian-scoring
```

---

## Ortak Kalite Kapıları (Her Faz İçin Zorunlu)

1. Testler yeşil
2. Lint/type-check (var olan proje komutları ile)
3. API response backward compatibility kontrolü
4. Service-level smoke:
   - `/api/v2/phishing/stats`
   - `/api/v2/phishing/check-url`
5. Hata loglarında yeni exception pattern olmaması

## Riskler ve Önlemler

- **Risk:** False positive artışı  
  **Önlem:** Source weight kalibrasyonu + shadow log
- **Risk:** WHOIS latency  
  **Önlem:** timeout + cache + fallback penalty
- **Risk:** API sözleşmesi kırılması  
  **Önlem:** contract test + eski alanları koruma
- **Risk:** CPU yük artışı  
  **Önlem:** concurrency=1 + timeout + selective signal execution

## Tamamlanma Kriteri

- Yeni model production’da aktif
- En az 100 örnek URL üzerinde eski/yeni skor karşılaştırma raporu
- Kritik phishing örneklerinde yakalama oranı düşmeden false positive kontrol altında
- Endpoint performansı kabul edilen SLA içinde
