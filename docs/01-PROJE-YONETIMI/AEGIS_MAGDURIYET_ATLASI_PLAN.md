# Aegis Mağduriyet Atlası — Kesinleştirilmiş Plan (v2)

## 1) Karar Özeti

1. **`threat_intel_cache.db` kullanılmayacak.**
2. Bu modül için ayrı DB açılacak: **`victim_atlas.db`**.
3. Veri toplama işi sunucuda **günde 1 kez Celery** ile çalışacak.
4. Kaynaklar güvenilirlik seviyesine göre sabitlenecek (Tier-1/Tier-2).

---

## 2) Modül Hedefi

“Aegis Mağduriyet Atlası”, phishing/sosyal mühendislik olaylarını teknik IOC listesi yerine:

- vaka hikayesi,
- saldırı yöntemi,
- mağduriyet tipi,
- kritik uyarı,
- korunma adımları

formatında kartvizit yapısında sunar.

---

## 3) Ayrı Veritabanı Tasarımı

## 3.1 DB Dosyası

- Yol: `data/victim_atlas.db` (prod: `/var/www/aegis_nexus/data/victim_atlas.db`)
- Bu DB sadece “Mağduriyet Atlası” içindir.

## 3.2 Tablolar

1. `sources_registry`
   - `id`, `name`, `base_url`, `trust_tier`, `enabled`, `last_success_at`, `last_error`

2. `raw_documents`
   - `id`, `source_id`, `external_id`, `url`, `title`, `published_at`, `fetched_at`, `raw_text`, `lang`, `hash`
   - Dedup: `UNIQUE(source_id, external_id)` + `hash` index

3. `victim_cases`
   - `id`, `case_slug`, `case_title`, `incident_period_start`, `incident_period_end`
   - `attack_method`, `loss_type`, `target_platform`
   - `critical_warning`, `narrative_summary`, `defense_steps_json`
   - `confidence_score`, `severity_score`
   - `first_seen`, `last_seen`, `created_at`, `updated_at`

4. `victim_case_evidence`
   - `id`, `case_id`, `raw_document_id`, `evidence_snippet`, `evidence_weight`

5. `ingest_runs`
   - `id`, `started_at`, `finished_at`, `status`, `documents_fetched`, `cases_created`, `cases_updated`, `errors_json`

## 3.3 Performans Politikası

1. “Hot set” = son/önemli **1000 vaka**.
2. UI listelemeleri hot set üstünden döner.
3. Arşiv kayıtlar DB’de kalır ama default sorguya girmez.

---

## 4) Kaynaklar (Kesin Liste)

## 4.1 Tier-1 (Birincil, günlük zorunlu)

1. **Resmi kurum duyuruları / CERT kaynakları**
   - US-CERT/CISA alert akışları
   - ENISA yayınları
   - TR kurum duyuruları (USOM / BTK benzeri resmi duyurular, erişilebilir feed/API varsa)

2. **Güvenlik vendor blog / threat advisory**
   - Microsoft Security Blog
   - Google TAG / Security Blog
   - Cloudflare / Palo Alto Unit42 / Kaspersky / Proofpoint gibi güvenilir araştırma blogları (RSS/API üzerinden)

3. **Haber kaynakları (editoryal filtreli)**
   - Sadece whitelist’e alınmış siber güvenlik haber siteleri

## 4.2 Tier-2 (İkincil, kontrollü)

1. Reddit (belirli subreddit whitelist)
2. X/Twitter (sadece doğrulanmış hesap listesi + anahtar kelime)
3. Şikayet platformları (erişim koşullarına ve TOS’a uyumlu yöntemle, gerekirse manuel/yarı-otomatik)

## 4.3 Hariç Tutulacaklar

1. Kimliği belirsiz scraping dump siteleri
2. TOS ihlali gerektiren çekimler
3. Kanıt linki olmayan, doğrulanamayan anonim içerikler (LLM’de düşük güven olarak etiketlenir, default UI’da gösterilmez)

---

## 5) NLP/LLM Çıkarım Kuralları (Kesin)

Her ham dokümandan aşağıdakiler zorunlu çıkarılır:

1. `attack_method`: phishing / smishing / vishing / social_engineering / malware_assisted
2. `loss_type`: bank_account / social_media / ecommerce / corporate_account / crypto_wallet / device_compromise
3. `target_platform`
4. `critical_warning` (1 cümle)
5. `defense_steps_json` (3-7 adım)
6. `confidence_score` (0-100)

**Yayın kuralı:**

- `confidence_score < 60` => “low confidence”, default listede gizli.
- `>= 60` => normal listede.

---

## 6) Celery Çalışma Modeli (Sunucu)

## 6.1 Yeni Tasklar

1. `victim_atlas_ingest_daily`
   - Kaynaklardan ham doküman çekme + parse + dedup

2. `victim_atlas_enrich_cases`
   - LLM extraction + case merge/update

3. `victim_atlas_prune_hotset`
   - 1000 hot set güncelleme + bakım

## 6.2 Zamanlama (Kesin)

1. Her gün **03:30 UTC**: `victim_atlas_ingest_daily`
2. Her gün **03:50 UTC**: `victim_atlas_enrich_cases`
3. Her gün **04:10 UTC**: `victim_atlas_prune_hotset`

## 6.3 Retry / Hata Politikası

1. Retry: 3 deneme, artan backoff
2. Kaynak bazlı hata logları `ingest_runs.errors_json` içinde tutulur
3. Kaynak 7 gün üst üste fail olursa `sources_registry.enabled=0` + alarm

---

## 7) API Sözleşmesi

`/api/v2/victim-atlas`

1. `GET /cases`
   - filtre: `attack_method`, `loss_type`, `severity_min`, `q`
   - pagination: `page`, `limit`
   - default: `confidence>=60`, `hot_set_only=true`

2. `GET /cases/{id}`
   - tam vaka + evidence listesi + savunma adımları

3. `GET /stats`
   - toplam vaka, yöntem dağılımı, son 30 gün trend

4. `GET /ingest/health` (admin)
   - son run durumu + kaynak sağlığı

5. `POST /ingest/run` (admin)
   - manuel tetikleme

---

## 8) UI/UX (Kartvizit)

1. Kart ön yüz:
   - Vaka adı
   - Zaman çizelgesi
   - Saldırı yöntemi
   - Kritik uyarı

2. Kart arka yüz:
   - “Nasıl korunurdun?” adım adım rehber
   - “Bu vakada en kritik hata” bölümü

3. Filtreler:
   - yöntem, kayıp tipi, platform, güven skoru

4. Listeleme:
   - varsayılan: yüksek güven + yüksek etki vakaları

---

## 9) Güvenlik / Uyum

1. PII maskeleme zorunlu (telefon, mail, TCKN benzeri pattern)
2. Kaynak URL + snippet tutulur, ham kişisel içerik minimumda tutulur
3. Admin endpointleri API key ile korunur
4. Celery loglarında secret/PII redaction uygulanır

---

## 10) Uygulama Fazları

## Faz 1 — Altyapı

1. `victim_atlas.db` + migration
2. kaynak registry + ingest_runs
3. temel API (`/cases`, `/stats`)

## Faz 2 — Ingest Pipeline

1. Tier-1 connector’lar
2. Celery daily schedule
3. dedup + case merge

## Faz 3 — Enrichment & UI

1. LLM extraction stabilization
2. kartvizit UI
3. hot set optimizasyonu

## Faz 4 — Operasyon

1. ingest health dashboard
2. kaynak kalite skoru
3. alarm ve otomatik disable mekanizması

---

## 11) Kesin TODO

1. `victim_atlas.db` için SQLAlchemy model setini çıkar.
2. `sources_registry` whitelist’i doldur (Tier-1/Tier-2).
3. `victim_atlas_ingest_daily` Celery taskını yaz.
4. `victim_atlas_enrich_cases` taskını yaz.
5. `victim_atlas_prune_hotset` taskını yaz.
6. Celery beat schedule’ı 03:30/03:50/04:10 UTC olarak ekle.
7. `/api/v2/victim-atlas/cases` + pagination/filter implement et.
8. `/api/v2/victim-atlas/stats` implement et.
9. `/api/v2/victim-atlas/ingest/health` admin endpoint ekle.
10. Kartvizit UI bileşenlerini oluştur.
11. PII maskeleme filtresini ingestion öncesi zorunlu kıl.
12. Sunucuda günlük run + log + hata alarmını aktive et.

---

## 12) Kullanılacak .continue Skill Yaklaşımları

1. `api-endpoint-builder`: endpoint sözleşmesi ve pagination standardı
2. `performance-optimizer`: hot set, indeks, sorgu optimizasyonu
3. `bug-hunter`: ingest hata izolasyonu, retry ve root-cause loglama
4. `audit-skills`: veri güvenliği, kötü niyetli içerik/payload kontrolleri
