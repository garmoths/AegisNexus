---
name: AegisNexus audit cleanup
overview: .continue içindeki aktif 8 skill temel alınarak AegisNexus için profesyonel, uygulanabilir ve önceliklendirilmiş audit TODO planı.
todos:
  - id: p0-secrets-and-access
    content: Secret sızıntısı, endpoint erişim kontrolü ve deploy güvenliğini kapat
    status: pending
  - id: p0-runtime-breaking-fixes
    content: Model/route/cache sözleşme bozukluklarını düzelt
    status: pending
  - id: p1-repo-and-legacy-cleanup
    content: Repo hijyenini düzelt, artık dosyaları temizle, legacy parçaları sınıflandır
    status: pending
  - id: p1-quality-gates
    content: Lint/test/CI kapılarını aktif et ve frontend kırıklarını kapat
    status: pending
  - id: p1-architecture-convergence
    content: Backend ve frontend için canonical stack kararı alıp geçiş planı yaz
    status: pending
  - id: p2-docs-and-runbook
    content: Dokümanları aktif-arşiv olarak düzenle ve gerçek çalışma modeliyle eşitle
    status: pending
isProject: false
---

# AegisNexus Skill-Bazli Profesyonel TODO Plani

## Kullanilan Skill Seti (.continue/skills)
- `systematic-debugging`
- `verification-before-completion`
- `api-security-testing`
- `ethical-hacking-methodology`
- `burp-suite-testing`
- `test-driven-development`
- `webapp-testing`
- `finishing-a-development-branch`

## Skill -> Is Paketi Eslestirmesi
- **Guvenlik denetimi ve sertlestirme:** `api-security-testing` + `ethical-hacking-methodology` + `burp-suite-testing`
- **Kok neden analizi ve hata kapatma:** `systematic-debugging`
- **Kalici kalite ve regresyon onleme:** `test-driven-development` + `webapp-testing`
- **Teslim ve kapanis disiplini:** `verification-before-completion` + `finishing-a-development-branch`

## Oncelikli TODO Listesi

### P0 - Guvenlik ve Canli Riskler
- [ ] `.env` ve dokumanlardaki credential kalintilarini sanitize et; tum expose secretlari rotate et.
- [ ] Mutating/maliyetli endpointlerde auth/authz zorunlulugu uygula.
- [ ] Deploy entrypoint uyumsuzlugunu gider (canonical app hedefi).
- [ ] API endpoint inventory + broken auth + IDOR/BOLA + input validation + bilgi sizmasi kontrollerini tamamla.

### P0 - Calisan Sistemi Bozan Teknik Hatalar
- [ ] `created_at` vs `submission_time` model/route uyumsuzlugunu duzelt.
- [ ] `cache_db.py` kolon/insert-update tutarsizliklarini tek semaya getir.
- [ ] URL normalize donus sozlesmesini (dict/tuple) tek standarda sabitle.
- [ ] Honeypot frontend/backend path uyumsuzluklarini tek API contract altinda duzelt.

### P1 - Repo Hijyeni ve Kod Artiklari
- [ ] `.gitignore`'u standart hale getir (env/venv/db/log/build/IDE).
- [ ] Runtime artifactlari gitten temizle (`venv`, `*.db`, `logs`, `celerybeat-schedule`, `react-build.tar.gz`).
- [ ] Orphan/legacy adaylarini siniflandir: hemen sil, gecis sonrasi sil, tutulacak.
- [ ] Duplicate endpoint ve mount edilmeyen router dosyalarini referans taramasi + smoke test ile karara bagla.

### P1 - Kalite Kapilari
- [ ] `frontend-react` lint kiriklarini release-blocking seviyede kapat.
- [ ] CI'ya lint + test + temel guvenlik scan (`pip-audit`) adimlari ekle.
- [ ] Kritik backend pathleri icin test-first yaklasimla baseline test seti olustur.
- [ ] Playwright tabanli temel smoke/regresyon testlerini web akislarina ekle.

### P1 - Mimari Sadelestirme
- [ ] FastAPI vs Flask icin canonical backend kararini yazili hale getir.
- [ ] `frontend` vs `frontend-react` icin tek birincil yuzeyi sec ve migration/deprecation plani cikar.
- [ ] API versiyon standardini (v1/v2) tek kaynaga indir.

### P2 - Dokuman ve Isletim Standardi
- [ ] `docs` altinda active/archive ayrimini netlestir.
- [ ] README ve API entegrasyon dokumanlarini gercek endpoint/port/calisma modeline hizala.
- [ ] Operasyon runbook'una deploy + healthcheck + rollback + verification adimlarini ekle.

## Silinsin mi? Islevi var mi? Karar Politikasi
- **Hemen silinebilir:** ortam ve runtime state dosyalari (build/cache/log/db/venv).
- **Kosullu silinebilir:** mount edilmeyen routerlar ve duplicate handlerlar (once referans taramasi + test).
- **Gecis plani olmadan silinmez:** legacy Flask katmani ve gecis bagimliligi olan dosyalar.

## Definition of Done
- P0 maddeleri kapali ve tekrar test edilmis.
- CI yesil (lint + test + security checks).
- Canonical mimari karari dokumanlasmis.
- Repo artifact/secret kaynakli risklerden arindirilmis.
- PR kapanis raporunda `checks passed`, `residual risk`, `cleanup status` alanlari doldurulmus.