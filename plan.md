# Phishing analizini 20s altına indirme planı

## Amaç
Mevcut 3–4 dakikalık sonuç süresini 20 saniye altına çekmek. Ana yavaşlık: tek işçi (concurrency=1), Playwright/Gemini ve OCR gibi ağır adımların her istekte tekrar yüklenmesi ve threat-intel zincirinin seri çalışması.

---

## A) EasyOCR + IP blacklist tek sefer yükleme (startup)
**Hedef:** Her istekte tekrar yüklenen modelleri ve blacklistleri worker başında belleğe almak.

**Yapılacaklar**
- `threat_intel_local.py` içinde `preload_models()` ekle:
  - EasyOCR reader’ı global singleton olarak başlat.
  - `load_ip_blacklists("/opt/phishing/ip_lists")` çağrısını sadece bir kez yap.
- Celery worker başlatılırken `worker_process_init` sinyaliyle `preload_models()` çağır.
- (Opsiyonel) API tarafında lifespan ile preload (sync path için).

**Test**
- Worker restart sonrası logda OCR/IP load **tek kez** görünsün.
- Aynı URL iki kez tarandığında OCR/IP yükleme logu tekrar etmesin.

---

## B) Celery worker throughput ayarı (concurrency + memory)
**Hedef:** Tek işçiden çıkıp 2–3 paralel iş ile toplam süreyi kısaltmak ve OOM riskini azaltmak.

**Yapılacaklar**
- systemd override:
  - `--concurrency=3 --pool=prefork --max-tasks-per-child=50`
  - `OMP_NUM_THREADS=1` gibi CPU thread kısıtları.
  - `--prefetch-multiplier=1` (kuyruk şişmesini engeller).
- Mevcut swap korunur (4GB).

**Test**
- Aynı anda 3 URL gönder, logda 3 işin “received” satırı gelmeli.
- OOM/WorkerLostError görülmemeli.

---

## C) Threat intel katmanlarını paralelleştir
**Hedef:** Seri çalışan 6+ dış/yerel kontrolü en yavaş servis kadar süreye indir.

**Yapılacaklar**
- `run_threat_intelligence()` içinde:
  - `analyze_screenshot`, `check_google_safe_browsing`, `check_virustotal_local`, `check_abuseipdb_local`, `domain_age`, `urlhaus/spamhaus/threatfox` çağrılarını **aynı anda** çalıştır.
  - `ThreadPoolExecutor` veya `asyncio.gather` kullan.
  - Her call kendi timeout’unu korusun; hata olan kaynak skip edilsin.
- `load_ip_blacklists()` çağrısı burada **kaldırılır** (A kısmıyla preload).

**Test**
- Tek URL için süre ölçümü (curl + time).
- Çıktı skorları öncekiyle uyumlu olmalı (risk level aynı/benzer).

---

## D) Playwright pool + fast-path yanıt (kritik)
**Hedef:** İlk yanıtı 2–3 sn’ye indirmek, ağır analiz async devam etsin.

**Yapılacaklar**
- Playwright’ı request başına açmak yerine **pool** kullan (worker init’te 1–2 browser).
- `check-url` endpoint’i:
  - hızlı katmanları çalıştır (DB, whitelist, ML, HTML).
  - kesin sonuç varsa hemen döndür.
  - değilse Celery ile deep-analysis başlatıp `job_id` döndür.
- `/result/{job_id}` endpoint: Redis’ten sonucu çekip döndür.

**Test**
- URL check isteği 2–3 sn içinde `status: analyzing + job_id` döndürmeli.
- `result/{job_id}` 1–2 dk içinde `complete` dönmeli.
- Frontend poll davranışı sorunsuz olmalı.

---

## Beklenen kazanım (hedef)
- OCR yükleme: **~30 sn → 0**
- IP blacklist: **~2–3 sn → 0**
- Threat intel seri: **~15–30 sn → paralel 3–5 sn**
- Playwright açılışı: **~5–10 sn → pool 1–2 sn**
- İlk yanıt: **3–4 dk → 2–3 sn**
