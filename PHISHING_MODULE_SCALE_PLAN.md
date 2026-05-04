# 🛡️ Phishing Modülü — Ölçeklendirme & Dedektör Güçlendirme Planı

**Hazırlanma Tarihi:** 3 Mayıs 2026  
**Son Güncelleme:** 3 Mayıs 2026  
**Hedef Sunucu:** `104.248.45.198` — `/var/www/aegis_nexus`  
**Mevcut Stack:** FastAPI · SQLAlchemy · PostgreSQL · SQLite (cache) · **Redis** (A1 ile eklendi) · Celery (honeypot'ta var, phishing'de yok) · Playwright · Gemini 2.0 Flash

---

## 📋 Genel Bakış

| # | Bölüm | Etki | Tahmini Süre |
|---|-------|------|-------------|
| A1 | ~~Redis cache katmanı~~ | ✅ TAMAMLANDI — Trafiğin %60-70'ini keser | 3 Mayıs 2026 |
| A2 | ~~Celery async pipeline~~ | ✅ TAMAMLANDI — run_quick_checks + run_heavy_analysis task + /result/{job_id} | 4 Mayıs 2026 |
| A3 | ~~Playwright browser pool~~ | ✅ TAMAMLANDI — process-başı 1 persistent browser, context izolasyonu | 4 Mayıs 2026 |
| A4 | ~~Paralel threat intel~~ | ✅ TAMAMLANDI — 5 task eş zamanlı, ThreadPoolExecutor | 4 Mayıs 2026 |
| B1 | ~~HTML derin analizi~~ | ✅ TAMAMLANDI — AI'sız marka/credential tespiti | 4 Mayıs 2026 |
| B2 | pHash logo karşılaştırma | ⏳ Bekliyor — Gemini kotasını %40 korur | 3-4 saat |
| B3 | EasyOCR metin okuma | ⏳ Bekliyor — Ekstra güven katmanı | 2-3 saat |
| B4 | ~~Koşullu Gemini~~ | ✅ TAMAMLANDI — Günlük ~%80 kota tasarrufu | 3 Mayıs 2026 |
| C1 | Frontend polling UI | UX iyileştirmesi | 2-3 saat |

**Öneri uygulama sırası:** ~~A1~~ ✅ → ~~B4~~ ✅ → ~~B1~~ ✅ → ~~A4~~ ✅ → ~~A2~~ ✅ → ~~A3~~ ✅ → **B2** → B3 → C1

---

## BÖLÜM A: PERFORMANS & ÖLÇEKLENDİRME

---

### A1. Redis Cache Katmanı

**Mevcut durum:**  
`cache_db.py` — SQLite `threat_intel_cache.db` dosyasına yazar.  
`get_cached_scan_result()` ve `write_phishing_url()` SQLite bağlantısı açar.  
2-3k günlük sorguda her cache hit için disk I/O oluşur.

**Hedef:**  
Sıcak cache (son 30 gün tarama sonuçları) Redis'e taşınır. SQLite, kalıcı geçmiş ve IOC kaydı için korunur. Redis kurulu değilse graceful fallback ile SQLite çalışmaya devam eder.

**Değişecek dosyalar:**
- `modules/phishing_detector/cache_db.py` — Redis bağlantısı + fallback
- `modules/phishing_detector/router.py` — cache read sırası değişir

**Uygulama:**

```python
# modules/phishing_detector/redis_cache.py — YENİ DOSYA
import redis
import json
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

SCAN_CACHE_TTL = 60 * 60 * 24 * 30   # 30 gün
THREAT_INTEL_CACHE_TTL = 60 * 60 * 6  # 6 saat (Spamhaus, URLhaus vb.)

_redis_client: Optional[redis.Redis] = None

def get_redis() -> Optional[redis.Redis]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        host = os.getenv("REDIS_HOST", "127.0.0.1")
        port = int(os.getenv("REDIS_PORT", "6379"))
        _redis_client = redis.Redis(
            host=host, port=port,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        _redis_client.ping()
        logger.info("Redis bağlantısı kuruldu")
        return _redis_client
    except Exception as e:
        logger.warning(f"Redis kullanılamıyor, SQLite fallback aktif: {e}")
        _redis_client = None
        return None

def redis_set_scan(url_hash: str, result: Dict) -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        r.setex(f"scan:{url_hash}", SCAN_CACHE_TTL, json.dumps(result, default=str))
        return True
    except Exception as e:
        logger.warning(f"Redis write failed: {e}")
        return False

def redis_get_scan(url_hash: str) -> Optional[Dict]:
    r = get_redis()
    if r is None:
        return None
    try:
        data = r.get(f"scan:{url_hash}")
        return json.loads(data) if data else None
    except Exception as e:
        logger.warning(f"Redis read failed: {e}")
        return None

def redis_set_threat(key: str, data: Dict, ttl: int = THREAT_INTEL_CACHE_TTL) -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        r.setex(f"ti:{key}", ttl, json.dumps(data, default=str))
        return True
    except Exception as e:
        logger.warning(f"Redis threat cache write failed: {e}")
        return False

def redis_get_threat(key: str) -> Optional[Dict]:
    r = get_redis()
    if r is None:
        return None
    try:
        data = r.get(f"ti:{key}")
        if data:
            result = json.loads(data)
            result["_cache_hit"] = True
            return result
        return None
    except Exception as e:
        logger.warning(f"Redis threat cache read failed: {e}")
        return None

def redis_incr_gemini_counter() -> int:
    r = get_redis()
    if r is None:
        return 0
    try:
        pipe = r.pipeline()
        pipe.incr("gemini:daily_count")
        pipe.expire("gemini:daily_count", 86400)
        results = pipe.execute()
        return int(results[0])
    except Exception:
        return 0

def redis_get_gemini_count() -> int:
    r = get_redis()
    if r is None:
        return 0
    try:
        return int(r.get("gemini:daily_count") or 0)
    except Exception:
        return 0
```

**router.py değişikliği — cache read sırası:**

```python
# router.py içinde check_url fonksiyonunda:
# ÖNCE: sadece SQLite
cached_result = get_cached_scan_result(requested_url, days=30)

# SONRA: Redis önce, SQLite fallback
from .redis_cache import redis_get_scan
from .url_normalize import normalize_url_record

norm = normalize_url_record(requested_url)
url_hash = norm.get("url_hash", "")

cached_result = redis_get_scan(url_hash)   # ~0.3ms
if not cached_result:
    cached_result = get_cached_scan_result(requested_url, days=30)  # fallback

# Yazarken her ikisine de yaz:
redis_set_scan(url_hash, result)
write_phishing_url(...)
```

**Sunucuda kurulum:**

```bash
sudo apt install redis-server -y
sudo systemctl enable redis-server
sudo systemctl start redis-server
# Test:
redis-cli ping  # PONG

pip install redis
```

**Testler:**

```python
# tests/test_redis_cache.py
def test_redis_set_get():
    from modules.phishing_detector.redis_cache import redis_set_scan, redis_get_scan
    fake_result = {"url": "https://test.com", "safety_score": 85}
    redis_set_scan("abc123", fake_result)
    cached = redis_get_scan("abc123")
    assert cached is not None
    assert cached["safety_score"] == 85

def test_redis_fallback_when_unavailable(monkeypatch):
    # Redis kapalıyken None dönmeli, hata fırlatmamalı
    from modules.phishing_detector import redis_cache
    monkeypatch.setattr(redis_cache, "_redis_client", None)
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")  # port 9999 gibi kapalı port test edilebilir
    result = redis_get_scan("nonexistent")
    assert result is None  # Hata değil, None

def test_gemini_counter():
    from modules.phishing_detector.redis_cache import redis_incr_gemini_counter, redis_get_gemini_count
    before = redis_get_gemini_count()
    redis_incr_gemini_counter()
    after = redis_get_gemini_count()
    assert after == before + 1
```

---

### A2. Celery Async Pipeline

**Mevcut durum:**  
`router.py` → `calculate_safety_score()` senkron, ~15-30 saniye bloklar.  
FastAPI worker o süre boyunca başka istek alamaz. 1GB RAM sunucuda paralel istek = OOM.

**Hedef:**  
- `/check-url` önce hızlı katmanları (~200ms) senkron çalıştırır
- Eğer kesin sonuç yoksa Celery kuyruğuna ağır analizi atar, `job_id` döner
- Frontend `job_id` ile `/result/{job_id}` polling yapar

**Celery zaten kurulu:** `modules/honeypot/celery_tasks.py` örnek alınabilir.

**Değişecek dosyalar:**
- `modules/phishing_detector/celery_tasks.py` — YENİ
- `modules/phishing_detector/scanner.py` — `run_quick_checks()` fonksiyonu
- `modules/phishing_detector/router.py` — endpoint değişimi

**Uygulama:**

```python
# modules/phishing_detector/celery_tasks.py — YENİ DOSYA
import uuid
import json
import logging
from app.celery_app import celery   # mevcut celery instance
from .scanner import calculate_safety_score
from .redis_cache import redis_set_scan, redis_get_scan
from .url_normalize import normalize_url_record

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=2, time_limit=120)
def run_heavy_analysis(self, url: str, job_id: str):
    """Playwright + Gemini + tüm threat intel burada çalışır."""
    try:
        result = calculate_safety_score(url)
        norm = normalize_url_record(url)
        url_hash = norm.get("url_hash", "")

        # Sonucu job_id ve url_hash ile Redis'e yaz
        import redis as _redis
        r = _redis.Redis(host="127.0.0.1", decode_responses=True)
        r.setex(f"job:{job_id}", 3600, json.dumps(result, default=str))
        redis_set_scan(url_hash, result)

        logger.info(f"Heavy analysis done: {url} job={job_id}")
        return result
    except Exception as exc:
        logger.error(f"Heavy analysis failed: {url} — {exc}")
        raise self.retry(exc=exc, countdown=5)
```

```python
# scanner.py — yeni fonksiyon ekle (mevcut calculate_safety_score dokunulmaz)
def run_quick_checks(url: str) -> dict:
    """
    ~200ms'de tamamlanan hızlı katmanlar:
    - Whitelist kontrolü
    - Internal DB (exact match)
    - PhishTank DB
    - ML sınıflandırma
    Kesin sonuç varsa definitive=True döner.
    """
    from .scanner import (
        WHITELIST, PHISHTANK_DB, check_whitelist,
        normalize_url_record, ML_MODEL
    )
    # ... mevcut Katman 1-3 + ML kodunu buraya taşı
    # Kesin phishing/güvenli ise: return {..., "definitive": True}
    # Belirsizse: return {..., "definitive": False, "preliminary_score": score}
```

```python
# router.py endpoint değişimi
import uuid
from .celery_tasks import run_heavy_analysis
from .redis_cache import redis_get_scan

@router.post("/check-url")
async def check_url(request: CheckURLRequest, db: Session = Depends(get_db)):
    requested_url = request.url.strip()

    # 1. Redis cache (< 1ms)
    norm = normalize_url_record(requested_url)
    url_hash = norm.get("url_hash", "")
    cached = redis_get_scan(url_hash)
    if cached and not request.force_fresh:
        cached["cache"] = "redis-hit"
        return cached

    # 2. SQLite cache fallback
    if not request.force_fresh:
        cached = get_cached_scan_result(requested_url, days=30)
        if cached:
            cached["cache"] = "sqlite-hit"
            return cached

    # 3. Hızlı katmanlar (~200ms)
    quick = run_quick_checks(requested_url)
    if quick.get("definitive"):
        # Kesin sonuç → direkt dön, Celery'ye gerek yok
        write_phishing_url(url=requested_url, ...)
        return quick

    # 4. Ağır analizi async kuyruğa at
    job_id = str(uuid.uuid4())
    run_heavy_analysis.delay(requested_url, job_id)

    return {
        **quick,
        "status": "analyzing",
        "job_id": job_id,
        "cache": "none",
        "message": "Derin analiz kuyruğa alındı, lütfen bekleyin...",
    }

@router.get("/result/{job_id}")
async def get_job_result(job_id: str):
    import redis as _redis
    r = _redis.Redis(host="127.0.0.1", decode_responses=True)
    data = r.get(f"job:{job_id}")
    if data:
        result = json.loads(data)
        result["status"] = "complete"
        return result
    return {"status": "pending", "job_id": job_id}
```

**Testler:**

```python
# tests/test_phishing_celery.py
def test_quick_checks_phishtank_returns_definitive():
    # PhishTank'te olan domain → hızlı katmanda yakalanmalı
    result = run_quick_checks("http://known-phishing-domain.tk")
    # PhishTank DB'de varsa:
    # assert result["definitive"] == True
    # assert result["safety_score"] == 0

def test_quick_checks_whitelist_returns_definitive():
    result = run_quick_checks("https://ziraatbank.com.tr")
    assert result.get("is_whitelisted") == True
    assert result.get("definitive") == True

def test_job_result_pending_on_new_job():
    import uuid
    from fastapi.testclient import TestClient
    job_id = str(uuid.uuid4())
    # Yeni oluşturulmuş, henüz tamamlanmamış job
    response = client.get(f"/api/v2/phishing/result/{job_id}")
    assert response.json()["status"] == "pending"

def test_celery_task_writes_to_redis(mock_calculate_safety_score):
    # calculate_safety_score mock'lanır
    job_id = str(uuid.uuid4())
    run_heavy_analysis("https://test.com", job_id)
    import redis
    r = redis.Redis(host="127.0.0.1", decode_responses=True)
    data = r.get(f"job:{job_id}")
    assert data is not None
```

---

### A3. Playwright Browser Pool

**Mevcut durum:**  
`screenshot_analyzer.py` → `_capture_screenshot_base64()` her çağrıda:  
`sync_playwright().__enter__()` → `chromium.launch()` → ~3-5 sn overhead, ~300MB RAM  
2 paralel istek = 600MB RAM → 1GB sunucu için kritik

**Hedef:**  
Uygulama başlarken 3 Chromium instance açılır, pool'a alınır.  
Her tarama isteği mevcut browser'ı alır, işi bitince iade eder.  
Sabit RAM: ~900MB, launch overhead sıfır.

**Not:** Bu değişiklik `sync_playwright` → `async_playwright` geçişi gerektirir.  
A2 (Celery) uygulandıktan sonra yapılmalıdır çünkü Celery worker async loop ile daha temiz entegre edilir.

**Değişecek dosyalar:**
- `modules/phishing_detector/playwright_pool.py` — YENİ
- `modules/phishing_detector/screenshot_analyzer.py` — pool kullanımı

**Uygulama:**

```python
# modules/phishing_detector/playwright_pool.py — YENİ DOSYA
import asyncio
import logging
from contextlib import asynccontextmanager
from playwright.async_api import async_playwright, Browser

logger = logging.getLogger(__name__)

_pool: asyncio.Queue = None
_playwright_instance = None
POOL_SIZE = 3

async def init_pool():
    global _pool, _playwright_instance
    _pool = asyncio.Queue(maxsize=POOL_SIZE)
    _playwright_instance = await async_playwright().start()
    for i in range(POOL_SIZE):
        browser = await _playwright_instance.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--memory-pressure-off",
                "--disable-background-networking",
            ]
        )
        await _pool.put(browser)
        logger.info(f"Browser {i+1}/{POOL_SIZE} pool'a eklendi")
    logger.info(f"Playwright pool hazır ({POOL_SIZE} instance)")

@asynccontextmanager
async def acquire_browser() -> Browser:
    """Pool'dan browser al, bitince iade et."""
    global _pool
    if _pool is None:
        await init_pool()
    browser = await asyncio.wait_for(_pool.get(), timeout=30)
    try:
        yield browser
    finally:
        await _pool.put(browser)

async def close_pool():
    global _pool, _playwright_instance
    if _pool:
        while not _pool.empty():
            browser = await _pool.get()
            await browser.close()
    if _playwright_instance:
        await _playwright_instance.stop()
    logger.info("Playwright pool kapatıldı")
```

```python
# FastAPI lifespan'e ekle (app/main.py veya app/api_server.py):
from contextlib import asynccontextmanager
from modules.phishing_detector.playwright_pool import init_pool, close_pool

@asynccontextmanager
async def lifespan(app):
    await init_pool()
    yield
    await close_pool()

app = FastAPI(lifespan=lifespan)
```

**Testler:**

```python
# tests/test_playwright_pool.py
import pytest
import asyncio

@pytest.mark.asyncio
async def test_pool_init_creates_browsers():
    from modules.phishing_detector.playwright_pool import init_pool, _pool, close_pool
    await init_pool()
    assert _pool.qsize() == 3
    await close_pool()

@pytest.mark.asyncio
async def test_pool_acquire_release():
    from modules.phishing_detector.playwright_pool import init_pool, acquire_browser, _pool, close_pool
    await init_pool()
    initial_size = _pool.qsize()
    async with acquire_browser() as browser:
        assert _pool.qsize() == initial_size - 1
        assert browser is not None
    assert _pool.qsize() == initial_size  # İade edilmeli
    await close_pool()

@pytest.mark.asyncio
async def test_pool_concurrent_requests():
    # 3 instance varsa 4. istek beklemeli
    from modules.phishing_detector.playwright_pool import init_pool, acquire_browser, close_pool
    await init_pool()
    results = await asyncio.gather(*[
        acquire_browser().__aenter__() for _ in range(3)
    ])
    assert len(results) == 3
    await close_pool()
```

---

### A4. Paralel Threat Intel

**Mevcut durum:**  
`threat_intel.py` → `run_threat_intelligence()` içinde 7 kaynak **sırayla** çalışır:  
Screenshot → VirusTotal → GSB → AbuseIPDB → URLhaus → Spamhaus Domain → Spamhaus IP → ThreatFox  
Her biri 1-3 sn → toplam ~10-15 sn

**Hedef:**  
Screenshot hariç tüm kaynaklar `asyncio.gather()` ile paralel çalışır.  
Toplam süre: en yavaş tek kaynak kadar (~2-3 sn)

**Değişecek dosyalar:**
- `modules/phishing_detector/threat_intel.py` — `run_threat_intelligence()` async'e çevrilir
- `modules/phishing_detector/scanner.py` — async çağrı

**Uygulama:**

```python
# threat_intel.py — run_threat_intelligence async versiyonu

import asyncio

async def run_threat_intelligence_async(url, http_meta=None, page_text="", is_whitelisted=False):
    results = {
        "screenshot_analysis": None, "virustotal": None,
        "google_safe_browsing": None, "abuseipdb": None,
        "total_penalty": 0, "findings": [], "sources": [], "validated": False,
    }

    # Screenshot önce (diğerlerine bağımlı değil ama ağır, paralelde başlat)
    screenshot_task = asyncio.create_task(
        asyncio.to_thread(analyze_screenshot, url=url, http_meta=http_meta, page_text=page_text)
    )

    # Hafif kaynaklar paralel
    async def _vt(): return await asyncio.to_thread(_check_virustotal_local_sync, url)
    async def _gsb(): return await asyncio.to_thread(check_google_safe_browsing, url)
    async def _abuseipdb(): return await asyncio.to_thread(_check_abuseipdb_local_sync, url)
    async def _urlhaus(): return await asyncio.to_thread(_check_urlhaus_sync, url)
    async def _spamhaus_domain(): return await asyncio.to_thread(_check_spamhaus_domain_sync, url)
    async def _spamhaus_ip(): return await asyncio.to_thread(_check_spamhaus_ip_sync, url)
    async def _threatfox(): return await asyncio.to_thread(_check_threatfox_sync, url)

    intel_tasks = [_vt(), _gsb(), _abuseipdb(), _urlhaus(),
                   _spamhaus_domain(), _spamhaus_ip(), _threatfox()]

    # Screenshot ve intel aynı anda çalışır
    shot_result, *intel_results = await asyncio.gather(
        screenshot_task, *intel_tasks,
        return_exceptions=True
    )

    # Sonuçları işle...
    _process_screenshot_result(results, shot_result)
    _process_intel_results(results, intel_results)

    return results

# scanner.py'de çağrı:
import asyncio
threat_result = asyncio.run(run_threat_intelligence_async(url, http_meta, page_text, is_whitelisted))
# Veya Celery worker içinde zaten async context varsa:
# threat_result = await run_threat_intelligence_async(...)
```

**Testler:**

```python
# tests/test_threat_intel_parallel.py
import asyncio
import time
import pytest

@pytest.mark.asyncio
async def test_parallel_is_faster_than_sequential(mock_all_intel_sources):
    # Her kaynak 1 sn geciktiriliyor (mock)
    # Paralel: ~1 sn, sıralı: ~7 sn beklenir
    start = time.time()
    from modules.phishing_detector.threat_intel import run_threat_intelligence_async
    result = await run_threat_intelligence_async("https://test.com")
    elapsed = time.time() - start
    assert elapsed < 5  # 7 sıralı yerine 5'ten az olmalı

@pytest.mark.asyncio
async def test_exception_in_one_source_doesnt_fail_others(mock_gsb_raises):
    # GSB hata verse bile diğer kaynaklar sonuç dönmeli
    result = await run_threat_intelligence_async("https://test.com")
    assert result["virustotal"] is not None
    assert result["total_penalty"] >= 0

def test_backward_compat_sync_wrapper():
    # Mevcut senkron çağrı çalışmaya devam etmeli
    from modules.phishing_detector.threat_intel import run_threat_intelligence
    result = run_threat_intelligence("https://google.com")
    assert "total_penalty" in result
```

---

## BÖLÜM B: DEDEKTÖRLERİ GÜÇLENDİRME

---

### B1. HTML Derin Analizi

**Mevcut durum:**  
`scanner.py` → `page_content` (raw HTML) alınıyor ama analizi yüzeysel.  
`ai_analyzer.py` bazı marka kontrolleri yapıyor.

**Hedef:**  
`visual_analyzer.py` içinde `analyze_html()` mevcut `page_content`'ı ayrıştırır:  
BeautifulSoup ile marka taklidi, şifre alanı, kredi kartı formu tespiti yapar.  
**Screenshot bile gerekmez.** Gemini API çağrısından önce çalışır.

**Yeni dosya:** `modules/phishing_detector/visual_analyzer.py`

**Türk bankaları + global markalar listesi:**

```python
BRAND_KEYWORDS = {
    "ziraat": "Ziraat Bankası", "garanti": "Garanti BBVA",
    "akbank": "Akbank", "isbank": "İş Bankası",
    "isbankasi": "İş Bankası", "yapi kredi": "Yapı Kredi",
    "halkbank": "Halkbank", "vakifbank": "VakıfBank",
    "denizbank": "Denizbank", "enpara": "Enpara",
    "paypal": "PayPal", "google": "Google",
    "microsoft": "Microsoft", "apple": "Apple",
    "amazon": "Amazon", "netflix": "Netflix",
    "instagram": "Instagram", "facebook": "Facebook",
    "twitter": "Twitter/X", "whatsapp": "WhatsApp",
    "btcturk": "BtcTurk", "paribu": "Paribu",
}
```

**scanner.py entegrasyonu:**

```python
# scanner.py içinde Katman 7 (AI içerik analizi) öncesine ekle:
from .visual_analyzer import analyze_html

if page_content:
    html_result = analyze_html(page_content, input_url)
    score -= html_result["penalty"]
    risks.extend(html_result["details"])
    sources.append({
        "name": "HTML Analyzer",
        "status": f"ceza={html_result['penalty']}"
    })
    if html_result.get("definitive"):
        # Kesin sonuç → Gemini çağrısını atla
        skip_gemini = True
```

**Testler:**

```python
# tests/test_html_analyzer.py
from modules.phishing_detector.visual_analyzer import analyze_html

def test_brand_impersonation_detected():
    html = "<html><body>Ziraat Bankası giriş sayfası <form><input type='password'/></form></body></html>"
    result = analyze_html(html, "https://totally-not-ziraat.tk")
    assert result["penalty"] >= 60  # Marka + şifre kombinasyonu
    assert any("Ziraat" in d for d in result["details"])
    assert result["definitive"] == True

def test_no_penalty_for_real_bank():
    html = "<html><body>Ziraat Bankası</body></html>"
    result = analyze_html(html, "https://ziraatbank.com.tr")
    # Domain'de 'ziraat' var → ceza olmamalı
    assert result["penalty"] == 0

def test_credit_card_fields_detected():
    html = "<html><body>Kart no: <input/> CVV: <input/></body></html>"
    result = analyze_html(html, "https://phishing.site")
    assert result["penalty"] >= 35
    assert any("kart" in d.lower() or "cvv" in d.lower() for d in result["details"])

def test_password_only_medium_penalty():
    html = "<html><body><input type='password'/></body></html>"
    result = analyze_html(html, "https://unknown.site")
    # Şifre alanı var ama marka yok → orta ceza
    assert 15 <= result["penalty"] <= 25
    assert result["definitive"] == False

def test_max_penalty_cap():
    # Çok fazla indicator olsa bile max 85 olmalı
    html = "<html><body>" + "ziraat <input type='password'/> kart no cvv " * 10 + "</body></html>"
    result = analyze_html(html, "https://evil.tk")
    assert result["penalty"] <= 85
```

---

### B2. pHash Logo Karşılaştırma

**Mevcut durum:**  
Görsel marka tespiti sadece Gemini'ye bırakılmış.

**Hedef:**  
Bilinen marka logolarının perceptual hash'leri `data/logo_hashes.json`'da tutulur.  
Screenshot alındığında tile bazlı pHash karşılaştırması yapılır.  
`distance <= 8` ise `%92+ benzerlik` kabul edilir → `penalty: 60`, Gemini atlanır.

**Kurulum:**

```bash
# Sunucuda:
pip install imagehash Pillow
```

**Logo hash veritabanı oluşturma (bir kez çalıştır):**

```bash
cd /var/www/aegis_nexus
python modules/phishing_detector/build_logo_db.py
# → modules/phishing_detector/data/logo_hashes.json oluşturulur
```

`build_logo_db.py` içeriği:

```python
"""
Marka logolarını indir, pHash ile hash'le, JSON'a kaydet.
python modules/phishing_detector/build_logo_db.py
"""
import json, requests, imagehash
from PIL import Image
from io import BytesIO
from pathlib import Path

Path("modules/phishing_detector/data").mkdir(parents=True, exist_ok=True)

# URL'leri gerçek logo CDN adreslerine güncelle
LOGOS = {
    "ziraat":    ["https://www.ziraatbank.com.tr/.../logo.png"],
    "garanti":   ["https://www.garantibbva.com.tr/.../logo.png"],
    "akbank":    ["https://www.akbank.com/.../logo.png"],
    "isbank":    ["https://www.isbank.com.tr/.../logo.png"],
    "paypal":    ["https://www.paypalobjects.com/webstatic/icon/pp258.png"],
    "microsoft": ["https://img-prod-cms-rt-microsoft-com.akamaized.net/.../microsoft-logo.png"],
    "google":    ["https://www.google.com/images/branding/googlelogo/..."],
}

db = {}
for brand, urls in LOGOS.items():
    db[brand] = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            img = Image.open(BytesIO(resp.content)).convert("RGB")
            h = str(imagehash.phash(img))
            db[brand].append({"url": url, "hash": h})
            print(f"✅ {brand}: {h}")
        except Exception as e:
            print(f"❌ {brand} {url}: {e}")

with open("modules/phishing_detector/data/logo_hashes.json", "w") as f:
    json.dump(db, f, indent=2)
print("Logo DB hazır →", "modules/phishing_detector/data/logo_hashes.json")
```

**Testler:**

```python
# tests/test_phash_logo.py
from modules.phishing_detector.visual_analyzer import check_logo_phash

def test_known_logo_detected(ziraat_logo_screenshot_bytes):
    # Ziraat logosu içeren screenshot fixture
    result = check_logo_phash(ziraat_logo_screenshot_bytes)
    assert result["penalty"] == 60
    assert result["brand"] == "ziraat"
    assert result["definitive"] == True

def test_clean_site_no_match(google_homepage_screenshot_bytes):
    # Google'ın kendi sitesi — logo DB'de var ama domain de google.com
    # Bu testte domain kontrolü yapılmadığı için penalty gelir (expected)
    # Gerçek entegrasyonda domain kontrolü eklenmeli
    result = check_logo_phash(google_homepage_screenshot_bytes)
    # Sonuç: brand bulunabilir veya bulunamaz, penalty 0 veya 60
    assert "penalty" in result
    assert "definitive" in result

def test_empty_screenshot_returns_zero_penalty():
    # 1x1 boş pixel
    from PIL import Image
    import io
    img = Image.new("RGB", (1, 1), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    result = check_logo_phash(buf.getvalue())
    assert result["penalty"] == 0

def test_logo_db_loaded():
    from modules.phishing_detector.visual_analyzer import _LOGO_DB
    # logo_hashes.json varsa en az 1 marka olmalı
    # Yoksa boş dict kabul edilir (graceful)
    assert isinstance(_LOGO_DB, dict)
```

---

### B3. EasyOCR Metin Okuma

**Mevcut durum:**  
Sayfa metni `inner_text("body")` ile alınıyor — JavaScript ile render edilmemiş içerikler eksik kalıyor.  
Screenshot'tan direkt metin okuma yok.

**Hedef:**  
Screenshot PNG'sinden EasyOCR ile Türkçe+İngilizce metin okunur.  
Marka adı veya kimlik bilgisi isteği tespit edilirse penalty uygulanır.  
**Tamamen ücretsiz, offline çalışır.**

**Kurulum:**

```bash
pip install easyocr opencv-python-headless numpy
# İlk çalıştırmada ~200MB model indirir (sunucuya tek seferlik)
```

**Önemli not:**  
EasyOCR modeli başlangıçta RAM'e yüklenir (~400MB). Bu, 1GB RAM sunucuda kritik.  
Çözüm: Celery worker'da `get_ocr_reader()` ile lazy load + process-level singleton.

```python
# EasyOCR'ın sadece bir kez yüklenmesi:
_ocr_reader = None

def get_ocr_reader():
    global _ocr_reader
    if _ocr_reader is None:
        import easyocr
        _ocr_reader = easyocr.Reader(
            ['tr', 'en'],
            gpu=False,
            verbose=False,
            model_storage_directory='/var/www/aegis_nexus/.easyocr_models'
        )
    return _ocr_reader
```

**B3 için RAM kısıtı nedeniyle Öneri:**  
EasyOCR ancak Playwright pool (A3) uygulandıktan sonra devreye alınmalıdır.  
Playwright pool sayesinde kazanılan ~600MB RAM, EasyOCR'ın ~400MB ihtiyacını karşılar.

**Testler:**

```python
# tests/test_ocr_analyzer.py
from modules.phishing_detector.visual_analyzer import analyze_with_ocr

def test_ocr_detects_brand_in_screenshot(ziraat_screenshot_bytes):
    result = analyze_with_ocr(ziraat_screenshot_bytes, domain="phishing.tk")
    assert result["penalty"] >= 55
    assert "ziraat" in result["ocr_text_sample"].lower()

def test_ocr_no_penalty_when_domain_matches(paypal_screenshot_bytes):
    # Gerçek PayPal sitesinin screenshot'ı — domain'de 'paypal' var
    result = analyze_with_ocr(paypal_screenshot_bytes, domain="paypal.com")
    assert result["penalty"] == 0  # Domain match → ceza yok

def test_ocr_reader_singleton():
    from modules.phishing_detector.visual_analyzer import get_ocr_reader
    r1 = get_ocr_reader()
    r2 = get_ocr_reader()
    assert r1 is r2  # Aynı instance

def test_ocr_returns_zero_on_blank_image():
    from PIL import Image
    import io, numpy as np
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    result = analyze_with_ocr(buf.getvalue(), domain="blank.com")
    assert result["penalty"] == 0
```

---

### B4. Koşullu Gemini

**Mevcut durum:**  
Her URL için `_call_gemini()` çağrılıyor — günlük ~1500 free tier limiti hızla dolar.

**Hedef:**  
Önceki katmanlar (HTML, pHash, OCR) `penalty >= 65` üretirse Gemini atlanır.  
Günlük sayaç Redis'te tutulur, limit aşılırsa OCR fallback devreye girer.

**Değişecek dosyalar:**
- `modules/phishing_detector/screenshot_analyzer.py`

**Uygulama:**

```python
# screenshot_analyzer.py — analyze() fonksiyonu başına ekle:

from .redis_cache import redis_get_gemini_count, redis_incr_gemini_counter

GEMINI_DAILY_LIMIT = int(os.getenv("GEMINI_DAILY_LIMIT", "1400"))

def _should_call_gemini(pre_penalty: int) -> bool:
    """Önceki katmanlar yeterliyse veya kota doluysa False döner."""
    if pre_penalty >= 65:
        logger.info(f"Gemini atlandı: önceki katmanlar yeterli (penalty={pre_penalty})")
        return False
    daily = redis_get_gemini_count()
    if daily >= GEMINI_DAILY_LIMIT:
        logger.warning(f"Gemini günlük limit aşıldı ({daily}/{GEMINI_DAILY_LIMIT})")
        return False
    return True
```

```python
# analyze() içinde screenshot alındıktan sonra:
pre_penalty = html_result.get("penalty", 0) + phash_result.get("penalty", 0)

if not _should_call_gemini(pre_penalty):
    # OCR ile devam et (ücretsiz fallback)
    ocr_result = analyze_with_ocr(screenshot_bytes, domain)
    return _build_result_from_local(ocr_result, html_result, phash_result)

# Gemini'ye gönder
redis_incr_gemini_counter()
gemini_result = _call_gemini(...)
```

**Testler:**

```python
# tests/test_conditional_gemini.py
from unittest.mock import patch

def test_gemini_skipped_when_high_pre_penalty(mock_call_gemini):
    # HTML + pHash penalty >= 65 ise Gemini çağrılmamalı
    with patch("modules.phishing_detector.screenshot_analyzer._call_gemini") as mock_gemini:
        from modules.phishing_detector.screenshot_analyzer import analyze
        # html_penalty=70 simüle et
        result = analyze("https://phishing.tk", pre_penalty_override=70)
        mock_gemini.assert_not_called()

def test_gemini_skipped_when_daily_limit_reached(mock_redis_count_1400):
    with patch("modules.phishing_detector.screenshot_analyzer._call_gemini") as mock_gemini:
        from modules.phishing_detector.screenshot_analyzer import analyze
        analyze("https://new-site.com")
        mock_gemini.assert_not_called()

def test_gemini_called_for_ambiguous_site(mock_redis_count_0):
    # Önceki katmanlar < 65 penalty verdiyse Gemini çağrılmalı
    with patch("modules.phishing_detector.screenshot_analyzer._call_gemini") as mock_gemini:
        mock_gemini.return_value = {"risk_score": 20, "risk_level": "LOW"}
        from modules.phishing_detector.screenshot_analyzer import analyze
        analyze("https://ambiguous-site.com", pre_penalty_override=30)
        mock_gemini.assert_called_once()

def test_gemini_counter_increments():
    from modules.phishing_detector.redis_cache import redis_get_gemini_count, redis_incr_gemini_counter
    before = redis_get_gemini_count()
    redis_incr_gemini_counter()
    assert redis_get_gemini_count() == before + 1
```

---

## BÖLÜM C: FRONTEND

---

### C1. Async Job Polling UI

**Mevcut durum:**  
`ModulesApp.jsx` → `handleCheck()` POST `/check-url` atar, sonuç gelene kadar loading spinner gösterir.  
~15-30 sn boyunca tam bloke.

**Hedef:**  
1. POST `/check-url` → anında hızlı sonuç veya `{status: "analyzing", job_id: "..."}`
2. Hızlı sonuç varsa direkt göster
3. `status: "analyzing"` ise:
   - Hızlı katman sonuçlarını göster (ML skoru, whitelist durumu vb.)
   - Progress indicator + "Derin analiz devam ediyor..." mesajı
   - GET `/result/{job_id}` polling (3 saniyede bir, max 90 saniye)
   - Sonuç gelince UI güncellenir

**Değişecek dosyalar:**
- `frontend-react/src/ModulesApp.jsx` — `handleCheck()` ve `PhishingSection` component

**Uygulama mantığı:**

```javascript
// ModulesApp.jsx içinde PhishingSection'da:

const [jobId, setJobId] = useState(null)
const [analyzing, setAnalyzing] = useState(false)
const [pollCount, setPollCount] = useState(0)
const MAX_POLLS = 30  // 30 × 3sn = 90 sn max

const handleCheck = async () => {
  setLoading(true)
  setResult(null)
  setJobId(null)
  setAnalyzing(false)

  try {
    const resp = await fetch('/api/v2/phishing/check-url', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, force_fresh: false})
    })
    const data = await resp.json()

    if (data.status === 'analyzing' && data.job_id) {
      // Hızlı sonucu göster, polling başlat
      setResult(data)
      setJobId(data.job_id)
      setAnalyzing(true)
    } else {
      // Kesin sonuç geldi
      setResult(data)
    }
  } finally {
    setLoading(false)
  }
}

// Polling effect
useEffect(() => {
  if (!jobId || !analyzing) return
  if (pollCount >= MAX_POLLS) {
    setAnalyzing(false)
    return
  }

  const timer = setTimeout(async () => {
    try {
      const resp = await fetch(`/api/v2/phishing/result/${jobId}`)
      const data = await resp.json()
      if (data.status === 'complete') {
        setResult(data)
        setAnalyzing(false)
        setJobId(null)
      } else {
        setPollCount(c => c + 1)
      }
    } catch {
      setPollCount(c => c + 1)
    }
  }, 3000)

  return () => clearTimeout(timer)
}, [jobId, analyzing, pollCount])
```

**Progress indicator component:**

```jsx
{analyzing && (
  <motion.div
    initial={{opacity:0}} animate={{opacity:1}}
    style={{
      padding: '16px 20px',
      background: 'rgba(0,212,255,0.06)',
      border: `1px solid ${theme.primary}40`,
      borderRadius: theme.radius.md,
      marginBottom: 16,
      display: 'flex',
      alignItems: 'center',
      gap: 12
    }}
  >
    {/* Dönen ikon */}
    <motion.div
      animate={{rotate: 360}}
      transition={{repeat: Infinity, duration: 1.5, ease: 'linear'}}
      style={{fontSize: 20}}
    >
      🔍
    </motion.div>
    <div>
      <p style={{margin: 0, fontSize: 14, fontWeight: 700, color: theme.primary}}>
        Derin Analiz Devam Ediyor...
      </p>
      <p style={{margin: 0, fontSize: 12, color: theme.textMuted}}>
        Playwright screenshot + AI analizi ({Math.round(pollCount * 3)}s)
      </p>
    </div>
    {/* Progress bar */}
    <div style={{flex:1, height:4, background: theme.border, borderRadius:2}}>
      <motion.div
        style={{
          height:4,
          background: theme.primary,
          borderRadius:2,
          width: `${Math.min((pollCount / MAX_POLLS) * 100, 95)}%`
        }}
        transition={{duration: 0.5}}
      />
    </div>
  </motion.div>
)}
```

**Testler:**

```javascript
// tests/phishing-polling.test.jsx (Vitest + React Testing Library)
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

describe('PhishingSection polling', () => {
  it('shows analyzing state when job_id returned', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({
        json: () => ({ status: 'analyzing', job_id: 'test-job-123',
                        safety_score: 45, risk_level: '⚠️ Şüpheli' })
      })
    render(<PhishingSection />)
    userEvent.type(screen.getByPlaceholderText(/url/i), 'https://suspicious.site')
    userEvent.click(screen.getByRole('button', {name: /analiz/i}))
    await waitFor(() => {
      expect(screen.getByText(/derin analiz devam ediyor/i)).toBeInTheDocument()
    })
  })

  it('updates result when polling returns complete', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce({ json: () => ({ status: 'analyzing', job_id: 'abc' }) })
      .mockResolvedValueOnce({ json: () => ({ status: 'pending' }) })
      .mockResolvedValueOnce({ json: () => ({ status: 'complete', safety_score: 0,
                                               risk_level: '🚨 Tehlikeli' }) })
    // ... component render + poll simulation
    await waitFor(() => {
      expect(screen.getByText(/tehlikeli/i)).toBeInTheDocument()
    }, {timeout: 15000})
  })

  it('stops polling after MAX_POLLS reached', async () => {
    // 30 poll sonra analyzing=false olmalı
    // fetch her seferinde {status: "pending"} dönüyor
    // ...
  })

  it('shows definitive result immediately without polling', async () => {
    global.fetch = jest.fn().mockResolvedValueOnce({
      json: () => ({ safety_score: 0, risk_level: '🚨 Tehlikeli',
                     sources: [{name: 'PhishTank'}] })
    })
    // job_id yok → polling başlamamalı
    // ...
  })
})
```

---

## 📁 Yeni Dosya Yapısı

```
modules/phishing_detector/
├── scanner.py             ← run_quick_checks() eklenir
├── router.py              ← async polling endpoint, Redis cache
├── screenshot_analyzer.py ← koşullu Gemini, pool bağlantısı
├── threat_intel.py        ← async run_threat_intelligence_async()
├── cache_db.py            ← korunur (SQLite, kalıcı geçmiş)
├── redis_cache.py         ← YENİ: Redis wrapper + Gemini sayacı
├── celery_tasks.py        ← YENİ: run_heavy_analysis task
├── visual_analyzer.py     ← YENİ: HTML analizi, pHash, OCR
├── playwright_pool.py     ← YENİ: Browser pool
├── build_logo_db.py       ← YENİ: Logo hash DB oluşturucu (script)
└── data/
    └── logo_hashes.json   ← YENİ: pHash veritabanı
```

---

## 🖥️ Sunucu Kurulum Sırası

```bash
ssh root@104.248.45.198
cd /var/www/aegis_nexus
source venv/bin/activate

# A1: Redis
sudo apt install redis-server -y
sudo systemctl enable --now redis-server
pip install redis

# B1: BeautifulSoup (zaten kurulu olabilir)
pip install beautifulsoup4

# B2: pHash
pip install imagehash Pillow

# B3: EasyOCR (A3 sonrasına bırak, RAM kısıtı)
# pip install easyocr opencv-python-headless numpy

# Logo DB oluştur (B2 için)
python modules/phishing_detector/build_logo_db.py

# Servisi yeniden başlat
systemctl restart aegisnexus-api.service
```

---

## 🧪 Test Koşturma

```bash
# Tüm phishing testleri
pytest tests/ -k "phishing or redis_cache or html_analyzer or phash or ocr or gemini or celery" -v

# Sadece hızlı (IO gerektirmeyenler)
pytest tests/test_html_analyzer.py tests/test_conditional_gemini.py -v

# Redis bağlantısı gerektirenler
pytest tests/test_redis_cache.py -v --redis-url=redis://127.0.0.1:6379

# Frontend testleri
cd frontend-react && npm test -- --testPathPattern=phishing
```

---

## 📊 Beklenen Kazanımlar (Mevcut → Hedef)

| Metrik | Mevcut | Hedef |
|--------|--------|-------|
| Ortalama analiz süresi | 15-30 sn | 200ms (hızlı) + 8-12 sn (arka plan) |
| Paralel request kapasitesi | 1-2 | 10+ |
| RAM kullanımı (pik) | ~600MB+ | ~600MB (sabit) |
| Gemini günlük kullanım | %100 | ~%20 |
| Phishing tespit doğruluğu | %75-80 | %90+ |
| Cache hit oranı | %50 | %70+ (Redis) |

---

*Son Güncelleme: 3 Mayıs 2026*
