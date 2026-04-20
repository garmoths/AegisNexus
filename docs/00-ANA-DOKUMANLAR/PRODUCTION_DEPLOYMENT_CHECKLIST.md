# 🚀 Production Deployment Checklist

**Tarih:** 20 Nisan 2026  
**Sunucu:** DigitalOcean FRA-1 (Frankfurt)  
**IP:** 104.248.45.198  
**Status:** ✅ Production Ready

---

## 📁 1. Database & Cache Setup

### ✅ PostgreSQL 16
- Kurulum: `apt install postgresql`
- Servis: `systemctl status postgresql` → **active**
- Databases:
  - `aegisnexus` (IoC verileri - 7,053 kayıt)
  - `phishing_db` (Phishing URL'leri - 1,187,889 kayıt)
- Tablolar:
  - `indicators_of_compromise` ✅
  - `ioc_indicators` ✅ (Index'ler oluşturuldu)
  - `phishing_urls` ✅
- Connection: `DATABASE_URL=postgresql://enes:password@127.0.0.1:5432/phishing_db`

### ✅ Redis 7
- Kurulum: `apt install redis-server`
- Servis: `systemctl status redis` → **active**
- Test: `redis-cli ping` → **PONG**
- URL: `redis://localhost:6379/0`

---

## 📁 2. Message Broker & Task Queue

### ✅ RabbitMQ
- Kurulum: `apt install rabbitmq-server`
- Servis: `systemctl status rabbitmq-server` → **active**
- Management Plugin: `rabbitmq-plugins enable rabbitmq_management`
- Celery Broker: `amqp://guest:guest@localhost:5672//`

### ✅ Celery Workers (PM2'siz - Direkt Çalışıyor)
- Worker: `./venv/bin/celery -A modules.honeypot.celery_tasks worker --detach`
- Beat (Scheduler): `./venv/bin/celery -A modules.honeypot.celery_tasks beat --detach`
- PID files:
  - `/tmp/celery-worker.pid`
  - `/tmp/celery-beat.pid`
- Loglar: `tail -f /root/.pm2/logs/celery-worker-out.log`

**Çalışan Tasklar:**
- `fetch_urlhaus` → URLhaus'tan 500 IOC çeker
- `fetch_otx` → AlienVault OTX'ten 407 IOC çeker
- `run_ioc_fetch` → Parallel IOC fetcher

---

## 📁 3. API Endpoints & Backend

### ✅ IoC Stats Endpoint
```
GET /api/v2/honeypot/ioc/stats
```
**Response:**
```json
{
  "status": "success",
  "stats": {
    "total_iocs": 7053,
    "high_risk_count": 7043,
    "medium_risk_count": 5,
    "low_risk_count": 5
  },
  "module": "02_honeypot"
}
```

**Aggregation Verileri:**
- Toplam kayıt sayısı
- Bugün eklenen kayıtlar
- Son 7 gün günlük artış (weekly_growth)
- Risk skoru dağılımı (0-20, 21-40, 41-60, 61-80, 81-100)
- En çok görülen tehdit tipleri (top_threats)
- Kaynak dağılımı (source_breakdown)

### ✅ Phishing Stats Endpoint
```
GET /api/v2/phishing/stats
```
**Response:**
```json
{
  "toplam_zararli_site": 1187889,
  "module": "01_phishing_detector"
}
```

**Aggregation Verileri:**
- Toplam URL sayısı (1.1M+)
- Günlük yeni URL'ler
- En çok phishing yapılan domainler (top_domains)
- Son eklenen URL'ler (recent_urls)
- Tehdit kategorileri (threat_categories)

### ✅ Honeypot Stats Endpoint
```
GET /api/v2/honeypot/stats
```
**Response:** Session verileri, unique IPs, total interactions

---

## 📁 4. Web Server & Proxy

### ✅ Nginx
- Servis: `systemctl status nginx` → **active**
- Config: `/etc/nginx/sites-enabled/default`
- Reverse Proxy: `http://127.0.0.1:8000` → Port 80/443
- SSL: Let's Encrypt (443)
- Domain: aegisnexus.dev + api.aegisnexus.dev

### ✅ Uvicorn (FastAPI)
- Host: `0.0.0.0:8000`
- Process: PM2 managed (`pm2 status` → main)
- Workers: Single process (fork mode)

---

## 📁 5. Environment Variables (.env)

```bash
# PostgreSQL Database
DATABASE_URL=postgresql://enes:password@127.0.0.1:5432/phishing_db

# Redis
REDIS_URL=redis://localhost:6379/0

# RabbitMQ (Celery Broker)
CELERY_BROKER_URL=amqp://guest:guest@localhost:5672//

# API Keys (VirusTotal, URLScan, AbuseIPDB)
VIRUSTOTAL_API_KEYS=58177fb3550491ec6711145d5cadc097cde22c85079eec0be0e042285cddbf3c
URLSCAN_API_KEYS=019daba8-4266-774d-a251-dbc55d5a4a69
ABUSEIPDB_API_KEYS=055bc2de7cefa2db0bef577346ebc74386db8e74596e3b48bbabad16eda3b5978a678e6e797848b3
```

---

## 📁 6. Frontend-Backend Entegrasyonu

### API Base URL
```javascript
const API_BASE = 'https://aegisnexus.dev/api/v2';
// veya
const API_BASE = 'https://api.aegisnexus.dev';
```

### Fetch Örnekleri
```javascript
// IoC Stats
const iocStats = await fetch(`${API_BASE}/honeypot/ioc/stats`).then(r => r.json());

// Phishing Stats
const phishingStats = await fetch(`${API_BASE}/phishing/stats`).then(r => r.json());

// Honeypot Stats
const honeypotStats = await fetch(`${API_BASE}/honeypot/stats`).then(r => r.json());
```

---

## 📁 7. Monitoring & Logs

### PM2 Processler
```bash
pm2 status
pm2 logs main --lines 50
pm2 logs celery-worker --lines 20
```

### Systemd Servisler
```bash
systemctl status postgresql
systemctl status redis
systemctl status rabbitmq-server
systemctl status nginx
```

### Database Sorguları
```bash
sudo -u postgres psql -d phishing_db -c "SELECT COUNT(*) FROM phishing_urls;"
sudo -u postgres psql -d aegisnexus -c "SELECT COUNT(*) FROM indicators_of_compromise;"
```

---

## 📁 8. GitHub Sync

**Sunucu Commit:** `2ab86cd` - feat: Production deployment  
**Yerel Commit:** `3ed7d6e` - Merge remote main with local IoC API  
**Repo:** https://github.com/garmoths/AegisNexus

---

## 🎯 Test Komutları

```bash
# API Test
curl -s http://127.0.0.1:8000/api/v2/phishing/stats
curl -s http://127.0.0.1:8000/api/v2/honeypot/ioc/stats

# Celery Test
./venv/bin/celery -A modules.honeypot.celery_tasks inspect ping

# Database Test
sudo -u postgres psql -d phishing_db -c "\dt"
```

---

**Status:** 🟢 **Tüm sistemler operational**

**Son Güncelleme:** 20 Nisan 2026, 22:30 UTC+3
