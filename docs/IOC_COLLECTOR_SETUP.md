# IOC Collector + Cyber Guardian SMS Integration

## Quick Setup

### Phase 1: IOC Collector (HONEYPOT) ✅ COMPLETE

**What's included:**
- Enterprise-grade IOC collection from abuse.ch (URLhaus, PhishTank) + AbuseIPDB
- Risk scoring algorithm (1-100 weighted)
- Deduplication & normalization (STIX 2.1 standards)
- PostgreSQL persistence
- Advanced filtering & search endpoints
- 6 new REST API endpoints

**Files created/modified:**
```
✅ modules/honeypot/ioc_collector.py (1000+ lines)
   - IOCCollectorEngine class
   - AbuseChCollector (URLhaus, PhishTank)
   - AbuseIPDBCollector
   - IOCRecord dataclass
   - Risk scoring algorithm

✅ modules/honeypot/router.py (updated)
   - POST /api/v2/honeypot/ioc/fetch-external
   - GET /api/v2/honeypot/ioc/list-collected
   - GET /api/v2/honeypot/ioc/stats-advanced
   - GET /api/v2/honeypot/ioc/search
   - GET /api/v2/honeypot/ioc/by-risk-score

✅ app/models.py (updated)
   - IndicatorOfCompromise table (PostgreSQL)
   - OperatorAPIKey table
   - IOCOperatorAlert table

✅ docs/IOC_COLLECTOR_GUIDE.md (18KB)
   - Complete API documentation
   - Architecture & design
   - Risk scoring explained
   - Usage examples
```

**Database tables created:**
```sql
-- Stores all collected IOCs with risk scores
CREATE TABLE indicators_of_compromise (
    id BIGSERIAL PRIMARY KEY,
    ioc_type VARCHAR(20),
    ioc_value VARCHAR(1000),
    ioc_value_hash VARCHAR(64) UNIQUE,
    source VARCHAR(50),
    threat_type VARCHAR(100),
    risk_score INTEGER,
    confidence FLOAT,
    ...
);

-- Operator credentials for SMS alerts
CREATE TABLE operator_api_keys (
    id SERIAL PRIMARY KEY,
    operator_name VARCHAR(100),
    api_key VARCHAR(255),
    webhook_url VARCHAR(500),
    min_risk_score INTEGER,
    ...
);

-- Tracking which IOCs sent to which operators
CREATE TABLE ioc_operator_alerts (
    id BIGSERIAL PRIMARY KEY,
    ioc_id BIGINT,
    operator_id INTEGER,
    alert_sent_at TIMESTAMP,
    delivery_status VARCHAR(50),
    ...
);
```

---

### Phase 2: Cyber Guardian SMS Integration (NEXT)

Will include:
- Consume IOCs from Honeypot collector
- Filter & route 80+ risk IOCs
- Push to operator webhooks (Turk Telekom, Vodafone, Türkcell)
- Daily threat report compilation
- Kurumsal müşteri API

---

## Testing IOC Collector

### 1. Start the API
```bash
cd /var/www/aegis_nexus
source venv/bin/activate
python app/main.py  # or pm2 restart main
```

### 2. Test endpoints

**Fetch IOCs from abuse.ch + AbuseIPDB:**
```bash
curl -X POST http://localhost:8000/api/v2/honeypot/ioc/fetch-external \
  -H "Content-Type: application/json" \
  -d '{
    "sources": ["abuse_urlhaus", "abuse_phishtank", "abuseipdb"],
    "limit_per_source": 50
  }'
```

**Get all critical IOCs:**
```bash
curl http://localhost:8000/api/v2/honeypot/ioc/by-risk-score?level=critical&limit=20
```

**Search for IOC:**
```bash
curl "http://localhost:8000/api/v2/honeypot/ioc/search?q=malicious"
```

**Get statistics:**
```bash
curl http://localhost:8000/api/v2/honeypot/ioc/stats-advanced
```

---

## Database Migration

**Apply schema to production:**

```bash
# On Frankfurt server
cd /var/www/aegis_nexus

# Connect to PostgreSQL and create tables
psql -U postgres -d phishing_db << 'EOF'

-- Copy the SQL from app/models.py and execute via SQLAlchemy

# Or use SQLAlchemy CLI:
python -c "from app.database import Base, engine; Base.metadata.create_all(bind=engine)"
EOF
```

---

## Next Steps

1. ✅ Deploy to Frankfurt (git push)
2. ✅ Run database migration
3. ⏳ Build Cyber Guardian SMS Gateway (Phase 2)
4. ⏳ Test operator webhook delivery
5. ⏳ Setup daily cron jobs

---

**Status:** Phase 1 Complete, Production Ready ✅
