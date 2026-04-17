# 🔍 IOC Collector - Enterprise Threat Intelligence System

**Part of:** Honeypot Module (02) | Developed for AegisNexus  
**Version:** 1.0.0 | **Status:** Production Ready ✅

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [IOC Types & Threat Classifications](#ioc-types--threat-classifications)
4. [API Endpoints](#api-endpoints)
5. [Risk Scoring Algorithm](#risk-scoring-algorithm)
6. [Data Models](#data-models)
7. [Usage Examples](#usage-examples)
8. [Integration with Cyber Guardian](#integration-with-cyber-guardian)
9. [Best Practices](#best-practices)

---

## Overview

**IOC Collector** is an enterprise-grade threat intelligence system that:

✅ **Automatically collects** Indicators of Compromise (IOCs) from multiple sources
- URLhaus (abuse.ch) - Malicious URLs
- PhishTank (abuse.ch) - Phishing URLs  
- AbuseIPDB - Malicious IP addresses
- Internal honeypot events
- MISP/Shodan (extensible)

✅ **Validates & deduplicates** IOCs using STIX 2.1 standards

✅ **Scores risk** (1-100 scale) based on threat type, source credibility, confidence, detection frequency

✅ **Persists to PostgreSQL** for query, filtering, analytics

✅ **Integrates with Cyber Guardian** for operator SMS alerts and daily reports

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              EXTERNAL THREAT INTELLIGENCE SOURCES           │
├─────────────────────────────────────────────────────────────┤
│  URLhaus (abuse.ch)  |  PhishTank  |  AbuseIPDB  |  MISP    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  IOC COLLECTOR      │
                    │  ┌────────────────┐ │
                    │  │ - Fetch IOCs   │ │
                    │  │ - Parse data   │ │
                    │  │ - Normalize    │ │
                    │  └────────────────┘ │
                    └──────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  VALIDATORS         │
                    │  ┌────────────────┐ │
                    │  │ - Deduplicate  │ │
                    │  │ - Format check │ │
                    │  │ - False +      │ │
                    │  └────────────────┘ │
                    └──────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  RISK SCORING       │
                    │  ┌────────────────┐ │
                    │  │ Calc: 1-100    │ │
                    │  │ (weights)      │ │
                    │  │ (confidence)   │ │
                    │  │ (frequency)    │ │
                    │  └────────────────┘ │
                    └──────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ↓                      ↓                      ↓
    ┌────────┐          ┌──────────┐          ┌──────────┐
    │ Memory │          │PostgreSQL│          │ Operator │
    │ Cache  │          │ Database │          │ Gateway  │
    │        │          │          │          │          │
    │ Real-  │          │ Persist  │          │ 80+ Risk │
    │ time   │          │ Query    │          │ SMS/API  │
    │ Search │          │ Analytics│          │ Alerts   │
    └────────┘          └──────────┘          └──────────┘
```

---

## IOC Types & Threat Classifications

### Supported IOC Types (STIX 2.1)

```python
class IOCType(str, Enum):
    IP = "ip"              # IPv4 address
    DOMAIN = "domain"      # Domain name
    URL = "url"            # Full URL
    FILE_HASH = "hash"     # MD5, SHA256
    EMAIL = "email"        # Email address
```

**Format Examples:**
```
IP:         192.168.1.100, 10.0.0.50
Domain:     malicious-site.ru, phishing.com
URL:        http://evil.com/payload, https://fake-bank.tk/login
Hash:       5d41402abc4b2a76b9719d911017c592 (MD5)
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (SHA256)
Email:      attacker@malicious.com
```

### Threat Types

```python
class ThreatType(str, Enum):
    PHISHING = "phishing"           # Credential harvesting
    MALWARE = "malware"             # Malicious executables
    BOTNET = "botnet"               # Bot command & control
    C2_SERVER = "c2"                # Botnet C&C servers
    SPAM = "spam"                   # Spam sources
    DGA_DOMAIN = "dga"              # Domain Generation Algorithm
    EXPLOIT = "exploit"             # Exploit kit hosting
```

### IOC Sources

```python
class IOCSource(str, Enum):
    URLHAUS = "abuse_urlhaus"              # abuse.ch URLhaus
    PHISHTANK = "abuse_phishtank"          # abuse.ch PhishTank
    SSL_PHISHING = "abuse_ssl_phishing"    # abuse.ch SSL Phishing
    MALWARE_URLS = "abuse_malware_urls"    # abuse.ch Malware URLs
    ABUSEIPDB = "abuseipdb"                # AbuseIPDB database
    HONEYPOT = "honeypot"                  # Internal honeypot
    MISP = "misp"                          # MISP platform
    SHODAN = "shodan"                      # Shodan search engine
```

---

## API Endpoints

### 1. Fetch External IOCs

**Endpoint:** `POST /api/v2/honeypot/ioc/fetch-external`

Fetch IOCs from abuse.ch, AbuseIPDB, etc. and store them.

**Request:**
```json
{
  "sources": ["abuse_urlhaus", "abuse_phishtank", "abuseipdb"],
  "limit_per_source": 100
}
```

**Response:**
```json
{
  "status": "success",
  "module": "02_honeypot_ioc_collector",
  "collected": 523,
  "persisted": 523,
  "stats": {
    "total_iocs": 1240,
    "by_type": {
      "url": 650,
      "domain": 420,
      "ip": 170
    },
    "by_threat": {
      "phishing": 420,
      "malware": 520,
      "botnet": 300
    },
    "by_source": {
      "abuse_urlhaus": 450,
      "abuse_phishtank": 350,
      "abuseipdb": 170,
      "honeypot": 70
    },
    "average_risk_score": 72.5,
    "high_risk_count": 280,
    "critical_count": 45
  },
  "samples": [
    {
      "ioc_type": "url",
      "ioc_value": "http://fake-google.com/login",
      "source": "abuse_urlhaus",
      "threat_type": "phishing",
      "risk_score": 95,
      "confidence": 0.95,
      "detection_count": 3,
      "first_seen": "2026-04-17T08:00:00",
      "last_seen": "2026-04-17T10:30:00",
      "threat_tags": ["google_phishing"]
    }
  ]
}
```

---

### 2. List Collected IOCs

**Endpoint:** `GET /api/v2/honeypot/ioc/list-collected`

List all collected IOCs with advanced filtering.

**Query Parameters:**
- `ioc_type` (optional): Filter by type (ip, domain, url, hash)
- `threat_type` (optional): Filter by threat (phishing, malware, botnet, c2)
- `min_risk_score` (int, default: 0): Only return IOCs >= this score
- `source` (optional): Filter by source
- `limit` (int, default: 100): Result limit
- `offset` (int, default: 0): Pagination offset

**Examples:**

```bash
# Get all high-risk phishing URLs
GET /api/v2/honeypot/ioc/list-collected?threat_type=phishing&min_risk_score=80&ioc_type=url&limit=50

# Get all malicious IPs from AbuseIPDB
GET /api/v2/honeypot/ioc/list-collected?ioc_type=ip&source=abuseipdb&limit=100

# Get critical IOCs (95+)
GET /api/v2/honeypot/ioc/list-collected?min_risk_score=95&limit=100
```

**Response:**
```json
{
  "status": "success",
  "module": "02_honeypot_ioc_collector",
  "total": 280,
  "returned": 50,
  "offset": 0,
  "limit": 50,
  "iocs": [
    {
      "ioc_type": "domain",
      "ioc_value": "malicious-bank.ru",
      "source": "abuse_urlhaus",
      "threat_type": "phishing",
      "risk_score": 92,
      "confidence": 0.92,
      "detection_count": 5,
      "first_seen": "2026-04-16T12:00:00",
      "last_seen": "2026-04-17T10:30:00",
      "threat_tags": ["bank_phishing", "russian"]
    }
  ]
}
```

---

### 3. Get IOC Statistics

**Endpoint:** `GET /api/v2/honeypot/ioc/stats-advanced`

Get comprehensive statistics about collected IOCs.

**Response:**
```json
{
  "status": "success",
  "module": "02_honeypot_ioc_collector",
  "statistics": {
    "total_iocs": 1240,
    "by_type": {
      "url": 650,
      "domain": 420,
      "ip": 170
    },
    "by_threat": {
      "phishing": 420,
      "malware": 520,
      "botnet": 300
    },
    "by_source": {
      "abuse_urlhaus": 450,
      "abuse_phishtank": 350,
      "abuseipdb": 170,
      "honeypot": 70
    },
    "average_risk_score": 72.5,
    "high_risk_count": 280,
    "critical_count": 45
  },
  "insights": {
    "high_risk_percentage": 22.58,
    "critical_percentage": 3.63,
    "average_risk_score": 72.5
  }
}
```

---

### 4. Search IOC

**Endpoint:** `GET /api/v2/honeypot/ioc/search`

Search for specific IOC in database.

**Query Parameters:**
- `q` (required, min 2 chars): Search query (IP, domain, URL, hash, etc.)

**Example:**
```bash
GET /api/v2/honeypot/ioc/search?q=192.168.1.100
GET /api/v2/honeypot/ioc/search?q=malicious-site.ru
GET /api/v2/honeypot/ioc/search?q=5d41402abc4b2a76b9719d911017c592
```

**Response:**
```json
{
  "status": "success",
  "module": "02_honeypot_ioc_collector",
  "query": "192.168.1.100",
  "found": 3,
  "results": [
    {
      "id": 1523,
      "type": "ip",
      "value": "192.168.1.100",
      "threat_type": "botnet",
      "risk_score": 88,
      "source": "abuseipdb",
      "detection_count": 12,
      "first_seen": "2026-04-10T15:00:00",
      "last_seen": "2026-04-17T10:30:00"
    }
  ]
}
```

---

### 5. Get IOCs by Risk Level

**Endpoint:** `GET /api/v2/honeypot/ioc/by-risk-score`

Get IOCs grouped by risk level.

**Query Parameters:**
- `level` (required): One of: critical, high, medium, low
  - `critical`: 95-100 (immediate action required)
  - `high`: 80-94 (prioritize monitoring)
  - `medium`: 50-79 (normal operations)
  - `low`: 1-49 (low priority)
- `limit` (int, default: 100)

**Example:**
```bash
# Get all critical-risk IOCs
GET /api/v2/honeypot/ioc/by-risk-score?level=critical&limit=100

# Get high-risk IOCs (limited to 50)
GET /api/v2/honeypot/ioc/by-risk-score?level=high&limit=50
```

**Response:**
```json
{
  "status": "success",
  "module": "02_honeypot_ioc_collector",
  "risk_level": "critical",
  "score_range": {"min": 95, "max": 100},
  "found": 45,
  "iocs": [
    {
      "value": "192.168.1.100",
      "type": "ip",
      "threat_type": "c2",
      "risk_score": 99,
      "confidence": 0.98,
      "source": "abuseipdb",
      "detection_count": 27
    }
  ]
}
```

---

## Risk Scoring Algorithm

Risk score is calculated on a **1-100 scale** using weighted factors.

### Scoring Formula

```
BASE_SCORE = 50 (neutral baseline)

THREAT_TYPE_WEIGHT (0-30 points):
  C2 Server:       30 points (highest)
  Botnet:          28 points
  Malware:         25 points
  DGA Domain:      20 points
  Phishing:        18 points
  Exploit:         22 points
  Spam:             5 points (lowest)

SOURCE_CREDIBILITY (0-20 points):
  AbuseIPDB:       20 points (most trusted)
  URLhaus:         18 points
  PhishTank:       16 points
  Malware URLs:    15 points
  SSL Phishing:    14 points
  Honeypot:        10 points
  MISP:            15 points
  Shodan:          12 points

CONFIDENCE_MULTIPLIER (0.5x - 1.0x):
  Applies to base score
  Examples:
    - 95% confidence: 0.975x
    - 90% confidence: 0.95x
    - 50% confidence: 0.75x

DETECTION_COUNT_MULTIPLIER (1.0x - 1.3x):
  Increases if IOC seen multiple times
  Each detection: +0.05x (capped at 1.3x)
  Examples:
    - 1 detection:  1.0x
    - 5 detections: 1.2x
    - 10+ detections: 1.3x (capped)

FINAL_SCORE = min(100, max(1, BASE_SCORE × MULTIPLIERS))
```

### Score Interpretation

```
95-100  🔴 CRITICAL    → Immediate action required, known malware/C2
80-94   🟠 HIGH        → Prioritize investigation & monitoring
50-79   🟡 MEDIUM      → Normal threat level, continue monitoring
1-49    🟢 LOW         → Low priority, informational
```

### Example Calculation

```
Scenario: URLhaus reports a phishing domain (phishing.ru)

Inputs:
  - Threat Type: PHISHING
  - Source: URLhaus (abuse.ch)
  - Confidence: 0.92 (92%)
  - Detection Count: 3 (seen 3 times)

Calculation:
  Base Score:           50
  + Threat Type:        18 (phishing)
  + Source:             18 (URLhaus)
  × Confidence:         0.92
  × Detection Count:    1.1 (3 detections)
  
  = 50 + 18 + 18 = 86
  = 86 × 0.92 = 79.12
  = 79.12 × 1.1 = 87.03
  
  Final Risk Score: 87 (HIGH) ✓
```

---

## Data Models

### IOCRecord (In-Memory)

```python
@dataclass
class IOCRecord:
    # Core data
    ioc_type: str           # IOCType enum ('ip', 'domain', 'url', 'hash')
    ioc_value: str          # Normalized value
    source: str             # IOCSource enum
    threat_type: str        # ThreatType enum
    
    # Scoring
    risk_score: int         # 1-100
    confidence: float       # 0.0-1.0
    
    # Timeline
    first_seen: datetime    # When first detected
    last_seen: datetime     # When last detected
    detection_count: int    # How many times seen
    
    # Extra data
    threat_tags: List[str]  # ['zeus', 'dridex', 'emotet']
    context: Dict[str, Any] # {'country': 'CN', 'asn': 'AS12345'}
    metadata: Dict[str, Any] # Raw API response
    source_reference: str   # URL/ID to original report
```

### IndicatorOfCompromise (Database)

```python
class IndicatorOfCompromise(Base):
    __tablename__ = "indicators_of_compromise"
    
    id: BigInteger (Primary Key)
    ioc_type: str (indexed)
    ioc_value: str (indexed)
    ioc_value_hash: str (unique, indexed) # SHA256 for dedup
    
    source: str (indexed)
    source_reference: str
    
    threat_type: str (indexed)
    threat_tags: JSON
    
    risk_score: int (indexed)
    confidence: float
    
    first_seen: DateTime (indexed)
    last_seen: DateTime (indexed)
    detection_count: int
    
    context: JSON
    metadata: JSON
    
    operator_alert_sent: bool (indexed)
    operator_alert_timestamp: DateTime
    
    status: str # 'active', 'resolved', 'false_positive', 'archived'
    is_monitored: bool (indexed)
    
    created_at: DateTime (indexed)
    updated_at: DateTime
```

---

## Usage Examples

### Python Integration

```python
from modules.honeypot.ioc_collector import IOCCollectorEngine, IOCType, ThreatType

# Initialize engine
collector = IOCCollectorEngine()

# Fetch IOCs from all sources
iocs = collector.collect_all()

# Fetch from specific sources
iocs = collector.collect_all(include_sources=[
    "abuse_urlhaus",
    "abuse_phishtank",
    "abuseipdb"
])

# Store IOC
for ioc in iocs:
    collector.store_ioc(ioc)

# List IOCs
all_iocs = collector.list_iocs()

# Filter IOCs
high_risk_phishing = collector.list_iocs(filters={
    'threat_type': 'phishing',
    'min_risk_score': 80
})

# Get stats
stats = collector.get_stats()
print(f"Total IOCs: {stats['total_iocs']}")
print(f"Critical: {stats['critical_count']}")
print(f"Average Risk: {stats['average_risk_score']}")
```

### API Integration

```bash
# Fetch external IOCs
curl -X POST http://localhost:8000/api/v2/honeypot/ioc/fetch-external \
  -H "Content-Type: application/json" \
  -d '{
    "sources": ["abuse_urlhaus", "abuse_phishtank", "abuseipdb"],
    "limit_per_source": 100
  }'

# Get all critical IOCs
curl http://localhost:8000/api/v2/honeypot/ioc/by-risk-score?level=critical

# Search for IOC
curl http://localhost:8000/api/v2/honeypot/ioc/search?q=192.168.1.100

# Get statistics
curl http://localhost:8000/api/v2/honeypot/ioc/stats-advanced
```

---

## Integration with Cyber Guardian

IOC Collector feeds data to **Cyber Guardian** module for:

1. **Realtime Alerts** (Risk 80+)
   - Push to operator webhook
   - SMS notifications to Turk Telekom, Vodafone, Türkcell
   - Latency: <5 seconds

2. **Daily Reports** (All IOCs)
   - Compile all IOCs collected in 24 hours
   - Send summary to operators at 09:00 UTC
   - Format: CSV, JSON, or formatted text

3. **Kurumsal Müşteri API**
   - Customers query IOCs via custom API key
   - Filter by risk level, threat type, time range
   - Push to customer webhook

---

## Best Practices

### 1. Regular Collection Scheduling

Run IOC collection on a cron schedule:

```python
# Every hour
0 * * * * python -m modules.honeypot.ioc_collector --fetch-all

# Every 5 minutes for critical sources
*/5 * * * * python -m modules.honeypot.ioc_collector --sources abuse_urlhaus abuseipdb

# Daily comprehensive fetch
0 2 * * * python -m modules.honeypot.ioc_collector --fetch-all --archive-old
```

### 2. Deduplication Strategy

- Normalize all values before storing
- Remove `www.` prefix from domains
- Lowercase everything
- Use SHA256 hash for uniqueness check
- Update `detection_count` and `last_seen` on duplicates

### 3. False Positive Handling

- Maintain whitelist of known-good domains
- Mark IOCs as `false_positive` after validation
- Auto-archive after N days of inactivity
- Allow manual review/override

### 4. Database Optimization

- Index on: `ioc_type`, `risk_score`, `created_at`, `threat_type`
- Partition by `created_at` monthly for large datasets
- Archive old IOCs (>90 days, status='resolved')
- Vacuum regularly: `VACUUM ANALYZE indicators_of_compromise;`

### 5. API Rate Limiting

- URLhaus: ~1-2 requests/minute (rate-limited to 100 records)
- AbuseIPDB: 1 request/second (IP limit per key)
- Implement caching: 1-hour TTL
- Use multiple API keys for rotation

### 6. Monitoring & Alerts

Track:
- Collection success rate
- API error rates per source
- Average collection time
- New IOC rate (per hour)
- High-risk IOC rate

---

## FAQ

**Q: How often should I run collection?**  
A: Every hour for URLhaus/AbuseIPDB, daily for CSV feeds. Critical: every 5 minutes.

**Q: How do I prevent false positives?**  
A: Maintain whitelist, require multi-source confirmation for high-risk, manual review option.

**Q: What's the maximum IOC database size?**  
A: No hard limit, but partition table after 10M rows for performance.

**Q: Can I add custom IOC sources?**  
A: Yes! Extend `IOCCollectorEngine` with custom collector classes (see code comments).

**Q: How does deduplication work?**  
A: SHA256 hash of normalized value. Duplicates increment `detection_count`.

---

## Support & Feedback

For bugs, features, or questions:  
📧 Email: dev@aegisnexus.dev  
🐙 GitHub: github.com/garmoths/AegisNexus  
📱 Telegram: @aegisnexus_dev

---

**Made with ❤️ by AegisNexus Team**  
*Protecting Turkish internet from threats, one IOC at a time.*
