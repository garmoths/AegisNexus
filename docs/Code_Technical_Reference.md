# 🔬 CODE TECHNICAL REFERENCE - Modül Detayları

**Bu Dokuman:** Kodun her modülünün ayrıntılı teknik analizi  
**Hedef Audience:** Developers, DevOps, Technical Architects  
**Last Updated:** 17 April 2026

---

## 📚 İÇİNDEKİLER

1. [Threat Intelligence Stack](#threat-intelligence-stack)
2. [IOC Collector System](#ioc-collector-system)
3. [Database Layer](#database-layer)
4. [API Endpoints](#api-endpoints)
5. [Phishing Detector Module](#phishing-detector-module)
6. [Honeypot Module](#honeypot-module)
7. [Deployment Scripts](#deployment-scripts)

---

## 🔍 THREAT INTELLIGENCE STACK

### File: `modules/phishing_detector/threat_intel.py`
**Lines:** 559 total  
**Purpose:** External threat intelligence API integrations

#### Imports & Constants

```python
import os
import json
import logging
import hashlib
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

# API Keys (loaded from .env, comma-separated for rotation)
VIRUSTOTAL_API_KEYS = os.getenv("VIRUSTOTAL_API_KEYS", "").split(",")
GOOGLE_SAFE_BROWSING_KEYS = os.getenv("GOOGLE_SAFE_BROWSING_KEYS", "").split(",")
ABUSEIPDB_API_KEYS = os.getenv("ABUSEIPDB_API_KEYS", "").split(",")

# In-memory cache for API responses
API_CACHE = {}
CACHE_TTL = 3600  # 1 hour

# Rate limiting per API
API_RATE_LIMITS = {
    "virustotal": {"requests": [], "limit": 4, "window": 60, "key_index": 0},
    "abuseipdb": {"requests": [], "limit": 1500, "window": 86400, "key_index": 0},
    "google_safe": {"requests": [], "limit": 10000, "window": 86400, "key_index": 0},
}
```

#### Function: `_rotate_api_key(api_name)`

```python
def _rotate_api_key(api_name):
    """
    Rotate to next API key when current one fails.
    
    Logic:
    - If more than 1 key available: rotate
    - Otherwise: stay on current key
    - Reset rate limit counter after rotation
    
    Args:
        api_name: 'virustotal', 'google_safe', 'abuseipdb'
    
    Returns:
        str: Next API key to use
    
    Example:
        if response.status_code != 200:
            _rotate_api_key("virustotal")  # Move to next key
            continue  # Retry with new key
    """
    if api_name not in API_RATE_LIMITS:
        return None
    
    if api_name == "virustotal":
        if len(VIRUSTOTAL_API_KEYS) > 1:
            current_idx = API_RATE_LIMITS[api_name]["key_index"]
            next_idx = (current_idx + 1) % len(VIRUSTOTAL_API_KEYS)
            API_RATE_LIMITS[api_name]["key_index"] = next_idx
            API_RATE_LIMITS[api_name]["requests"] = []  # Reset rate limit
            logger.info(f"Rotated VirusTotal: {current_idx} → {next_idx}")
            return VIRUSTOTAL_API_KEYS[next_idx]
        return VIRUSTOTAL_API_KEYS[0] if VIRUSTOTAL_API_KEYS else None
    
    # Similar logic for google_safe and abuseipdb...
```

#### Function: `check_virustotal(url, timeout=8)`

```python
def check_virustotal(url, timeout=8):
    """
    Check URL reputation on VirusTotal.
    
    Endpoint: https://www.virustotal.com/api/v3/urls
    Auth: x-apikey header
    Key Rotation: 10 keys (round-robin)
    Cache: 1 hour in-memory
    
    Parameters:
        url (str): URL to check
        timeout (int): Request timeout in seconds
    
    Returns:
        dict: {
            "malicious": int,      # Number of vendors marking as malicious
            "suspicious": int,     # Suspicious votes
            "clean": int,          # Clean votes
            "status": str          # 'malicious', 'suspicious', or 'clean'
        }
        OR None if all keys fail
    
    HTTP Status Codes:
        200: OK (return immediately with result)
        404: URL not in database
        401: Invalid API key (rotate to next key)
        429: Rate limited (rotate to next key)
        5xx: Server error (rotate to next key)
        Timeout: Connection timeout (rotate to next key)
    
    Process:
    1. Generate cache key (SHA256 of URL)
    2. Check in-memory cache (1 hour TTL)
    3. If cached: return immediately
    4. If not cached: enter key rotation loop
        - Get current API key
        - Make HTTP request
        - If 200: cache + return (EXIT LOOP)
        - If !=200: rotate key + continue
        - If timeout/error: rotate key + continue
    5. All keys exhausted: return None + log error
    
    Code Flow:
    ```
    cache_key = f"vt_{hash(url)}"
    
    # Check cache
    if cache_key in API_CACHE:
        return cached_result
    
    # Key rotation loop (max 10 iterations)
    for attempt in range(len(VIRUSTOTAL_API_KEYS)):
        key = _get_current_api_key("virustotal")
        
        try:
            response = requests.get(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": key},
                timeout=8
            )
            
            if response.status_code == 200:
                result = parse_response(response.json())
                API_CACHE[cache_key] = (result, now)
                return result  # SUCCESS - EXIT
            
            else:
                logger.warning(f"VT {response.status_code} → rotate")
                _rotate_api_key("virustotal")
                continue  # RETRY WITH NEXT KEY
        
        except Exception as e:
            logger.error(f"VT error: {e} → rotate")
            _rotate_api_key("virustotal")
            continue
    
    # All keys failed
    return None
    ```
    """
```

#### Function: `check_google_safe_browsing(url)`

```python
def check_google_safe_browsing(url):
    """
    Google Safe Browsing API v4.
    
    Endpoint: POST https://safebrowsing.googleapis.com/v4/threatMatches:find
    Query Param: key={key}
    Key Rotation: 2 keys
    Rate Limit: 10,000 req/day (very generous)
    
    Threat Types Checked:
    - MALWARE: Downloads malicious executables
    - SOCIAL_ENGINEERING: Phishing, social engineering
    - UNWANTED_SOFTWARE: Spyware, adware, PUPs
    - POTENTIALLY_HARMFUL_APPLICATION: Potentially dangerous APKs
    
    Returns:
        dict: {
            "matches": [
                {
                    "threatType": "MALWARE" | "SOCIAL_ENGINEERING" | ...,
                    "platformType": "ANY_PLATFORM" | "WINDOWS" | "LINUX" | ...,
                    "threat": {...}  # Threat details from API
                },
                ...
            ]
        }
        OR {} if no threats found
    
    Request Format:
    ```
    POST /v4/threatMatches:find?key=YOUR_API_KEY
    Content-Type: application/json
    
    {
        "client": {
            "clientId": "aegisnexus",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntries": [
                {"url": "http://example.com"}
            ]
        }
    }
    ```
    
    Similar key rotation logic as VirusTotal
    """
```

#### Function: `check_abuseipdb(ip_address)`

```python
def check_abuseipdb(ip_address):
    """
    AbuseIPDB API v2.
    
    Endpoint: https://api.abuseipdb.com/api/v2/check
    Query Params: ipAddress={ip}&maxAgeInDays=90
    Auth: Header "Key: {api_key}"
    Key Rotation: 9 keys (currently all exhausted)
    Rate Limit: 1500 req/day per key
    
    Returns:
        dict: {
            "abuseConfidenceScore": 0-100,      # 0=clean, 100=confirmed malicious
            "countryCode": "CN" | "US" | ...,
            "domain": "example.com",
            "isp": "China Telecom",
            "usageType": "Data Center",
            "reportsCount": int,
            "lastReportedAt": "2026-04-17T15:30:00+00:00"
        }
    
    Score Interpretation:
        0-24%:   Likely legitimate
        25-74%:  Suspicious or contested
        75-100%: Confirmed malicious
    
    Status: DISABLED (quota exhausted)
    Reason: 9 keys × 5 req/day = 45 req/day max
            Hourly fetch = 24+ req/day = quota exceeded
    Solution: Get new keys or reduce frequency
    """
```

---

## 🍯 IOC COLLECTOR SYSTEM

### File: `modules/honeypot/ioc_collector.py`
**Lines:** 801 total  
**Purpose:** Collect IOCs from multiple threat intel sources

#### Data Model: `IOCRecord` (Dataclass)

```python
@dataclass
class IOCRecord:
    """
    Standard Indicator of Compromise record.
    Follows STIX 2.1 indicator format.
    
    Fields:
        ioc_type: str
            'ip' - IP address (IPv4/IPv6)
            'domain' - Domain name
            'url' - Full URL
            'hash' - File hash (MD5, SHA256)
            'email' - Email address
        
        ioc_value: str
            The actual indicator value (normalized)
            Examples:
            - '192.168.1.1' (IP)
            - 'malware.example.com' (domain)
            - 'http://example.com/malware' (URL)
            - 'abc123def456' (hash)
        
        source: str
            Where this IOC came from
            'abuse_urlhaus' - URLhaus public CSV
            'abuse_phishtank' - PhishTank API
            'abuseipdb' - AbuseIPDB
            'honeypot' - Internal honeypot
            'misp' - MISP instance
        
        threat_type: str
            'phishing' - Phishing attacks
            'malware' - Malware hosting
            'botnet' - Botnet infrastructure
            'c2' - Command & Control server
            'spam' - Spam/unwanted email
            'dga' - Domain generation algorithm
            'exploit' - Exploit kit
        
        risk_score: int
            1-100 scoring
            1-39: Low risk
            40-79: Medium risk
            80-100: High risk / Confirmed malicious
        
        confidence: float
            0.0-1.0 confidence level from source
            URLhaus: 0.95 (highly reliable)
            PhishTank: 0.90
            AbuseIPDB: varies (0.7-1.0)
        
        threat_tags: List[str]
            Additional classification tags
            ['zeus', 'dridex', 'emotet', 'ransomware']
        
        context: Dict
            Geographic/network context
            {'country': 'CN', 'asn': 'AS12345', 'org': 'China Telecom'}
        
        ioc_metadata: Dict
            Raw API response + extra fields
        
        source_reference: str
            URL/ID pointing to original report
            For URLhaus: 'https://urlhaus.abuse.ch/url/3824507/'
    
    Methods:
        get_value_hash() -> str
            Returns SHA256 hash of normalized ioc_value
            Used for deduplication in database
            
            Example:
            'http://example.com' → 'abc123def456...' (SHA256)
        
        to_dict() -> Dict
            Convert to dictionary for JSON serialization
    """
```

#### Helper Class: `HTTPSession`

```python
class HTTPSession:
    """
    Wrapper around requests.Session with:
    - Automatic retries on server errors (5xx)
    - Connection pooling
    - Configurable timeout
    - NO automatic retry on rate limiting (429)
      We handle 429 manually with key rotation
    
    Parameters:
        timeout (int): Request timeout in seconds (default 10)
        max_retries (int): Max retries on 5xx (default 0)
    
    Example:
        session = HTTPSession(timeout=10, max_retries=2)
        response = session.get("https://api.example.com/data")
    
    Retry Strategy:
    - Total retries: max_retries
    - Backoff factor: 0 (no delay)
    - Status codes to retry: [500, 502, 503, 504] (5xx only)
    - NOT retrying 429 (we handle manually)
    """
```

#### Main Class: `IOCCollectorEngine`

```python
class IOCCollectorEngine:
    """
    Master orchestrator for IOC collection.
    Coordinates all threat intel sources.
    
    Supported Sources:
    - 'abuse_urlhaus': URLhaus public CSV endpoint
    - 'abuse_phishtank': PhishTank API (disabled)
    - 'abuse_ssl_phishing': SSL Phishing database (not implemented)
    - 'abuseipdb': AbuseIPDB blacklist (disabled - quota exhausted)
    - 'honeypot': Internal honeypot events (not implemented)
    - 'misp': MISP instance (not implemented)
    - 'shodan': Shodan API (not implemented)
    
    Key Methods:
        
        collect_all(include_sources=None, limit=2000)
            Collect IOCs from specified sources.
            
            Args:
                include_sources: List of sources to use
                                 Default: ['abuse_urlhaus']
                limit: Max IOCs per source
            
            Returns:
                List[IOCRecord]
            
            Example:
            ```
            engine = IOCCollectorEngine()
            iocs = engine.collect_all(
                include_sources=['abuse_urlhaus'],
                limit=2000
            )
            print(f"Collected {len(iocs)} IOCs")
            ```
    """
```

#### URLhaus Collector: `AbuseChCollector`

```python
class AbuseChCollector:
    """
    Abuse.ch threat intel sources.
    Currently only URLhaus is active (public endpoint, no auth).
    
    Methods:
        
        fetch_urlhaus_recent()
            Fetch recent malicious URLs from URLhaus public CSV.
            
            Endpoint: https://urlhaus.abuse.ch/downloads/csv/
            Auth: None (public)
            Format: ZIP containing CSV
            Update frequency: Real-time
            
            Process:
            1. HTTP GET to endpoint
            2. Response: ZIP file
            3. Extract: csv.txt from ZIP
            4. Parse: CSV rows (DictReader)
            5. Create IOCRecord for each row
            6. Yield records (generator)
            
            CSV Format:
            ```
            "id","dateadded","url","url_status","last_online","threat","tags",...
            "3824507","2026-04-17 15:17:17","http://39.65.159.56:52425/bin.sh",...
            ```
            
            Threat Types:
            - 'malware_download'
            - 'phishing'
            - 'botnet'
            - 'c2_server'
            - 'exploit_kit'
            - 'trojan'
            
            Returns:
                Generator[IOCRecord]
            
            Example:
            ```
            collector = AbuseChCollector()
            for ioc in collector.fetch_urlhaus_recent():
                print(f"URL: {ioc.ioc_value}, Risk: {ioc.risk_score}")
            ```
        
        fetch_phishtank_recent()
            PhishTank API integration (currently disabled).
            Requires API key (not available).
        
        _map_threat_type(threat_str) -> str
            Map threat string to ThreatType enum.
            
            Mapping:
            'malware_download' → 'malware'
            'phishing' → 'phishing'
            'botnet' → 'botnet'
            'c2_server' → 'c2'
            'exploit_kit' → 'exploit'
            Other → 'malware' (default)
        
        _calculate_risk(threat_str) -> int
            Calculate risk score (1-100) based on threat type.
            
            Scoring:
            'c2' → 100 (highest)
            'botnet' → 95
            'malware' → 90
            'phishing' → 85
            'exploit' → 88
            'dga' → 80
            'spam' → 40
            Default → 70
    """
```

#### AbuseIPDB Collector

```python
class AbuseIPDBCollector:
    """
    AbuseIPDB API v2 integration.
    Collect malicious IP addresses.
    
    Status: DISABLED (quota exhausted)
    Reason: 9 keys × 5 req/day = 45 req/day
            Hourly fetch = 24+ req/day = EXCEEDED
    
    Methods:
        
        fetch_blacklist()
            Fetch bulk IP blacklist.
            
            Endpoint: https://api.abuseipdb.com/api/v2/blacklist
            Query: limit=100000&plaintext=1
            Auth: Header "Key: {api_key}"
            Response: Plaintext list of IPs (1 per line)
            
            Returns:
                Generator[IOCRecord]
        
        fetch_single_ip(ip_address)
            Check single IP reputation.
            
            Endpoint: https://api.abuseipdb.com/api/v2/check
            Query: ipAddress={ip}&maxAgeInDays=90
            
            Returns:
                IOCRecord (if malicious) or None
        
        _calculate_risk_from_score(abuse_score) -> int
            Convert AbuseIPDB score (0-100) to our risk_score (1-100).
            
            Mapping:
            0-24% → risk 30 (low)
            25-74% → risk 60 (medium)
            75-100% → risk 95 (high)
    """
```

---

## 🗄️ DATABASE LAYER

### File: `app/database.py`

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv
import os

load_dotenv()

# PostgreSQL connection string
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://enes:password@127.0.0.1:5432/phishing_db"
)

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,           # Max 10 connections in pool
    max_overflow=20,        # Max 20 overflow connections
    pool_pre_ping=True,     # Test connections before use
    echo=False              # Set to True for SQL logging
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

def get_db():
    """Dependency injection for FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database (create tables if not exist)."""
    Base.metadata.create_all(bind=engine)
```

### File: `app/models.py` - IndicatorOfCompromise

```python
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, BigInteger, Index
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class IndicatorOfCompromise(Base):
    """
    IOC storage table.
    Stores all indicators of compromise from multiple sources.
    
    Table: indicators_of_compromise
    Rows: 5,053 (as of April 17, 2026)
    """
    __tablename__ = "indicators_of_compromise"
    
    # Primary Key
    id = Column(BigInteger, primary_key=True, index=True)
    
    # Core IOC Data
    ioc_type = Column(String(20), index=True, nullable=False)
    # Values: 'url', 'domain', 'ip', 'hash', 'email'
    
    ioc_value = Column(String(1000), index=True, nullable=False)
    # The actual indicator (normalized)
    # Examples:
    # - 'http://example.com/malware' (URL)
    # - 'malware.example.com' (domain)
    # - '192.168.1.1' (IP)
    
    ioc_value_hash = Column(String(64), unique=True, index=True)
    # SHA256 hash of ioc_value (lowercase)
    # Used for deduplication
    # When checking for existing: SELECT * WHERE ioc_value_hash = hash
    
    # Source Tracking
    source = Column(String(50), index=True, nullable=False)
    # Values: 'abuse_urlhaus', 'abuse_phishtank', 'abuseipdb', 'honeypot'
    
    source_reference = Column(String(500), nullable=True)
    # URL/ID to original report
    # Example: 'https://urlhaus.abuse.ch/url/3824507/'
    
    # Threat Classification
    threat_type = Column(String(100), index=True, nullable=False)
    # Values: 'phishing', 'malware', 'botnet', 'c2', 'spam', 'exploit', 'dga'
    
    threat_tags = Column(JSON, nullable=True, default=[])
    # Array of tags: ['zeus', 'dridex', 'emotet', 'trojan']
    
    # Risk & Confidence
    risk_score = Column(Integer, index=True, nullable=False)
    # 1-100 scale
    # 1-39: Low risk
    # 40-79: Medium risk
    # 80-100: High risk / Confirmed malicious
    
    confidence = Column(Float, nullable=False)
    # 0.0-1.0 confidence from source
    # URLhaus: 0.95
    # PhishTank: 0.90
    # AbuseIPDB: 0.7-1.0
    
    # Timeline & Frequency
    first_seen = Column(
        DateTime,
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    # When we first detected this IOC
    
    last_seen = Column(
        DateTime,
        index=True,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    # Last time we saw this IOC
    
    detection_count = Column(Integer, default=1)
    # How many times we've detected this IOC
    
    # Status
    status = Column(String(20), default='active')
    # Values: 'active', 'inactive', 'archived'
    
    # Metadata
    ioc_metadata = Column(JSON, nullable=True)
    # Raw API response + extra fields
    
    context_data = Column(JSON, nullable=True)
    # Geographic/network context
    # {'country': 'CN', 'asn': 'AS12345', 'org': 'China Telecom'}
    
    # Timestamps
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    
    # Indexes (for fast queries)
    __table_args__ = (
        Index('idx_ioc_value', 'ioc_value'),
        Index('idx_source', 'source'),
        Index('idx_risk_score', 'risk_score'),
        Index('idx_created_at', 'created_at'),
        Index('idx_threat_type', 'threat_type'),
    )
```

---

## 🔌 API ENDPOINTS

### File: `modules/honeypot/router.py`

```python
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import IndicatorOfCompromise

router = APIRouter(prefix="/api/v1/ioc", tags=["IOC"])

# Endpoints:

@router.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "OK", "service": "IOC Collector"}

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Get IOC statistics.
    
    Returns:
    ```
    {
        "total_iocs": 5053,
        "high_risk": 5043,
        "by_source": {
            "abuse_urlhaus": 4900,
            "others": 153
        },
        "by_threat_type": {
            "phishing": 3200,
            "malware": 1800,
            "botnet": 53
        }
    }
    ```
    """
    total = db.query(IndicatorOfCompromise).count()
    high_risk = db.query(IndicatorOfCompromise).filter(
        IndicatorOfCompromise.risk_score >= 80
    ).count()
    
    return {
        "total_iocs": total,
        "high_risk": high_risk,
    }

@router.get("/search")
def search_ioc(
    value: str = None,
    ioc_type: str = None,
    source: str = None,
    min_risk: int = 80,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Search IOCs with filters.
    
    Query Parameters:
    - value: Partial IOC value search
    - ioc_type: 'url', 'domain', 'ip', 'hash'
    - source: 'abuse_urlhaus', 'abuseipdb', etc.
    - min_risk: Minimum risk score (1-100)
    - limit: Max results to return
    
    Returns:
    ```
    [
        {
            "id": 1,
            "ioc_type": "url",
            "ioc_value": "http://malware.example.com",
            "source": "abuse_urlhaus",
            "threat_type": "malware",
            "risk_score": 95,
            "confidence": 0.95,
            "created_at": "2026-04-17T15:30:00Z"
        },
        ...
    ]
    ```
    """
    query = db.query(IndicatorOfCompromise)
    
    if value:
        query = query.filter(
            IndicatorOfCompromise.ioc_value.contains(value)
        )
    
    if ioc_type:
        query = query.filter(
            IndicatorOfCompromise.ioc_type == ioc_type
        )
    
    if source:
        query = query.filter(
            IndicatorOfCompromise.source == source
        )
    
    query = query.filter(
        IndicatorOfCompromise.risk_score >= min_risk
    )
    
    return query.order_by(
        IndicatorOfCompromise.risk_score.desc()
    ).limit(limit).all()

@router.get("/{ioc_id}")
def get_ioc(ioc_id: int, db: Session = Depends(get_db)):
    """Get single IOC by ID."""
    ioc = db.query(IndicatorOfCompromise).filter(
        IndicatorOfCompromise.id == ioc_id
    ).first()
    
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    return ioc
```

---

## 🎯 PHISHING DETECTOR MODULE

### File: `modules/phishing_detector/scanner.py`

```python
class URLScanner:
    """
    Main URL scanning engine using threat intelligence APIs.
    
    Methods:
        scan_url(url) -> Dict
            Scan single URL against all threat intel sources.
            
            Process:
            1. Normalize URL (lowercase, strip whitespace)
            2. Extract domain
            3. Call threat_intel functions (VirusTotal, Google Safe, AbuseIPDB)
            4. Aggregate results
            5. Calculate final risk score
            6. Return report
            
            Returns:
            ```
            {
                "url": "http://example.com",
                "domain": "example.com",
                "is_malicious": True,
                "risk_score": 95,
                "threats": {
                    "virustotal": {
                        "malicious": 45,
                        "suspicious": 3,
                        "clean": 50,
                        "status": "malicious"
                    },
                    "google_safe_browsing": {
                        "status": "MALWARE",
                        "matches": [...]
                    },
                    "abuseipdb": {
                        "ip": "192.168.1.1",
                        "abuse_score": 85
                    }
                },
                "timestamp": "2026-04-17T15:30:00Z"
            }
            ```
    """
```

---

## 🍯 HONEYPOT MODULE

### File: `modules/honeypot/ioc_validator.py`

```python
class IOCValidator:
    """
    IOC validation and normalization.
    
    Methods:
        normalize_ioc(ioc_value, ioc_type) -> str
            Normalize IOC value for consistent deduplication.
            
            URL: Lowercase, remove query params (optional)
            Domain: Lowercase, remove www prefix
            IP: Validate format
            Hash: Lowercase
            Email: Lowercase
    
    Examples:
        normalize_ioc('HTTP://EXAMPLE.COM', 'url')
        → 'http://example.com'
        
        normalize_ioc('WWW.EXAMPLE.COM', 'domain')
        → 'example.com'
        
        normalize_ioc('ABC123DEF456', 'hash')
        → 'abc123def456'
    """
```

### File: `modules/honeypot/ioc_scorer.py`

```python
class RiskScorer:
    """
    Calculate risk score for IOCs.
    
    Methods:
        calculate_risk_score(threat_type, confidence) -> int
            Generate 1-100 risk score based on threat type.
            
            Logic:
            1. Base score from threat_type
            2. Adjust by confidence (0-1.0)
            3. Cap at 1-100 range
            
            Base Scores:
            - c2_server: 100
            - botnet: 95
            - malware: 90
            - exploit: 88
            - dga: 80
            - phishing: 85
            - spam: 40
            
            Final = base_score × confidence
            (e.g., malware (90) × 0.95 confidence = 85.5 → 86)
    """
```

---

## 🚀 DEPLOYMENT SCRIPTS

### File: `scripts/ioc_fetcher.py`

```python
"""
🚨 IOC Fetcher - Main entry point for hourly IOC collection.

Cron Schedule: 0 * * * * (every hour at minute 0)
Runtime: ~6-8 seconds
Log: /var/log/aegis/cron.log

Process:
1. Connect to PostgreSQL
2. Fetch IOCs from sources (URLhaus, etc.)
3. Deduplicate against existing IOCs
4. Persist new/updated IOCs to database
5. Log statistics
6. Error handling
"""

class IOCFetcher:
    """Main orchestrator for IOC collection."""
    
    def __init__(self):
        self.engine = IOCCollectorEngine()
        self.db = None
        self.stats = {}
    
    def connect_db(self) -> bool:
        """
        Connect to PostgreSQL.
        
        Returns:
            bool: True if successful, False if failed
        
        Error Handling:
        - If connection fails: log error, return False
        - Script will exit without persisting
        """
    
    def fetch_iocs(self, sources=None) -> List[IOCRecord]:
        """
        Fetch IOCs from specified sources.
        
        Default: sources = ["abuse_urlhaus"]
        
        Calls IOCCollectorEngine.collect_all()
        """
    
    def persist_iocs(self, iocs) -> Dict:
        """
        Persist IOCs to database.
        
        Logic:
        - For each IOC:
            - Calculate SHA256 hash of ioc_value
            - SELECT WHERE ioc_value_hash (check existence)
            - If exists: UPDATE last_seen, detection_count++
            - If new: INSERT new record
        - COMMIT transaction
        - Return stats: {inserted: N, updated: M}
        
        Error Handling:
        - If error during persist: ROLLBACK, raise exception
        """
    
    def run(self):
        """
        Main execution loop (called by cron).
        
        Steps:
        1. Record start time
        2. Connect to database
        3. Fetch IOCs
        4. Persist to database
        5. Get statistics
        6. Record end time
        7. Log duration
        
        Error Handling:
        - If any step fails: log error, increment error counter
        - Continue execution (don't crash)
        """

# Main execution
if __name__ == "__main__":
    fetcher = IOCFetcher()
    fetcher.run()
```

---

## 📋 QUICK REFERENCE TABLE

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Threat Intel APIs | threat_intel.py | 559 | VirusTotal, Google Safe, AbuseIPDB |
| IOC Collector | ioc_collector.py | 801 | URLhaus, PhishTank, AbuseIPDB collectors |
| IOC Validator | ioc_validator.py | ~150 | Normalization, deduplication |
| Risk Scorer | ioc_scorer.py | ~100 | Risk score calculation |
| Database ORM | models.py | ~200 | SQLAlchemy models |
| Database Setup | database.py | ~50 | PostgreSQL connection |
| API Routes | router.py | ~200 | FastAPI endpoints |
| URL Scanner | scanner.py | ~300 | Main scanning engine |
| IOC Fetcher | ioc_fetcher.py | 254 | Hourly cron job |
| **TOTAL** | | **~3,000** | |

---

**Last Updated:** 17 April 2026  
**Version:** 1.0 Production Ready  
**Author:** Technical Team
