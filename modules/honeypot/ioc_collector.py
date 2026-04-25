"""
IOC Collector Module - Enterprise-grade Threat Intelligence Collection.

Collects Indicators of Compromise (IOCs) from multiple sources:
- abuse.ch (URLhaus, PhishTank, SSL Phishing, etc.)
- AbuseIPDB (malicious IP database)
- Internal honeypot events

Implements best practices from:
- MISP (Malware Information Sharing Platform)
- OpenCTI (Open Cyber Threat Intelligence Platform)
- STIX 2.1 standard indicators
"""

import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import json

import requests
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class IOCType(str, Enum):
    """Supported Indicator types (STIX-based)."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "hash"  # MD5, SHA256
    EMAIL = "email"


class ThreatType(str, Enum):
    """Threat classifications."""
    PHISHING = "phishing"
    MALWARE = "malware"
    BOTNET = "botnet"
    C2_SERVER = "c2"
    SPAM = "spam"
    DGA_DOMAIN = "dga"
    EXPLOIT = "exploit"


class IOCSource(str, Enum):
    """Indicator sources."""
    URLHAUS = "abuse_urlhaus"
    PHISHTANK = "abuse_phishtank"
    SSL_PHISHING = "abuse_ssl_phishing"
    MALWARE_URLS = "abuse_malware_urls"
    ABUSEIPDB = "abuseipdb"
    HONEYPOT = "honeypot"
    MISP = "misp"
    ALIENVAULT_OTX = "alienvault_otx"
    SHODAN = "shodan"


# API Configuration
ABUSE_CH_API_TIMEOUT = 60
ABUSEIPDB_API_TIMEOUT = 30
REQUEST_BATCH_SIZE = 50

# Cache settings
CACHE_TTL = 3600  # 1 hour


# ============================================================================
# DATA MODELS (Dataclasses)
# ============================================================================

@dataclass
class IOCRecord:
    """
    Standard IOC record following STIX 2.1 indicator format.
    Used for: storage, caching, serialization.
    """
    ioc_type: str  # IOCType enum value
    ioc_value: str  # The actual indicator (normalized)
    source: str  # IOCSource enum value
    threat_type: str  # ThreatType enum value
    risk_score: int  # 1-100 (calculated)
    confidence: float  # 0.0-1.0 (from source)
    
    # Timeline
    first_seen: datetime = None
    last_seen: datetime = None
    detection_count: int = 1
    
    # Additional fields
    threat_tags: List[str] = None  # ['zeus', 'dridex', 'emotet']
    context: Dict[str, Any] = None  # {'country': 'CN', 'asn': 'AS12345'}
    ioc_metadata: Dict[str, Any] = None  # Raw API response metadata
    source_reference: str = None  # URL/ID to original report
    
    def __post_init__(self):
        """Initialize datetime defaults."""
        now = datetime.now(timezone.utc)
        if self.first_seen is None:
            self.first_seen = now
        if self.last_seen is None:
            self.last_seen = now
        if self.threat_tags is None:
            self.threat_tags = []
        if self.context is None:
            self.context = {}
        if self.ioc_metadata is None:
            self.ioc_metadata = {}
    
    def get_value_hash(self) -> str:
        """Generate SHA256 hash of normalized value for deduplication."""
        normalized = self.ioc_value.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            **asdict(self),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


# ============================================================================
# HELPER UTILITIES
# ============================================================================

class HTTPSession:
    """Robust HTTP session with minimal retries."""
    
    def __init__(self, timeout: int = 10, max_retries: int = 0):
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0,
            status_forcelist=[500, 502, 503, 504],  # Removed 429 - we handle that manually
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.timeout = timeout
    
    def get(self, url: str, headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Safe GET with timeout."""
        try:
            return self.session.get(url, timeout=self.timeout, headers=headers, **kwargs)
        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def post(self, url: str, json: Dict = None, headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Safe POST with timeout."""
        try:
            return self.session.post(url, json=json, timeout=self.timeout, headers=headers, **kwargs)
        except requests.exceptions.Timeout:
            logger.error(f"Timeout posting to {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None


def normalize_value(value: str, ioc_type: str) -> str:
    """Normalize IOC value for consistent deduplication."""
    value = value.strip().lower()
    
    if ioc_type == IOCType.DOMAIN:
        # Remove www. prefix
        value = re.sub(r'^www\.', '', value)
        # Remove trailing dot
        value = value.rstrip('.')
    
    elif ioc_type == IOCType.URL:
        # Remove schema
        value = re.sub(r'^https?://', '', value)
        # Remove trailing slash
        value = value.rstrip('/')
    
    elif ioc_type == IOCType.EMAIL:
        # Already normalized
        pass
    
    elif ioc_type == IOCType.FILE_HASH:
        # All uppercase for hash consistency
        value = value.upper()
    
    return value


def calculate_risk_score(
    threat_type: str,
    source: str,
    confidence: float,
    detection_count: int = 1
) -> int:
    """
    Calculate risk score (1-100) using weighted factors.
    
    Inspired by: CVSS scoring, ThreatStream, VirusTotal reputation.
    """
    base_score = 50  # Neutral baseline
    
    # Threat type weight (30 points max)
    threat_weights = {
        ThreatType.C2_SERVER: 30,      # Highest
        ThreatType.BOTNET: 28,
        ThreatType.MALWARE: 25,
        ThreatType.DGA_DOMAIN: 20,
        ThreatType.PHISHING: 18,       # Medium
        ThreatType.EXPLOIT: 22,
        ThreatType.SPAM: 5,            # Low
    }
    base_score += threat_weights.get(threat_type, 10)
    
    # Source credibility (20 points max)
    source_weights = {
        IOCSource.ABUSEIPDB: 20,       # Highest trust
        IOCSource.URLHAUS: 18,
        IOCSource.PHISHTANK: 16,
        IOCSource.MALWARE_URLS: 15,
        IOCSource.SSL_PHISHING: 14,
        IOCSource.HONEYPOT: 10,        # Medium
        IOCSource.MISP: 15,
        IOCSource.SHODAN: 12,
    }
    base_score += source_weights.get(source, 8)
    
    # Confidence multiplier (0.5-1.0)
    base_score = int(base_score * (0.5 + confidence))
    
    # Detection count multiplier (increase if seen multiple times)
    if detection_count > 1:
        multiplier = min(1 + (detection_count * 0.05), 1.3)  # Cap at 1.3x
        base_score = int(base_score * multiplier)
    
    # Clamp to 1-100
    return max(1, min(100, base_score))


# ============================================================================
# COLLECTORS (API integrations)
# ============================================================================

class AbuseChCollector:
    """Collector for abuse.ch threat feeds (URLhaus, PhishTank, SSL Phishing, etc.)."""
    
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    def __init__(self):
        self.http = HTTPSession(timeout=ABUSE_CH_API_TIMEOUT)
        
        # Load API keys for rotation
        urlhaus_keys = os.getenv("URLHAUS_API_KEYS", "").split(",") if os.getenv("URLHAUS_API_KEYS") else []
        urlhaus_keys = [k.strip() for k in urlhaus_keys if k.strip()]
        
        # Fallback to single key if no multi-key configured
        if not urlhaus_keys:
            single_key = os.getenv("URLHAUS_API_KEY", "")
            if single_key:
                urlhaus_keys = [single_key]
        
        self.urlhaus_api_keys = urlhaus_keys
        self.urlhaus_key_index = 0
        
        phishtank_keys = os.getenv("PHISHTANK_API_KEYS", "").split(",") if os.getenv("PHISHTANK_API_KEYS") else []
        phishtank_keys = [k.strip() for k in phishtank_keys if k.strip()]
        
        # Fallback to URLhaus keys for PhishTank (same API)
        if not phishtank_keys:
            phishtank_keys = self.urlhaus_api_keys
        
        self.phishtank_api_keys = phishtank_keys
        self.phishtank_key_index = 0
    
    def _rotate_urlhaus_key(self):
        """Rotate to next URLhaus API key."""
        if len(self.urlhaus_api_keys) > 1:
            self.urlhaus_key_index = (self.urlhaus_key_index + 1) % len(self.urlhaus_api_keys)
            logger.info(f"Rotated URLhaus key to #{self.urlhaus_key_index + 1}/{len(self.urlhaus_api_keys)}")
        return self.urlhaus_api_keys[self.urlhaus_key_index] if self.urlhaus_api_keys else None
    
    def _rotate_phishtank_key(self):
        """Rotate to next PhishTank API key."""
        if len(self.phishtank_api_keys) > 1:
            self.phishtank_key_index = (self.phishtank_key_index + 1) % len(self.phishtank_api_keys)
            logger.info(f"Rotated PhishTank key to #{self.phishtank_key_index + 1}/{len(self.phishtank_api_keys)}")
        return self.phishtank_api_keys[self.phishtank_key_index] if self.phishtank_api_keys else None
    
    def fetch_urlhaus_recent(self, limit: int = 100) -> List[IOCRecord]:
        """Fetch recent malicious URLs from URLhaus CSV recent dump."""
        iocs = []
        try:
            import io, csv
            endpoint = "https://urlhaus.abuse.ch/downloads/csv_recent/"
            logger.info("📥 Fetching URLhaus recent CSV")
            response = self.http.get(endpoint)

            if not response or response.status_code != 200:
                logger.error(f"❌ URLhaus error: {response.status_code if response else 'timeout'}")
                return []

            reader = csv.reader(io.StringIO(response.text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                # CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                url = row[2] if len(row) > 2 else None
                threat = row[5] if len(row) > 5 else ""
                if url:
                    iocs.append(IOCRecord(
                        ioc_type=IOCType.URL,
                        ioc_value=url,
                        source=IOCSource.URLHAUS,
                        threat_type=ThreatType.PHISHING if "phishing" in threat.lower() else ThreatType.MALWARE,
                        risk_score=80,
                        confidence=0.9
                    ))
                if len(iocs) >= limit:
                    break

            logger.info(f"✅ URLhaus fetched {len(iocs)} recent URLs")
            return iocs
        except Exception as e:
            logger.error(f"❌ URLhaus fetch failed: {str(e)}")
            return []

    def fetch_phishtank_recent(self, limit: int = 100) -> List[IOCRecord]:
        """Fetch recent phishing URLs from PhishTank with API key rotation."""
        iocs = []
        
        if not self.phishtank_api_keys:
            logger.warning("PhishTank API key not configured")
            return iocs
        
        endpoint = f"{self.BASE_URL}/phish/recent/"
        
        # Try all PhishTank keys
        attempts = len(self.phishtank_api_keys)
        for attempt in range(attempts):
            try:
                current_key = self.phishtank_api_keys[self.phishtank_key_index]
                params = {"limit": min(limit, 1000)}
                headers = {"Auth-Key": current_key} if current_key else {}
                
                response = self.http.get(endpoint, params=params, headers=headers)
                
                # Only 200 = success
                if response and response.status_code == 200:
                    data = response.json()
                    if data.get('query_status') != 'ok':
                        logger.warning(f"PhishTank query status: {data.get('query_status')}, rotating...")
                        self._rotate_phishtank_key()
                        continue
                    
                    for phish_record in data.get('phishing', []):
                        try:
                            url = phish_record.get('url', '')
                            target = phish_record.get('target', 'Unknown')
                            
                            if not url:
                                continue
                            
                            url_normalized = normalize_value(url, IOCType.URL)
                            iocs.append(IOCRecord(
                                ioc_type=IOCType.URL,
                                ioc_value=url_normalized,
                                source=IOCSource.PHISHTANK,
                                threat_type=ThreatType.PHISHING,
                                confidence=0.92,
                                detection_count=1,
                                threat_tags=[target] if target != 'Unknown' else [],
                                ioc_metadata={'target': target},
                            ))
                            
                            # Extract domain
                            domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/:?#]+)', url)
                            if domain_match:
                                domain = domain_match.group(1)
                                domain_normalized = normalize_value(domain, IOCType.DOMAIN)
                                iocs.append(IOCRecord(
                                    ioc_type=IOCType.DOMAIN,
                                    ioc_value=domain_normalized,
                                    source=IOCSource.PHISHTANK,
                                    threat_type=ThreatType.PHISHING,
                                    confidence=0.88,
                                    detection_count=1,
                                    threat_tags=[target] if target != 'Unknown' else [],
                                ))
                        
                        except Exception as e:
                            logger.debug(f"Error parsing PhishTank record: {e}")
                            continue
                    
                    logger.info(f"✅ PhishTank (key #{self.phishtank_key_index + 1}) fetched {len(iocs)} IOCs")
                    return iocs
                
                else:
                    status_code = response.status_code if response else "timeout"
                    logger.warning(f"❌ PhishTank key #{self.phishtank_key_index + 1}: HTTP {status_code}, rotating (attempt {attempt + 1}/{attempts})...")
                    self._rotate_phishtank_key()
                    continue
            
            except requests.Timeout:
                logger.warning(f"❌ PhishTank key #{self.phishtank_key_index + 1}: timeout (attempt {attempt + 1}/{attempts}), rotating...")
                self._rotate_phishtank_key()
                continue
            except Exception as e:
                logger.warning(f"❌ PhishTank key #{self.phishtank_key_index + 1}: {e} (attempt {attempt + 1}/{attempts}), rotating...")
                self._rotate_phishtank_key()
                continue
        
        # All keys failed
        logger.error(f"PhishTank: All {len(self.phishtank_api_keys)} API keys failed")
        return iocs


class AbuseIPDBCollector:
    """Collector for AbuseIPDB malicious IP database."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str = None):
        self.api_keys = [k.strip() for k in os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if k.strip()]
        self.current_key_index = 0
        self.api_key = api_key or (self.api_keys[0] if self.api_keys else "")
        self.http = HTTPSession(timeout=ABUSEIPDB_API_TIMEOUT)
    
    def get_next_key(self):
        """Get next API key in rotation."""
        if len(self.api_keys) > 1:
            self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
            self.api_key = self.api_keys[self.current_key_index]
            logger.info(f"🔄 Rotated to API key #{self.current_key_index + 1}/{len(self.api_keys)}")
        return self.api_key
    
    def fetch_blacklist(self, limit: int = 100) -> List[IOCRecord]:
        """
        Fetch recent malicious IPs from AbuseIPDB blacklist with key rotation.
        Only 200 is success, anything else rotates to next key.
        """
        iocs = []
        endpoint = f"{self.BASE_URL}/blacklist"
        max_retries = len(self.api_keys)
        attempt = 0
        
        logger.info(f"🔑 Starting with {max_retries} API keys")
        
        while attempt < max_retries:
            attempt += 1
            
            if not self.api_key:
                logger.warning("AbuseIPDB API key not configured")
                return iocs
            
            try:
                logger.info(f"📡 Attempt {attempt}/{max_retries}: Using key #{self.current_key_index + 1}")
                
                headers = {
                    "Key": self.api_key,
                    "Accept": "application/json",
                }
                
                params = {
                    "limit": min(limit, 100000),
                    "plaintext": 1,
                }
                
                response = self.http.get(endpoint, headers=headers, params=params)
                
                # Only 200 is success
                if response and response.status_code == 200:
                    # Parse plaintext IP list
                    text = response.text
                    for line in text.strip().split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        try:
                            ip = line.split(',')[0].strip() if ',' in line else line
                            
                            if not self._is_valid_ip(ip):
                                continue
                            
                            risk_score = calculate_risk_score(
                                threat_type=ThreatType.BOTNET,
                                source=IOCSource.ABUSEIPDB,
                                confidence=0.95,
                                detection_count=1
                            )
                            
                            iocs.append(IOCRecord(
                                ioc_type=IOCType.IP,
                                ioc_value=ip,
                                source=IOCSource.ABUSEIPDB,
                                threat_type=ThreatType.BOTNET,
                                risk_score=risk_score,
                                confidence=0.95,
                                detection_count=1,
                                ioc_metadata={'abuseipdb_reference': f"https://www.abuseipdb.com/check/{ip}"},
                            ))
                        
                        except Exception as e:
                            logger.debug(f"Error parsing IP: {e}")
                            continue
                    
                    logger.info(f"✅ AbuseIPDB fetched {len(iocs)} IOCs (key #{self.current_key_index + 1})")
                    return iocs
                
                # Any non-200 status = rotate to next key
                else:
                    status = response.status_code if response else 'timeout'
                    logger.warning(f"⚠️ Key #{self.current_key_index + 1} returned {status}. Rotating...")
                    self.get_next_key()
                    continue
            
            except Exception as e:
                logger.error(f"❌ Error (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    logger.info(f"Rotating to next key...")
                    self.get_next_key()
                    continue
                return iocs
        
        logger.error(f"❌ All {max_retries} API keys exhausted")
        return iocs
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Basic IP validation (IPv4)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


# ============================================================================
# MAIN IOC COLLECTOR ENGINE
# ============================================================================

class IOCCollectorEngine:
    """
    Enterprise IOC Collector Engine.
    Orchestrates collection, validation, deduplication, and scoring.
    """
    
    def __init__(self):
        self.ioc_store: Dict[str, IOCRecord] = {}  # key = SHA256(normalized_value)
        self.abuse_ch = AbuseChCollector()
        self.abuseipdb = AbuseIPDBCollector()
        self.last_update = {}
    
    def collect_all(self, include_sources: List[str] = None, limit: int = 1000) -> List[IOCRecord]:
        """
        Fetch IOCs from all configured sources.
        
        Args:
            include_sources: List of IOCSource values to include. If None, fetch all.
            limit: Max IOCs per source
        
        Returns:
            List of collected and validated IOCRecord objects.
        """
        if include_sources is None:
            include_sources = [s.value for s in IOCSource]
        
        collected = []
        
        # Abuse.ch
        if IOCSource.URLHAUS.value in include_sources:
            collected.extend(self.abuse_ch.fetch_urlhaus_recent(limit=limit))
        
        if IOCSource.PHISHTANK.value in include_sources:
            collected.extend(self.abuse_ch.fetch_phishtank_recent(limit=limit))
        
        # AbuseIPDB
        if IOCSource.ABUSEIPDB.value in include_sources:
            collected.extend(self.abuseipdb.fetch_blacklist(limit=limit))
        
        # Validate and deduplicate
        validated = self._validate_and_deduplicate(collected)
        
        logger.info(f"Collected {len(collected)} raw IOCs, {len(validated)} unique after dedup")
        return validated
    
    def _validate_and_deduplicate(self, iocs: List[IOCRecord]) -> List[IOCRecord]:
        """
        Validate IOCs and merge duplicates.
        Follows MISP deduplication strategy.
        """
        unique_iocs = []
        seen = set()
        
        for ioc in iocs:
            # Calculate hash for deduplication
            value_hash = ioc.get_value_hash()
            
            if value_hash in seen:
                # Update existing IOC (merge)
                existing_idx = next(
                    (i for i, x in enumerate(unique_iocs) if x.get_value_hash() == value_hash),
                    None
                )
                if existing_idx is not None:
                    existing = unique_iocs[existing_idx]
                    existing.detection_count += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    # Update risk score based on increased detection
                    existing.risk_score = calculate_risk_score(
                        existing.threat_type,
                        existing.source,
                        existing.confidence,
                        existing.detection_count
                    )
            else:
                # New IOC
                if self._validate_ioc(ioc):
                    ioc.risk_score = calculate_risk_score(
                        ioc.threat_type,
                        ioc.source,
                        ioc.confidence,
                        ioc.detection_count
                    )
                    unique_iocs.append(ioc)
                    seen.add(value_hash)
        
        return unique_iocs
    
    def _validate_ioc(self, ioc: IOCRecord) -> bool:
        """Validate IOC format and sanity checks."""
        
        # Type-specific validation
        if ioc.ioc_type == IOCType.IP:
            return AbuseIPDBCollector._is_valid_ip(ioc.ioc_value)
        
        elif ioc.ioc_type == IOCType.DOMAIN:
            # Domain should have at least one dot
            return '.' in ioc.ioc_value and len(ioc.ioc_value) > 3
        
        elif ioc.ioc_type == IOCType.URL:
            # Basic URL validation
            return ioc.ioc_value.startswith(('http', 'ftp')) or '://' in ioc.ioc_value
        
        elif ioc.ioc_type == IOCType.FILE_HASH:
            # SHA256 (64 char hex) or MD5 (32 char hex)
            return len(ioc.ioc_value) in [32, 64] and all(c in '0123456789ABCDEFabcdef' for c in ioc.ioc_value)
        
        elif ioc.ioc_type == IOCType.EMAIL:
            # Basic email validation
            return '@' in ioc.ioc_value and '.' in ioc.ioc_value.split('@')[1]
        
        return False
    
    def store_ioc(self, ioc: IOCRecord) -> bool:
        """Store IOC in memory cache."""
        try:
            key = ioc.get_value_hash()
            self.ioc_store[key] = ioc
            return True
        except Exception as e:
            logger.error(f"Error storing IOC: {e}")
            return False
    
    def get_ioc(self, ioc_value: str, ioc_type: str) -> Optional[IOCRecord]:
        """Retrieve stored IOC by value."""
        normalized = normalize_value(ioc_value, ioc_type)
        value_hash = hashlib.sha256(normalized.encode()).hexdigest()
        return self.ioc_store.get(value_hash)
    
    def list_iocs(self, filters: Dict = None) -> List[IOCRecord]:
        """
        List stored IOCs with optional filtering.
        
        Filters:
            - 'ioc_type': Filter by type (ip, domain, url, hash)
            - 'threat_type': Filter by threat type
            - 'min_risk_score': Only IOCs >= this score
            - 'source': Filter by source
        """
        results = list(self.ioc_store.values())
        
        if not filters:
            return results
        
        # Apply filters
        if 'ioc_type' in filters:
            results = [i for i in results if i.ioc_type == filters['ioc_type']]
        
        if 'threat_type' in filters:
            results = [i for i in results if i.threat_type == filters['threat_type']]
        
        if 'min_risk_score' in filters:
            results = [i for i in results if i.risk_score >= filters['min_risk_score']]
        
        if 'source' in filters:
            results = [i for i in results if i.source == filters['source']]
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored IOCs."""
        iocs = list(self.ioc_store.values())
        
        if not iocs:
            return {
                'total_iocs': 0,
                'by_type': {},
                'by_threat': {},
                'by_source': {},
                'average_risk_score': 0,
                'high_risk_count': 0,
            }
        
        stats = {
            'total_iocs': len(iocs),
            'by_type': {},
            'by_threat': {},
            'by_source': {},
            'average_risk_score': sum(i.risk_score for i in iocs) / len(iocs),
            'high_risk_count': len([i for i in iocs if i.risk_score >= 80]),
            'critical_count': len([i for i in iocs if i.risk_score >= 95]),
        }
        
        for ioc in iocs:
            stats['by_type'][ioc.ioc_type] = stats['by_type'].get(ioc.ioc_type, 0) + 1
            stats['by_threat'][ioc.threat_type] = stats['by_threat'].get(ioc.threat_type, 0) + 1
            stats['by_source'][ioc.source] = stats['by_source'].get(ioc.source, 0) + 1
        
        return stats


# Export
__all__ = [
    'IOCCollectorEngine',
    'IOCRecord',
    'IOCType',
    'ThreatType',
    'IOCSource',
]



class AlienVaultOTXCollector:
    """AlienVault OTX IOC Collector (requests.get)"""

    def __init__(self, api_key: str = None):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        self.api_key = api_key or os.getenv('ALIENVAULT_OTX_API_KEY')
        self.base_url = "https://otx.alienvault.com/api/v1"

    def fetch_recent_pulses(self, limit: int = 100) -> List[IOCRecord]:
        try:
            import requests
            headers = {'X-OTX-API-KEY': self.api_key}
            endpoint = f"{self.base_url}/pulses/subscribed?limit={limit}"
            logger.info("📥 Fetching OTX pulses")
            r = requests.get(endpoint, headers=headers, timeout=20)

            if r.status_code != 200:
                logger.error(f"❌ OTX error: {r.status_code}")
                return []

            data = r.json()
            iocs = []
            for pulse in data.get('results', []):
                for indicator in pulse.get('indicators', []):
                    t = indicator.get('type')
                    if t == 'URL':
                        ioc_type = IOCType.URL
                    elif t in ['domain', 'hostname']:
                        ioc_type = IOCType.DOMAIN
                    elif t == 'IPv4':
                        ioc_type = IOCType.IP
                    elif t in ['MD5', 'SHA1', 'SHA256']:
                        ioc_type = IOCType.FILE_HASH
                    else:
                        continue

                    val = indicator.get('indicator')
                    if not val:
                        continue

                    iocs.append(IOCRecord(
                        ioc_type=ioc_type,
                        ioc_value=val,
                        source=IOCSource.ALIENVAULT_OTX,
                        threat_type=ThreatType.MALWARE,
                        risk_score=75,
                        confidence=0.8,
                        ioc_metadata={'pulse_id': pulse.get('id'), 'pulse_name': pulse.get('name')}
                    ))

            logger.info(f"✅ OTX fetched {len(iocs)} IOCs")
            return iocs
        except Exception as e:
            logger.error(f"❌ OTX fetch failed: {str(e)}")
            return []
