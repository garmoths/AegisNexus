"""
Local Threat Intelligence API Replacements
=========================================
VirusTotal ve AbuseIPDB'nin yaptığını tamamen local yapan modül
Mevcut kodunda sadece import'u değiştirmen yeterli
"""

import re
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# ============================================================
# VİRUSTOTAL REPLACEMENT → check_virustotal_local()
# Orijinal: vt["malicious"], vt["suspicious"] döndürüyordu
# Bu fonksiyon aynı dict yapısını döndürür, kod değişmez
# ============================================================

def check_virustotal_local(url: str, conn) -> dict:
    """
    Döndürdüğü dict orijinal VirusTotal dict'i ile aynı yapıda:
    {
        "malicious": int,   # 0, 1, 2, 3+ 
        "suspicious": int,
        "source": str       # hangi feed'den geldi
    }
    Böylece mevcut penalty kodun (>=3, >=1) hiç değişmez.
    """
    cur = conn.cursor()
    domain = urlparse(url).netloc.lower().replace("www.", "")
    malicious_hits = 0
    suspicious_hits = 0
    source = None

    # --- KONTROL 1: Exact URL match (feed DB'nde var mı?) ---
    cur.execute("""
        SELECT phish_id FROM phishing_urls 
        WHERE url = %s AND status = 'valid'
        LIMIT 1
    """, (url,))
    if row := cur.fetchone():
        # Direkt DB hit → 5 motor işaretledi gibi davran (40 penalty tetiklenir)
        return {"malicious": 5, "suspicious": 0, "source": row[0]}

    # --- KONTROL 2: Domain exact match ---
    cur.execute("""
        SELECT phish_id, COUNT(*) as cnt FROM phishing_urls
        WHERE domain_norm = %s AND status = 'valid'
        GROUP BY phish_id
    """, (domain,))
    rows = cur.fetchall()
    if rows:
        total_hits = sum(r[1] for r in rows)
        source = rows[0][0]
        if total_hits >= 3:
            return {"malicious": 3, "suspicious": 0, "source": source}
        else:
            return {"malicious": 1, "suspicious": 0, "source": source}

    # --- KONTROL 3: Fuzzy domain match (typosquatting tespiti) ---
    # DB'deki domainleri tek tek değil, sample ile karşılaştır (performans)
    cur.execute("""
        SELECT DISTINCT domain_norm FROM phishing_urls
        WHERE status = 'valid'
        AND length(domain_norm) BETWEEN %s AND %s
        LIMIT 5000
    """, (len(domain) - 3, len(domain) + 3))
    
    db_domains = [r[0] for r in cur.fetchall()]
    best_score = 0
    best_domain = None
    
    for db_domain in db_domains:
        score = fuzz.token_sort_ratio(domain, db_domain)
        if score > best_score:
            best_score = score
            best_domain = db_domain

    if best_score >= 90:
        # Çok benzer domain → 3 motor işaretledi gibi (40 penalty)
        return {"malicious": 3, "suspicious": 0, "source": f"fuzzy:{best_domain}"}
    elif best_score >= 75:
        # Biraz benzer → 1 motor işaretledi gibi (20 penalty)
        return {"malicious": 1, "suspicious": 0, "source": f"fuzzy:{best_domain}"}

    # --- KONTROL 4: URL feature skoru (hiçbir yerde bulunamadı) ---
    suspicious_score = _calculate_url_suspicion(url, domain)
    if suspicious_score >= 3:
        suspicious_hits = 2  # 10 penalty tetiklenir
    elif suspicious_score >= 2:
        suspicious_hits = 1  # 10 penalty tetiklenir

    return {"malicious": malicious_hits, "suspicious": suspicious_hits, "source": None}


def _calculate_url_suspicion(url: str, domain: str) -> int:
    """
    URL'nin şüpheli özelliklerini sayar.
    Her şüpheli özellik 1 puan, toplam 5+ → kesin şüpheli
    """
    score = 0
    url_lower = url.lower()

    # Uzun URL
    if len(url) > 100:
        score += 1

    # Çok fazla subdomain
    if domain.count('.') >= 4:
        score += 1

    # IP adresi kullanımı
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 2

    # Riskli TLD
    RISKY_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', 
                  '.work', '.click', '.loan', '.win', '.racing'}
    if any(domain.endswith(tld) for tld in RISKY_TLDS):
        score += 1

    # Phishing anahtar kelimeleri URL'de
    PHISHING_KEYWORDS = [
        'verify', 'secure', 'login', 'update', 'confirm', 'account',
        'banking', 'paypal', 'instagram', 'facebook', 'apple', 'google',
        'microsoft', 'amazon', 'netflix', 'doğrula', 'hesap', 'güvenlik'
    ]
    hits = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    score += min(hits, 2)  # max 2 puan

    # Çok fazla tire veya rakam
    if domain.count('-') >= 3:
        score += 1
    if sum(c.isdigit() for c in domain) / max(len(domain), 1) > 0.4:
        score += 1

    # Encoding / obfuscation
    if '%' in url and url.count('%') > 3:
        score += 1

    return score


# ============================================================
# ABUSEIPDB REPLACEMENT → check_abuseipdb_local()
# Orijinal: aipdb["abuse_score"] döndürüyordu (0-100)
# Bu fonksiyon aynı dict yapısını döndürür
# ============================================================

# IP blacklist'leri memory'e yükle (uygulama başlarken bir kez çalıştır)
_IP_BLACKLIST: set = set()
_IP_NETWORKS: list = []

def load_ip_blacklists(filepath_dir: str = "/opt/phishing/ip_lists"):
    """
    Firehol + Spamhaus listelerini memory'e yükler.
    Celery beat ile günde 1 kez refresh edilmeli.
    """
    global _IP_BLACKLIST, _IP_NETWORKS
    import os

    _IP_BLACKLIST = set()
    _IP_NETWORKS = []

    list_files = [
        f"{filepath_dir}/firehol_level1.netset",
        f"{filepath_dir}/spamhaus_drop.txt",
        f"{filepath_dir}/spamhaus_edrop.txt",
        f"{filepath_dir}/emerging_threats.txt",
    ]

    for fpath in list_files:
        if not os.path.exists(fpath):
            logger.warning(f"IP list file not found: {fpath}")
            continue
        with open(fpath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                try:
                    if '/' in line:
                        _IP_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                    else:
                        _IP_BLACKLIST.add(line)
                except ValueError:
                    continue

    logger.info(f"Loaded {len(_IP_BLACKLIST)} IPs and {len(_IP_NETWORKS)} networks to memory")
    return len(_IP_BLACKLIST) + len(_IP_NETWORKS)


def check_abuseipdb_local(url: str) -> dict:
    """
    Döndürdüğü dict orijinal AbuseIPDB dict'i ile aynı yapıda:
    {"abuse_score": int}  # 0-100
    Mevcut penalty kodu (>= 70) hiç değişmez.
    """
    domain = urlparse(url).netloc.lower().replace("www.", "")

    # Domain'den IP çöz
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        # DNS çözümlenemedi → şüpheli say
        return {"abuse_score": 50}

    ip_obj = ipaddress.ip_address(ip)

    # Private IP → temiz
    if ip_obj.is_private or ip_obj.is_loopback:
        return {"abuse_score": 0}

    # Exact IP blacklist kontrolü
    if ip in _IP_BLACKLIST:
        return {"abuse_score": 85}  # 25 penalty tetiklenir

    # CIDR network kontrolü
    for network in _IP_NETWORKS:
        if ip_obj in network:
            return {"abuse_score": 75}  # 25 penalty tetiklenir

    return {"abuse_score": 0}
