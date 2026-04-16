"""
Multi-Source Phishing Data Aggregator
Ücretsiz kaynaklardan toplu phishing verisi çeker
"""
import requests
import os
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.models import PhishingURL
from .url_normalize import normalize_url_record

DEFAULT_GITHUB_FEEDS = {
    "github_phishing_active": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "github_phishing_new_today": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
    "github_spam404": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "github_phishingdb_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "github_phishingdb_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
}


def get_github_feed_urls() -> Dict[str, str]:
    """GitHub feed URL'lerini env'den veya varsayilandan alir."""
    raw = os.getenv("PHISHING_GITHUB_FEEDS", "").strip()
    if not raw:
        return DEFAULT_GITHUB_FEEDS

    feeds: Dict[str, str] = {}
    for idx, item in enumerate(raw.split(","), start=1):
        url = item.strip()
        if not url:
            continue
        feeds[f"github_custom_{idx}"] = url

    return feeds or DEFAULT_GITHUB_FEEDS


def fetch_urlhaus_data() -> List[str]:
    """URLHaus'tan son 30 günün phishing URL'leri"""
    try:
        url = "https://urlhaus-api.abuse.ch/downloads/csv_recent/"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            urls = []
            lines = response.text.split('\n')
            for line in lines[9:]:  # İlk 9 satır header
                parts = line.split('","')
                if len(parts) >= 3:
                    url = parts[2].replace('"', '')
                    if url.startswith('http'):
                        urls.append(url)
            return list(set(urls))  # Unique
    except Exception as e:
        print(f"URLHaus hatasi: {e}")
    return []


def fetch_openphish_data() -> List[str]:
    """OpenPhish'ten canli feed"""
    try:
        url = "https://openphish.com/feed.txt"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            urls = [u.strip() for u in response.text.split('\n') if u.strip().startswith('http')]
            return list(set(urls))
    except Exception as e:
        print(f"OpenPhish hatasi: {e}")
    return []


def parse_feed_lines_to_urls(content: str) -> List[str]:
    """Duz metin feed satirlarini URL listesine cevirir."""
    urls = set()

    for raw_line in content.splitlines():
        line = raw_line.strip().strip('"').strip("'")
        if not line or line.startswith("#"):
            continue

        # Olasi CSV ve yorum formatlarini temizle
        if "," in line:
            line = line.split(",", 1)[0].strip()
        if " " in line:
            line = line.split(" ", 1)[0].strip()

        if line.startswith(("http://", "https://")):
            urls.add(line)
            continue

        if line.startswith("www."):
            urls.add(f"http://{line}")
            continue

        # Domain/path formati geldiyse de kabul et
        if "." in line and "/" in line:
            urls.add(f"http://{line}")
            continue

        # Sadece domain ise de yakala
        if "." in line and " " not in line:
            urls.add(f"http://{line}")

    return list(urls)


def fetch_github_feed_data(feed_url: str) -> List[str]:
    """GitHub raw feed'den URL listesini ceker."""
    try:
        response = requests.get(feed_url, timeout=60)
        if response.status_code == 200:
            return parse_feed_lines_to_urls(response.text)
    except Exception as e:
        print(f"GitHub feed hatasi ({feed_url}): {e}")
    return []


def deduplicate_urls(urls: List[str], seen_hashes: Optional[Set[str]] = None) -> List[str]:
    """URL'leri normalize ederek hash bazli tekillestirir."""
    unique_urls: List[str] = []
    local_hashes: Set[str] = set()

    for raw_url in urls:
        normalized = normalize_url_record(raw_url)
        url_hash = normalized.get("url_hash")
        if not url_hash:
            continue

        if url_hash in local_hashes:
            continue
        if seen_hashes is not None and url_hash in seen_hashes:
            continue

        local_hashes.add(url_hash)
        if seen_hashes is not None:
            seen_hashes.add(url_hash)

        unique_urls.append(normalized.get("canonical_url") or raw_url)

    return unique_urls


def fetch_tweetfeed_data() -> List[str]:
    """TweetFeed'ten IoC'ler (Twitter'da paylasilan phishing linkleri)"""
    try:
        url = "https://api.tweetfeed.live/v1/today"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            urls = []
            for item in data:
                if item.get('type') == 'url' and item.get('value', '').startswith('http'):
                    urls.append(item['value'])
            return list(set(urls))
    except Exception as e:
        print(f"TweetFeed hatasi: {e}")
    return []


def fetch_malwarebazaar_urls() -> List[str]:
    """MalwareBazaar'dan son yuklenen orneklerin C2 URL'leri"""
    try:
        headers = {
            'API-KEY': 'free'  # Ucretsiz, rate limitli
        }
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {
            'query': 'get_recent',
            'selector': '100'  # Son 100
        }
        response = requests.post(url, headers=headers, data=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            urls = []
            for sample in result.get('data', []):
                c2 = sample.get('c2', [])
                for c2_url in c2:
                    if c2_url.startswith('http'):
                        urls.append(c2_url)
            return list(set(urls))
    except Exception as e:
        print(f"MalwareBazaar hatasi: {e}")
    return []


def extract_target_from_url(url: str) -> str:
    """URL'den hedef marka tahmini"""
    try:
        domain = urlparse(url).netloc.lower()
        
        brands = {
            'facebook': 'Facebook', 'fb': 'Facebook', 'instagram': 'Instagram',
            'twitter': 'Twitter', 'x.com': 'X', 'google': 'Google', 'gmail': 'Gmail',
            'microsoft': 'Microsoft', 'outlook': 'Microsoft', 'office365': 'Microsoft',
            'apple': 'Apple', 'icloud': 'Apple', 'amazon': 'Amazon', 'netflix': 'Netflix',
            'paypal': 'PayPal', 'chase': 'Chase Bank', 'wellsfargo': 'Wells Fargo',
            'bankofamerica': 'Bank of America', 'citi': 'Citibank', 'amex': 'American Express',
            'linkedin': 'LinkedIn', 'github': 'GitHub', 'dropbox': 'Dropbox',
            'adobe': 'Adobe', 'steam': 'Steam', 'epicgames': 'Epic Games',
            'roblox': 'Roblox', 'tiktok': 'TikTok', 'snapchat': 'Snapchat',
            'whatsapp': 'WhatsApp', 'telegram': 'Telegram', 'discord': 'Discord',
            'spotify': 'Spotify', 'ebay': 'eBay', 'alibaba': 'Alibaba',
            'aliexpress': 'AliExpress', 'binance': 'Binance', 'coinbase': 'Coinbase',
            'twitch': 'Twitch', 'youtube': 'YouTube', 'zoom': 'Zoom', 'webex': 'Cisco Webex'
        }
        
        for key, brand in brands.items():
            if key in domain:
                return brand
        
        return "Unknown"
    except:
        return "Unknown"


def convert_to_phishtank_format(urls: List[str], source: str) -> List[Dict]:
    """URL listesini Phishtank formatina cevir"""
    entries = []
    timestamp = datetime.utcnow().isoformat()
    
    for i, url in enumerate(urls):
        entry = {
            "phish_id": f"{source}_{abs(hash(url)) % 1000000000}",
            "url": url,
            "phish_detail_url": url,
            "status": "valid",
            "online": True,
            "target": extract_target_from_url(url),
            "submission_time": timestamp,
            "source": source
        }
        entries.append(entry)
    
    return entries


def import_to_database(db: Session, entries: List[Dict], batch_size: int = 1000) -> Dict:
    """Entry'leri veritabanina aktar"""
    added = 0
    updated = 0
    errors = 0
    
    for i, entry in enumerate(entries):
        try:
            phish_id = str(entry.get('phish_id', ''))
            if not phish_id:
                continue

            url = entry.get('url', '')
            normalized = normalize_url_record(url)
            url_hash = normalized.get('url_hash')
            if not url_hash:
                errors += 1
                continue

            # Global duplicate kontrolu (kaynak fark etmeksizin)
            existing_by_hash = db.query(PhishingURL).filter(
                PhishingURL.url_hash == url_hash
            ).first()

            if existing_by_hash:
                existing_by_hash.url = normalized.get('canonical_url') or url
                existing_by_hash.domain_norm = normalized.get('domain_norm')
                existing_by_hash.status = entry.get('status', 'unknown')
                existing_by_hash.online = entry.get('online', False)
                existing_by_hash.target = entry.get('target', 'Unknown')
                updated += 1
            else:
                # Ayni phish_id daha once kaydedildiyse guncelle
                existing_by_id = db.query(PhishingURL).filter(
                    PhishingURL.phish_id == phish_id
                ).first()

                if existing_by_id:
                    existing_by_id.url = normalized.get('canonical_url') or url
                    existing_by_id.url_hash = url_hash
                    existing_by_id.domain_norm = normalized.get('domain_norm')
                    existing_by_id.status = entry.get('status', 'unknown')
                    existing_by_id.online = entry.get('online', False)
                    existing_by_id.target = entry.get('target', 'Unknown')
                    updated += 1
                    continue

                new_entry = PhishingURL(
                    phish_id=phish_id,
                    url=normalized.get('canonical_url') or url,
                    url_hash=url_hash,
                    domain_norm=normalized.get('domain_norm'),
                    status=entry.get('status', 'unknown'),
                    online=entry.get('online', False),
                    target=entry.get('target', 'Unknown'),
                    submission_time=datetime.utcnow()
                )
                db.add(new_entry)
                added += 1
            
            if (i + 1) % batch_size == 0:
                db.commit()
                print(f"  Islenen: {i + 1}/{len(entries)} (Eklendi: {added}, Guncellendi: {updated})")
                
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Kayit hatasi: {e}")
            continue
    
    db.commit()
    
    return {
        "total": len(entries),
        "added": added,
        "updated": updated,
        "errors": errors
    }


def fetch_all_sources(db: Session) -> Dict:
    """Tum kaynaklardan veri cek ve birlestir"""
    all_results = {}
    total_added = 0
    total_updated = 0
    global_seen_hashes: Set[str] = set()
    
    print("\n" + "="*60)
    print("🚀 MULTI-SOURCE PHISHING DATA AGGREGATOR")
    print("="*60)
    
    # 1. URLHaus
    print("\n📡 1. URLHaus'ten veri cekiliyor...")
    urls = deduplicate_urls(fetch_urlhaus_data(), seen_hashes=global_seen_hashes)
    if urls:
        entries = convert_to_phishtank_format(urls, "urlhaus")
        result = import_to_database(db, entries)
        all_results['urlhaus'] = result
        total_added += result['added']
        total_updated += result['updated']
        print(f"   ✅ URLHaus: {result['total']} URL, {result['added']} eklendi")
    else:
        print("   ⚠️  URLHaus verisi alinamadi")
    
    # 2. OpenPhish
    print("\n📡 2. OpenPhish'ten veri cekiliyor...")
    urls = deduplicate_urls(fetch_openphish_data(), seen_hashes=global_seen_hashes)
    if urls:
        entries = convert_to_phishtank_format(urls, "openphish")
        result = import_to_database(db, entries)
        all_results['openphish'] = result
        total_added += result['added']
        total_updated += result['updated']
        print(f"   ✅ OpenPhish: {result['total']} URL, {result['added']} eklendi")
    else:
        print("   ⚠️  OpenPhish verisi alinamadi")
    
    # 3. TweetFeed
    print("\n📡 3. TweetFeed'ten veri cekiliyor...")
    urls = deduplicate_urls(fetch_tweetfeed_data(), seen_hashes=global_seen_hashes)
    if urls:
        entries = convert_to_phishtank_format(urls, "tweetfeed")
        result = import_to_database(db, entries)
        all_results['tweetfeed'] = result
        total_added += result['added']
        total_updated += result['updated']
        print(f"   ✅ TweetFeed: {result['total']} URL, {result['added']} eklendi")
    else:
        print("   ⚠️  TweetFeed verisi alinamadi")
    
    # 4. GitHub buyuk feed'leri
    print("\n📡 4. GitHub buyuk feed'lerinden veri cekiliyor...")
    github_feeds = get_github_feed_urls()
    for source_name, feed_url in github_feeds.items():
        print(f"   ↳ {source_name}: {feed_url}")
        urls = deduplicate_urls(fetch_github_feed_data(feed_url), seen_hashes=global_seen_hashes)
        if urls:
            entries = convert_to_phishtank_format(urls, source_name)
            result = import_to_database(db, entries)
            all_results[source_name] = result
            total_added += result['added']
            total_updated += result['updated']
            print(f"   ✅ {source_name}: {result['total']} URL, {result['added']} eklendi")
        else:
            print(f"   ⚠️  {source_name}: veri alinamadi")
    
    print("\n" + "="*60)
    print("📊 OZET")
    print("="*60)
    print(f"   Toplam yeni eklenen: {total_added}")
    print(f"   Toplam guncellenen: {total_updated}")
    print(f"   Aktif kaynak: {len([k for k in all_results if all_results[k]['total'] > 0])}")
    
    return {
        "status": "success",
        "sources": all_results,
        "total_added": total_added,
        "total_updated": total_updated
    }


if __name__ == "__main__":
    from shared.utils.db import SessionLocal
    
    db = SessionLocal()
    try:
        result = fetch_all_sources(db)
        print(f"\nSonuc: {result}")
    finally:
        db.close()
