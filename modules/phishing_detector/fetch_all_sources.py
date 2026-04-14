"""
Multi-Source Phishing Data Aggregator
Ücretsiz kaynaklardan toplu phishing verisi çeker
"""
import requests
import json
import os
import csv
import io
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.models import PhishingURL
from .url_normalize import normalize_url_record

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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


def fetch_phishtank_data() -> List[str]:
    """Phishtank JSON'dan URL'ler"""
    phishtank_path = os.path.join(BASE_DIR, "phishtank.json")
    
    if not os.path.exists(phishtank_path):
        return []
    
    try:
        with open(phishtank_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if isinstance(data, dict) and 'data' in data:
            data = data['data']
        
        urls = []
        for entry in data:
            url = entry.get('url', '')
            if url and url.startswith('http'):
                urls.append(url)
        
        return list(set(urls))
    except Exception as e:
        print(f"Phishtank hatasi: {e}")
    return []


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
            
            # Duplicate kontrolu
            existing = db.query(PhishingURL).filter(
                PhishingURL.phish_id == phish_id
            ).first()
            
            url = entry.get('url', '')
            normalized = normalize_url_record(url)
            
            if existing:
                existing.url = url
                existing.url_hash = normalized.get('url_hash')
                existing.domain_norm = normalized.get('domain_norm')
                existing.status = entry.get('status', 'unknown')
                existing.online = entry.get('online', False)
                existing.target = entry.get('target', 'Unknown')
                updated += 1
            else:
                new_entry = PhishingURL(
                    phish_id=phish_id,
                    url=url,
                    url_hash=normalized.get('url_hash'),
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
    
    print("\n" + "="*60)
    print("🚀 MULTI-SOURCE PHISHING DATA AGGREGATOR")
    print("="*60)
    
    # 1. URLHaus
    print("\n📡 1. URLHaus'ten veri cekiliyor...")
    urls = fetch_urlhaus_data()
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
    urls = fetch_openphish_data()
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
    urls = fetch_tweetfeed_data()
    if urls:
        entries = convert_to_phishtank_format(urls, "tweetfeed")
        result = import_to_database(db, entries)
        all_results['tweetfeed'] = result
        total_added += result['added']
        total_updated += result['updated']
        print(f"   ✅ TweetFeed: {result['total']} URL, {result['added']} eklendi")
    else:
        print("   ⚠️  TweetFeed verisi alinamadi")
    
    # 4. Phishtank JSON (yerel)
    print("\n📡 4. Phishtank JSON'dan veri cekiliyor...")
    urls = fetch_phishtank_data()
    if urls:
        entries = convert_to_phishtank_format(urls, "phishtank_json")
        result = import_to_database(db, entries)
        all_results['phishtank'] = result
        total_added += result['added']
        total_updated += result['updated']
        print(f"   ✅ Phishtank JSON: {result['total']} URL, {result['added']} eklendi")
    else:
        print("   ⚠️  Phishtank JSON bulunamadi")
    
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
