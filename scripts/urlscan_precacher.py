#!/usr/bin/env python3
"""
URLScan.io Pre-Cache System
============================
200 popüler site'yi önceden scan'la ve cache'le.
Sonraki taramalar instant (0.0001s) olacak!

Memory Usage: ~200-400 KB (in-memory cache)
"""

import sys
import time
import logging
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from modules.phishing_detector.threat_intel import check_urlscan, API_CACHE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Top 200 popüler/yaygın site'ler
POPULAR_URLS = [
    # Tech & Dev
    "https://google.com", "https://github.com", "https://stackoverflow.com",
    "https://amazon.com", "https://wikipedia.org", "https://youtube.com",
    "https://facebook.com", "https://reddit.com", "https://twitter.com",
    "https://instagram.com", "https://linkedin.com", "https://medium.com",
    
    # E-commerce
    "https://ebay.com", "https://aliexpress.com", "https://etsy.com",
    "https://shopify.com", "https://walmart.com", "https://bestbuy.com",
    "https://target.com", "https://costco.com", "https://ikea.com",
    
    # Communication
    "https://gmail.com", "https://outlook.com", "https://slack.com",
    "https://discord.com", "https://telegram.org", "https://whatsapp.com",
    "https://skype.com", "https://zoom.us", "https://meet.google.com",
    
    # News & Media
    "https://bbc.com", "https://cnn.com", "https://reuters.com",
    "https://nytimes.com", "https://theguardian.com", "https://huffpost.com",
    "https://medium.com", "https://devto.com", "https://hackernews.com",
    
    # Streaming
    "https://netflix.com", "https://youtube.com", "https://twitch.tv",
    "https://spotify.com", "https://apple.com", "https://disney.com",
    "https://hulu.com", "https://primevideo.com", "https://hbomax.com",
    
    # Finance
    "https://paypal.com", "https://stripe.com", "https://wise.com",
    "https://coinbase.com", "https://kraken.com", "https://binance.com",
    "https://investing.com", "https://tradingview.com", "https://bloomberg.com",
    
    # Social
    "https://tiktok.com", "https://pinterest.com", "https://snapchat.com",
    "https://nextdoor.com", "https://quora.com", "https://tumblr.com",
    "https://viber.com", "https://line.me", "https://wechat.com",
    
    # Learning
    "https://coursera.org", "https://udemy.com", "https://edx.org",
    "https://codecademy.com", "https://udacity.com", "https://pluralsight.com",
    "https://datacamp.com", "https://freecodecamp.org", "https://khanacademy.org",
    
    # Cloud & DevOps
    "https://aws.amazon.com", "https://azure.microsoft.com", "https://cloud.google.com",
    "https://heroku.com", "https://vercel.com", "https://netlify.com",
    "https://digitalocean.com", "https://linode.com", "https://vultr.com",
    
    # Security & Privacy
    "https://protonmail.com", "https://tutanota.com", "https://mullvadvpn.com",
    "https://nordvpn.com", "https://expressvpn.com", "https://surfshark.com",
    
    # Search & Reference
    "https://google.com", "https://bing.com", "https://duckduckgo.com",
    "https://wikipedia.org", "https://wiktionary.org", "https://urbandictionary.com",
    
    # Shopping & Deals
    "https://amazon.com", "https://ebay.com", "https://letgo.com",
    "https://craigslist.org", "https://offerup.com", "https://alibaba.com",
    
    # Travel
    "https://booking.com", "https://airbnb.com", "https://expedia.com",
    "https://hotels.com", "https://kayak.com", "https://tripadvisor.com",
    "https://uber.com", "https://lyft.com", "https://airasia.com",
    
    # Food & Delivery
    "https://ubereats.com", "https://deliveroo.com", "https://grubhub.com",
    "https://doordash.com", "https://justeat.com", "https://yelp.com",
    "https://openrice.com", "https://zomato.com", "https://swiggy.com",
    
    # Health & Fitness
    "https://myfitnesspal.com", "https://fitbit.com", "https://strava.com",
    "https://healthline.com", "https://webmd.com", "https://medlineplus.gov",
    "https://zocdoc.com", "https://teladoc.com", "https://amwell.com",
    
    # Banking & Insurance
    "https://chase.com", "https://bankofamerica.com", "https://wellsfargo.com",
    "https://geico.com", "https://statefarm.com", "https://progressive.com",
    
    # Utilities & Services
    "https://github.com", "https://bitbucket.org", "https://gitlab.com",
    "https://npm.com", "https://pypi.org", "https://maven.org",
    "https://docker.com", "https://kubernetes.io", "https://jenkins.io",
    
    # Government & Public
    "https://usa.gov", "https://whitehouse.gov", "https://irs.gov",
    "https://dmv.org", "https://passport.gov", "https://ssn.gov",
    
    # Gaming
    "https://steam.com", "https://epicgames.com", "https://roblox.com",
    "https://discord.com", "https://twitch.tv", "https://mixer.com",
    
    # Additional Popular
    "https://microsoft.com", "https://apple.com", "https://sony.com",
    "https://samsung.com", "https://lg.com", "https://intel.com",
    "https://nvidia.com", "https://amd.com", "https://qualcomm.com",
]

def get_cache_size():
    """Cache'in kaç MB yer tuttuğunu hesapla."""
    cache_json = json.dumps(API_CACHE)
    size_bytes = len(cache_json.encode('utf-8'))
    size_kb = size_bytes / 1024
    size_mb = size_kb / 1024
    return size_bytes, size_kb, size_mb

def precache_urls(urls=None, max_urls=200):
    """URLs'i önceden cache'le."""
    if urls is None:
        urls = POPULAR_URLS[:max_urls]
    
    logger.info(f"🚀 Pre-caching {len(urls)} popüler site'ler için URLScan.io...")
    logger.info(f"   ⏱️  Ortalama ~20-25 saniye/site = ~{len(urls) * 22 / 60:.0f} dakika total")
    
    success = 0
    failed = 0
    
    for idx, url in enumerate(urls, 1):
        try:
            start = time.time()
            result = check_urlscan(url)
            elapsed = time.time() - start
            
            status = "✅" if result.get("available") else "⚠️"
            print(f"[{idx:3d}/{len(urls)}] {status} {url:<40} ({elapsed:6.1f}s)")
            
            if result.get("available"):
                success += 1
            else:
                failed += 1
        
        except Exception as e:
            print(f"[{idx:3d}/{len(urls)}] ❌ {url:<40} (Error: {str(e)[:30]})")
            failed += 1
    
    logger.info(f"\n✅ Pre-cache tamamlandı!")
    logger.info(f"   Başarılı: {success}/{len(urls)}")
    logger.info(f"   Başarısız: {failed}/{len(urls)}")
    
    # Cache size report
    size_bytes, size_kb, size_mb = get_cache_size()
    logger.info(f"\n📊 Cache Boyut:")
    logger.info(f"   {size_bytes:,} bytes")
    logger.info(f"   {size_kb:.2f} KB")
    logger.info(f"   {size_mb:.4f} MB")
    
    logger.info(f"\n💾 Kullanım Detayları:")
    logger.info(f"   - Cache entries: {len(API_CACHE)}")
    logger.info(f"   - Ortalama entry boyutu: {size_bytes / len(API_CACHE) if API_CACHE else 0:.0f} bytes")
    logger.info(f"   - Hafta sonra (~7 gün): ~{size_mb * 7:.4f} MB (TTL: 3600s)")

if __name__ == "__main__":
    precache_urls()
