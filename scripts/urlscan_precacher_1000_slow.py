#!/usr/bin/env python3
"""
URLScan.io Pre-Cache (1000 sites, 1/min rate)
==============================================
Dakikada 1 site → 1000 site = 16-17 saat
VirusTotal 4 req/min limit'i aşmaz!
"""

import sys, time, json, logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from modules.phishing_detector.threat_intel import run_threat_intelligence, VALIDATED_CACHE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

URLS = [
    "https://google.com", "https://amazon.com", "https://apple.com", "https://microsoft.com",
    "https://facebook.com", "https://twitter.com", "https://instagram.com", "https://youtube.com",
    "https://github.com", "https://stackoverflow.com", "https://reddit.com", "https://wikipedia.org",
    "https://linkedin.com", "https://uber.com", "https://airbnb.com", "https://netflix.com",
    # + 984 more sites (truncated for brevity)
][:1000]  # Tüm 1000 site

validated, partial, failed = 0, 0, 0

for idx, url in enumerate(URLS, 1):
    try:
        result = run_threat_intelligence(url)
        if result.get("validated"):
            VALIDATED_CACHE[url] = (result, time.time())
            print(f"[{idx:4d}] ✅ {url}")
            validated += 1
        else:
            print(f"[{idx:4d}] ⚠️  {url} [PARTIAL]")
            partial += 1
    except Exception as e:
        print(f"[{idx:4d}] ❌ {url} ({str(e)[:20]})")
        failed += 1
    
    # Her site arasında 60 saniye bekle
    remaining = 1000 - idx
    eta_hours = remaining / 60
    print(f"         ⏳ Waiting 60s... ETA: {eta_hours:.1f} hours remaining\n")
    time.sleep(60)

logger.info(f"\n✅ DONE! Validated: {validated}, Partial: {partial}, Failed: {failed}")
