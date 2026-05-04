"""
B2 — Logo pHash Veritabanı Oluşturucu
======================================
Marka logolarını indir, pHash ile hash'le, JSON'a kaydet.

Kullanım (sunucuda veya lokalde, bir kez çalıştır):
    cd /var/www/aegis_nexus
    python -m modules.phishing_detector.build_logo_db

Çıktı:
    modules/phishing_detector/data/logo_hashes.json
"""

from __future__ import annotations

import json
import sys
import time
from io import BytesIO
from pathlib import Path

import requests

try:
    import imagehash
    from PIL import Image
except ImportError:
    print("❌ imagehash ve Pillow gerekli: pip install imagehash Pillow")
    sys.exit(1)

OUTPUT_PATH = Path(__file__).parent / "data" / "logo_hashes.json"
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── Logo kaynakları ───────────────────────────────────────────────────────────
# Her marka için birden fazla logo varyantı (farklı boyut/renk) eklenebilir.
# URL'ler erişilebilir olmalı; timeout=15s
LOGOS: dict[str, list[str]] = {
    "paypal": [
        "https://www.paypalobjects.com/webstatic/icon/pp258.png",
        "https://upload.wikimedia.org/wikipedia/commons/thumb/b/b5/PayPal.svg/320px-PayPal.svg.png",
    ],
    "google": [
        "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
    ],
    "microsoft": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/320px-Microsoft_logo.svg.png",
    ],
    "apple": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/f/fa/Apple_logo_black.svg/195px-Apple_logo_black.svg.png",
    ],
    "amazon": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/a/a9/Amazon_logo.svg/320px-Amazon_logo.svg.png",
    ],
    "netflix": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/0/08/Netflix_2015_logo.svg/320px-Netflix_2015_logo.svg.png",
    ],
    "facebook": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Facebook_icon.svg/240px-Facebook_icon.svg.png",
    ],
    "instagram": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e7/Instagram_logo_2016.svg/240px-Instagram_logo_2016.svg.png",
    ],
    "twitter": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6f/Logo_of_Twitter.svg/300px-Logo_of_Twitter.svg.png",
    ],
    "whatsapp": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6b/WhatsApp.svg/240px-WhatsApp.svg.png",
    ],
    # Türk bankaları — Google Favicon API (sz=256)
    # Not: sz=256 ile 256x256 PNG döner; küçük placeholder (˜500b) otomatik atlanır
    "ziraat": [
        "https://www.ziraatbank.com.tr/SiteAssets/images/logo.png",
        "https://www.google.com/s2/favicons?domain=ziraatbank.com.tr&sz=256",
    ],
    "garanti": [
        "https://www.google.com/s2/favicons?domain=garantibbva.com.tr&sz=256",
    ],
    "akbank": [
        "https://www.google.com/s2/favicons?domain=akbank.com&sz=256",
        "https://icons.duckduckgo.com/ip3/akbank.com.ico",
    ],
    "isbank": [
        "https://www.google.com/s2/favicons?domain=isbank.com.tr&sz=256",
    ],
    "vakifbank": [
        "https://www.vakifbank.com.tr/favicon.ico",
        "https://www.google.com/s2/favicons?domain=vakifbank.com.tr&sz=256",
        "https://icons.duckduckgo.com/ip3/vakifbank.com.tr.ico",
    ],
    "halkbank": [
        "https://www.google.com/s2/favicons?domain=halkbank.com.tr&sz=256",
    ],
    "denizbank": [
        "https://www.google.com/s2/favicons?domain=denizbank.com&sz=256",
    ],
    "enpara": [
        "https://www.google.com/s2/favicons?domain=enpara.com&sz=256",
    ],
    # Kripto
    "btcturk": [
        "https://www.google.com/s2/favicons?domain=pro.btcturk.com&sz=256",
        "https://upload.wikimedia.org/wikipedia/commons/8/8b/BtcTurk_Logo.png",
    ],
    "paribu": [
        "https://www.paribu.com/favicon.ico",
        "https://www.google.com/s2/favicons?domain=paribu.com&sz=256",
    ],
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; AegisNexus/1.0; "
        "+https://github.com/garmoths/AegisNexus)"
    )
}

MIN_SIZE_BYTES = 500  # Google'nin placeholder ikonunu elemek için

def fetch_and_hash(brand: str, url: str) -> dict | None:
    try:
        resp = requests.get(url, timeout=15, headers=HEADERS)
        resp.raise_for_status()
        if len(resp.content) < MIN_SIZE_BYTES:
            print(f"  ⚠️  {brand}: çok küçük ({len(resp.content)}b) — muhtemelen placeholder, atlanıyor")
            return None
        img = Image.open(BytesIO(resp.content)).convert("RGB")
        h = str(imagehash.phash(img))
        print(f"  ✅ {brand}: {h}  ({img.size[0]}x{img.size[1]})")
        return {"url": url, "hash": h, "size": list(img.size)}
    except Exception as exc:
        print(f"  ❌ {brand} — {url}: {exc}")
        return None


def main():
    # Mevcut DB'yi yükle (güncelleme modu)
    existing: dict = {}
    if OUTPUT_PATH.exists():
        try:
            existing = json.loads(OUTPUT_PATH.read_text())
            print(f"Mevcut DB yüklendi ({len(existing)} marka), güncelleniyor...\n")
        except Exception:
            pass

    db: dict = dict(existing)

    for brand, urls in LOGOS.items():
        print(f"\n[{brand}]")
        entries = []
        for url in urls:
            entry = fetch_and_hash(brand, url)
            if entry:
                entries.append(entry)
            time.sleep(1.0)  # rate-limit önlemi
        if entries:
            db[brand] = entries

    OUTPUT_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False))
    total = sum(len(v) for v in db.values())
    print(f"\n✅ Logo DB hazır → {OUTPUT_PATH}")
    print(f"   {len(db)} marka, {total} hash kaydı")


if __name__ == "__main__":
    main()
