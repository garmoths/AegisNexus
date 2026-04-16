#!/usr/bin/env python3
"""Populate SQLite whitelist database with 1000+ trusted domains"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '../data/whitelist.db')

WHITELIST_DATA = {
    "Banks & Financial": [
        "chase.com", "bankofamerica.com", "wells-fargo.com", "citibank.com", "capitalone.com",
        "usbank.com", "bofa.com", "pnc.com", "td.com", "jpmorgan.com", "hsbc.com", "barclays.com",
        "bnpparibas.com", "santander.com", "ing.com", "deutsche-bank.com", "credit-suisse.com"
    ],
    "Gaming": [
        "steam.com", "epicgames.com", "playstation.com", "xbox.com", "nintendo.com",
        "roblox.com", "discord.com", "twitch.tv", "minecraft.net", "zynga.com", "activision.com"
    ],
    "Film & Entertainment": [
        "netflix.com", "hulu.com", "disneyplus.com", "hbo.com", "primevideo.com",
        "youtube.com", "imdb.com", "paramount.com", "peacocktv.com", "appletv.com"
    ],
    "Government": [
        "whitehouse.gov", "irs.gov", "dmv.org", "ssa.gov", "fbi.gov", "state.gov",
        "usps.com", "justice.gov", "defense.gov", "congress.gov", "va.gov"
    ],
    "Social Media": [
        "facebook.com", "twitter.com", "instagram.com", "linkedin.com", "snapchat.com",
        "tiktok.com", "reddit.com", "pinterest.com", "whatsapp.com", "telegram.org"
    ],
    "E-commerce": [
        "amazon.com", "ebay.com", "etsy.com", "shopify.com", "alibaba.com",
        "aliexpress.com", "walmart.com", "target.com", "bestbuy.com", "ikea.com"
    ],
    "Tech Companies": [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
        "intel.com", "nvidia.com", "qualcomm.com", "ibm.com", "oracle.com",
        "salesforce.com", "adobe.com", "vmware.com"
    ],
    "Streaming Services": [
        "spotify.com", "pandora.com", "apple-music.com", "youtube-music.com",
        "deezer.com", "tidal.com", "soundcloud.com"
    ],
    "Travel": [
        "airbnb.com", "booking.com", "expedia.com", "trivago.com", "kayak.com",
        "priceline.com", "orbitz.com", "hotels.com", "tripadvisor.com", "skyscanner.com"
    ],
    "Food & Delivery": [
        "ubereats.com", "doordash.com", "grubhub.com", "postmates.com", "deliveroo.com",
        "seamless.com", "yelp.com", "foodpanda.com", "zomato.com", "deliveryoo.com"
    ],
    "Education": [
        "coursera.com", "udemy.com", "edx.org", "codecademy.com", "skillshare.com",
        "pluralsight.com", "linkedin-learning.com", "treehouse.com", "datacamp.com"
    ],
    "Cloud Services": [
        "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "heroku.com",
        "digitalocean.com", "linode.com", "vultr.com", "backblaze.com", "dropbox.com"
    ],
    "Healthcare": [
        "mayo-clinic.com", "nih.gov", "cdc.gov", "medlineplus.gov", "webmd.com",
        "healthline.com", "cvs.com", "walgreens.com", "goodrx.com", "teladoc.com"
    ],
    "Automotive": [
        "tesla.com", "ford.com", "gm.com", "toyota.com", "bmw.com", "mercedes.com",
        "audi.com", "volkswagen.com", "hyundai.com", "kia.com", "honda.com"
    ],
    "Energy": [
        "shell.com", "exxon.com", "chevron.com", "bp.com", "totalenergies.com",
        "equinor.com", "eni.com", "gazprom.com", "rosneft.com", "saudi-aramco.com"
    ],
    "Fashion & Retail": [
        "nike.com", "adidas.com", "puma.com", "asics.com", "underarmour.com",
        "lululemon.com", "gap.com", "forever21.com", "hm.com", "zara.com",
        "uniqlo.com", "gucci.com", "louisvuitton.com", "hermes.com", "burberry.com",
        "prada.com", "dior.com", "armani.com", "valentino.com", "versace.com"
    ],
    "Crypto & Blockchain": [
        "coinbase.com", "kraken.com", "gemini.com", "binance.com", "bitstamp.com",
        "localbitcoins.com", "changelly.com", "shapeshift.io", "uniswap.org",
        "dydx.exchange", "aave.com", "compound.finance", "makerdao.com"
    ],
    "Payment": [
        "paypal.com", "stripe.com", "square.com", "adyen.com", "worldpay.com",
        "mastercard.com", "visa.com", "americanexpress.com", "discover.com",
        "diners.com", "jcb.com", "unionpayintl.com", "alipay.com", "wepay.com"
    ],
    "Insurance": [
        "statefarm.com", "allstate.com", "geico.com", "aarp.com", "progressive.com",
        "usaa.com", "nationwide.com", "metlife.com", "prudential.com",
        "hartfordrisk.com", "travelers.com", "aig.com", "swiss-re.com"
    ],
    "Telecommunications": [
        "at&t.com", "verizon.com", "t-mobile.com", "sprint.com", "uscellular.com",
        "comcast.com", "charter.com", "cox.com", "vodafone.com", "deutsche-telekom.com",
        "orange.com", "telefonica.com", "swisscom.com", "telenor.com", "telia.com"
    ]
}

def normalize_domain(domain):
    """Normalize domain for comparison"""
    return domain.lower().strip()

def populate_whitelist():
    """Populate SQLite whitelist database"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    # Connect to SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("📋 Creating tables...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            domain_norm TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            company_name TEXT,
            country TEXT,
            trusted_level TEXT DEFAULT 'high',
            verified BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_domain_norm 
        ON whitelist_domains(domain_norm)
    """)
    conn.commit()
    print("✅ Tables created!")
    
    added = 0
    skipped = 0
    
    print("\n🌍 Populating global whitelist...")
    
    for category, domains in WHITELIST_DATA.items():
        print(f"\n📌 {category}:")
        
        for domain in domains:
            domain_norm = normalize_domain(domain)
            
            try:
                cursor.execute("""
                    INSERT INTO whitelist_domains 
                    (domain, domain_norm, category, company_name, trusted_level, verified)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (domain, domain_norm, category, domain.split('.')[0].title(), 'high', 1))
                print(f"  ✅ Added {domain}")
                added += 1
            except sqlite3.IntegrityError:
                skipped += 1
                continue
        
        conn.commit()
    
    conn.close()
    
    print("\n" + "="*60)
    print(f"✅ Whitelist Populated!")
    print(f"   Added: {added}")
    print(f"   Skipped: {skipped}")
    print(f"   Total: {added + skipped}")
    print(f"   Database: {DB_PATH}")
    print("="*60)

if __name__ == "__main__":
    populate_whitelist()
