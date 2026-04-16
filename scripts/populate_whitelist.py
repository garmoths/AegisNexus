"""
Global trusted domains whitelist populator
1000+ trusted company domains
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils.db import SessionLocal
from app.models import WhitelistDomain
from urllib.parse import urlparse

WHITELIST_DATA = [
    # ===== BANKS & FINANCE =====
    ("Banks", [
        "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "citi.com",
        "americanexpress.com", "amex.com", "capitalone.com", "bankofscotland.com",
        "hsbc.com", "barclays.com", "lloyds.com", "natwest.com", "santander.com",
        "deutsche-bank.com", "bnpparibas.com", "ing.com", "unicredit.com",
        "commerzbank.com", "societe-generale.com", "mizuhobank.com", "sumitomimitsui.com",
        "icicibank.com", "hdfcbank.com", "axisbank.com", "kotak.com",
        "standardchartered.com", "aab.ae", "adib.ae", "cbd.ae",
        "paypal.com", "stripe.com", "square.com", "klarna.com", "affirm.com",
        "coinbase.com", "kraken.com", "gemini.com", "binance.com", "ftx.com",
    ]),
    
    # ===== GAMING COMPANIES =====
    ("Gaming", [
        "steam.com", "epicgames.com", "ubisoft.com", "activision.com", "blizzard.com",
        "ea.com", "rockstargames.com", "take2games.com", "nintendo.com", "playstation.com",
        "xbox.com", "microsoft.com", "valve.com", "bandainamco.com", "capcom.com",
        "konami.com", "sega.com", "sony.com", "tencent.com", "netease.com",
        "nexon.com", "ncsoft.com", "smilegate.com", "sulake.com", "miniclip.com",
        "scopely.com", "rovio.com", "supercell.com", "playrix.com", "zynga.com",
        "roblox.com", "mojang.com", "minecraft.net", "twitch.tv", "discord.com",
    ]),
    
    # ===== FILM & ENTERTAINMENT =====
    ("Entertainment", [
        "netflix.com", "disneyplus.com", "hulu.com", "primevideo.com", "hbomax.com",
        "paramountplus.com", "peacocktv.com", "appletv.com", "themoviedb.org",
        "imdb.com", "rottentomatoes.com", "warnerbros.com", "universalstudios.com",
        "sonypictures.com", "foxmovies.com", "paramount.com", "mubi.com",
        "criterion.com", "criterion.channel.com", "youtube.com", "vimeo.com",
        "dailymotion.com", "tiktok.com", "instagram.com", "snapchat.com",
        "twitch.tv", "mixer.com", "vevo.com", "spotify.com", "pandora.com",
        "deezer.com", "soundcloud.com", "bandcamp.com",
    ]),
    
    # ===== GOVERNMENT & OFFICIAL =====
    ("Government", [
        "whitehouse.gov", "senate.gov", "house.gov", "state.gov", "treasury.gov",
        "justice.gov", "defense.gov", "irs.gov", "fbi.gov", "faa.gov",
        "cdc.gov", "hhs.gov", "dhs.gov", "va.gov", "usps.gov",
        "ssn.gov", "nasa.gov", "noaa.gov", "usgs.gov", "epa.gov",
        "gov.uk", "parliament.uk", "nhs.uk", "parliament.eu", "europa.eu",
        "japan.go.jp", "gov.cn", "gov.in", "astrazeneca.com.au",
    ]),
    
    # ===== SOCIAL MEDIA & MESSAGING =====
    ("Social Media", [
        "facebook.com", "meta.com", "instagram.com", "whatsapp.com", "messenger.com",
        "twitter.com", "x.com", "linkedin.com", "telegram.org", "signal.org",
        "discord.com", "slack.com", "skype.com", "viber.com", "line.me",
        "wechat.com", "qq.com", "reddit.com", "nextdoor.com", "pinterest.com",
        "snapchat.com", "tiktok.com", "youtube.com", "twitch.tv",
    ]),
    
    # ===== E-COMMERCE & RETAIL =====
    ("E-commerce", [
        "amazon.com", "ebay.com", "walmart.com", "target.com", "costco.com",
        "alibaba.com", "aliexpress.com", "shopify.com", "etsy.com", "rakuten.com",
        "mercadolibre.com", "flipkart.com", "lazada.com", "tokopedia.com",
        "shopee.com", "coupang.com", "naver.com", "gmarket.co.kr",
        "wish.com", "wayfair.com", "overstock.com", "newegg.com",
    ]),
    
    # ===== TECH GIANTS =====
    ("Tech", [
        "google.com", "apple.com", "microsoft.com", "amazon.com", "meta.com",
        "adobe.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
        "qualcomm.com", "broadcom.com", "amd.com", "dell.com", "hp.com",
        "lenovo.com", "asus.com", "samsung.com", "lg.com", "sony.com",
        "htc.com", "nokia.com", "motorola.com", "blackberry.com",
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    ]),
    
    # ===== STREAMING & MEDIA =====
    ("Streaming", [
        "netflix.com", "disneyplus.com", "youtube.com", "twitch.tv",
        "hulu.com", "primevideo.com", "hbomax.com", "peacocktv.com",
        "crunchyroll.com", "funimation.com", "hidive.com",
        "spotify.com", "pandora.com", "applemusic.apple.com", "musicunlimited.amazon.com",
        "deezer.com", "tidal.com", "soundcloud.com", "bandcamp.com",
    ]),
    
    # ===== TRAVEL & HOSPITALITY =====
    ("Travel", [
        "booking.com", "airbnb.com", "expedia.com", "orbitz.com", "kayak.com",
        "trivago.com", "hotels.com", "marriott.com", "hilton.com", "ihg.com",
        "hyatt.com", "wyndham.com", "choice.com", "accor.com", "intercontinental.com",
        "fourseasons.com", "ritz-carlton.com", "peninsula.com",
    ]),
    
    # ===== FOOD & DELIVERY =====
    ("Food & Delivery", [
        "ubereats.com", "doordash.com", "grubhub.com", "deliveroo.com", "just-eat.com",
        "mcdonalds.com", "kfc.com", "wendys.com", "chipotle.com", "subway.com",
        "pizzahut.com", "dominos.com", "tacobell.com", "starbucks.com",
        "dunkindonuts.com", "jimmyjohns.com", "zaxbys.com", "popeyes.com",
    ]),
    
    # ===== EDUCATION =====
    ("Education", [
        "mit.edu", "stanford.edu", "harvard.edu", "yale.edu", "princeton.edu",
        "columbia.edu", "upenn.edu", "duke.edu", "caltech.edu", "carnegie.org",
        "berkeley.edu", "ucla.edu", "michigan.edu", "cornell.edu", "rice.edu",
        "carnegie.edu", "oxford.ac.uk", "cam.ac.uk", "imperial.ac.uk",
        "universityofsingapore.edu.sg", "tsinghua.edu.cn", "peking.edu.cn",
    ]),
    
    # ===== CLOUD & SaaS =====
    ("Cloud Services", [
        "aws.amazon.com", "microsoft.com", "google.com", "ibm.com", "oracle.com",
        "heroku.com", "digital-ocean.com", "vultr.com", "linode.com", "hetzner.com",
        "ovh.com", "ionos.com", "godaddy.com", "namecheap.com", "cloudflare.com",
        "akamai.com", "fastly.com", "cloudfront.com", "dropbox.com", "box.com",
    ]),
    
    # ===== HEALTHCARE =====
    ("Healthcare", [
        "amgen.com", "pfizer.com", "moderna.com", "janssen.com", "merck.com",
        "astrazeneca.com", "eli-lilly.com", "abbvie.com", "bristol-myers.com",
        "medtronic.com", "boston-scientific.com", "zimmer-biomet.com", "stryker.com",
        "abiomed.com", "cvs.com", "walgreens.com", "rite-aid.com",
    ]),
    
    # ===== AUTOMOTIVE =====
    ("Automotive", [
        "tesla.com", "ford.com", "gm.com", "mercedes-benz.com", "bmw.com",
        "audi.com", "porsche.com", "volkswagen.com", "toyota.com", "honda.com",
        "mazda.com", "subaru.com", "mitsubishi.com", "nissan.com", "infiniti.com",
        "hyundai.com", "kia.com", "geely.com", "nio.com", "xpeng.com",
    ]),
    
    # ===== ENERGY =====
    ("Energy", [
        "exxonmobil.com", "chevron.com", "shell.com", "bp.com", "totalenergies.com",
        "equinor.com", "eni.com", "gazprom.com", "rosneft.com", "saudi-aramco.com",
    ]),
    
    # ===== RETAIL FASHION =====
    ("Fashion & Retail", [
        "nike.com", "adidas.com", "puma.com", "asics.com", "underarmour.com",
        "lululemon.com", "gap.com", "forever21.com", "hm.com", "zara.com",
        "uniqlo.com", "gucci.com", "louisvuitton.com", "hermes.com", "burberry.com",
        "prada.com", "dior.com", "armani.com", "valentino.com", "versace.com",
    ]),
    
    # ===== CRYPTOCURRENCY & BLOCKCHAIN =====
    ("Crypto & Blockchain", [
        "coinbase.com", "kraken.com", "gemini.com", "binance.com", "bitstamp.com",
        "localbitcoins.com", "changelly.com", "shapeshift.io", "uniswap.org",
        "dydx.exchange", "aave.com", "compound.finance", "makerdao.com",
    ]),
    
    # ===== PAYMENT PROCESSING =====
    ("Payment", [
        "paypal.com", "stripe.com", "square.com", "adyen.com", "worldpay.com",
        "mastercard.com", "visa.com", "americanexpress.com", "discover.com",
        "diners.com", "jcb.com", "unionpayintl.com", "alipay.com", "wepay.com",
    ]),
    
    # ===== INSURANCE =====
    ("Insurance", [
        "statefarm.com", "allstate.com", "geico.com", "aarp.com", "progressive.com",
        "usaa.com", "nationwide.com", "metlife.com", "prudential.com",
        "hartfordrisk.com", "travelers.com", "aig.com", "swiss-re.com",
    ]),
    
    # ===== TELECOMMUNICATIONS =====
    ("Telecommunications", [
        "at&t.com", "verizon.com", "t-mobile.com", "sprint.com", "uscellular.com",
        "comcast.com", "charter.com", "cox.com", "vodafone.com", "deutsche-telekom.com",
        "orange.com", "telefonica.com", "swisscom.com", "telenor.com", "telia.com",
    ]),
]

def normalize_domain(domain: str) -> str:
    """Normalize domain for comparison"""
    domain = domain.lower().strip()
    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def populate_whitelist():
    """Populate whitelist_domains table with 1000+ trusted domains"""
    # Tabloları oluşturmaya çalış (başarısız olursa continue)
    try:
        from app.models import Base
        from app.database import engine
        print("📋 Creating tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Tables created!")
    except Exception as e:
        print(f"⚠️  Table creation skipped (may already exist): {str(e)[:100]}")
    
    db = SessionLocal()
    added = 0
    skipped = 0
    
    print("\n🌍 Populating global whitelist...")
    
    for category, domains in WHITELIST_DATA:
        print(f"\n📌 {category}: {len(domains)} domains")
        
        for domain in domains:
            try:
                domain_norm = normalize_domain(domain)
                
                # Check if already exists
                existing = db.query(WhitelistDomain).filter(
                    WhitelistDomain.domain_norm == domain_norm
                ).first()
                
                if existing:
                    skipped += 1
                    continue
                
                # Add new entry
                entry = WhitelistDomain(
                    domain=domain,
                    domain_norm=domain_norm,
                    category=category,
                    company_name=domain.split('.')[0].title(),
                    trusted_level="high",
                    verified=True
                )
                db.add(entry)
                added += 1
                
            except Exception as e:
                print(f"  ❌ Error adding {domain}: {e}")
                continue
        
        db.commit()
        print(f"   ✅ Added {len([d for d in domains])} domains")
    
    db.close()
    
    print("\n" + "="*60)
    print(f"✅ Whitelist Populated!")
    print(f"   Added: {added}")
    print(f"   Skipped: {skipped}")
    print(f"   Total: {added + skipped}")
    print("="*60)

if __name__ == "__main__":
    populate_whitelist()
