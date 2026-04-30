import re
import json
import os
import ssl
import socket
import logging
import requests
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models import IndicatorOfCompromise, PhishingURL, WhitelistDomain
from datetime import datetime
from .url_normalize import normalize_url_record

# AI Modülleri - Yerel modüllerden import
from .ai_analyzer import analyze_page_content
from .ml_classifier import classify_url
from .threat_intel import check_ioc_threatfox, run_threat_intelligence

logger = logging.getLogger(__name__)

# =========================================================
# AYARLAR VE JSON YÜKLEME
# =========================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHTANK_PATH = os.path.join(BASE_DIR, "phishtank.json")

PHISHTANK_DB = set()
try:
    if os.path.exists(PHISHTANK_PATH):
        with open(PHISHTANK_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            for entry in data:
                u = entry['url']
                clean_u = u.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]
                PHISHTANK_DB.add(clean_u)
except Exception:
    pass


# =========================================================
# BEYAZ LİSTE (WHITELIST) — KAPSAMLI
# =========================================================
WHITELIST = {
    # ===== TÜRKİYE — DEVLET & KAMU =====
    "turkiye.gov.tr", "e-devlet.gov.tr", "edevlet.gov.tr",
    "tbmm.gov.tr", "tccb.gov.tr", "basbakanlik.gov.tr",
    "meb.gov.tr", "saglik.gov.tr", "csb.gov.tr",
    "icisleri.gov.tr", "adalet.gov.tr", "msb.gov.tr",
    "ticaret.gov.tr", "sanayi.gov.tr", "uab.gov.tr",
    "tarım.gov.tr", "tarim.gov.tr", "ailevecalisma.gov.tr",
    "kultur.gov.tr", "gençlik.gov.tr", "genclik.gov.tr",
    "mfa.gov.tr", "disisleri.gov.tr", "hazine.gov.tr",
    "hmb.gov.tr", "shgm.gov.tr", "jandarma.gov.tr",
    "egm.gov.tr", "emniyet.gov.tr", "nvi.gov.tr",
    "gib.gov.tr", "gelirler.gov.tr", "ivdb.gov.tr",
    "sgk.gov.tr", "iskur.gov.tr", "uyap.gov.tr",
    "yargitay.gov.tr", "danistay.gov.tr", "anayasa.gov.tr",
    "sayistay.gov.tr", "hsyk.gov.tr", "bddk.gov.tr",
    "spk.gov.tr", "tcmb.gov.tr", "tbb.org.tr",
    "tuik.gov.tr", "tubitak.gov.tr", "yok.gov.tr",
    "osym.gov.tr", "ösym.gov.tr", "aok.gov.tr",
    "afad.gov.tr", "kizilay.org.tr", "tse.org.tr",
    "epdk.gov.tr", "btk.gov.tr", "rtuk.gov.tr",
    "kvkk.gov.tr", "kgm.gov.tr", "dhmi.gov.tr",
    "tcdd.gov.tr", "ptt.gov.tr", "otogar.gov.tr",
    "meteoroloji.gov.tr", "mgm.gov.tr",
    "enabiz.gov.tr", "hayatevesigar.gov.tr",
    "turksat.com.tr", "trt.net.tr", "aa.com.tr",

    # ===== TÜRKİYE — BANKALAR =====
    "ziraatbank.com.tr", "ziraat.com.tr",
    "isbank.com.tr", "isbank.com",
    "garantibbva.com.tr", "garanti.com.tr",
    "akbank.com", "akbank.com.tr",
    "yapikredi.com.tr", "ykb.com",
    "halkbank.com.tr", "halkbankasi.com.tr",
    "vakifbank.com.tr", "vakifkatilim.com.tr",
    "qnbfinansbank.com", "finansbank.com.tr",
    "denizbank.com", "denizbank.com.tr",
    "teb.com.tr",
    "ingbank.com.tr", "ing.com.tr",
    "hsbc.com.tr",
    "sekerbank.com.tr",
    "anadolubank.com.tr",
    "alternatifbank.com.tr",
    "fibabanka.com.tr",
    "odeabank.com.tr",
    "kuveytturk.com.tr",
    "albaraka.com.tr",
    "turkiyefinans.com.tr",
    "ziraatkatilim.com.tr",
    "emlakkatilim.com.tr",
    "icbc.com.tr",
    "burgan.com.tr",
    "pfrbank.com.tr",
    "mufgbank.com.tr",
    "aktivbank.com.tr",
    "takasbank.com.tr",
    "kalkinma.com.tr",
    "exim.gov.tr", "eximbank.gov.tr",
    "ilbank.gov.tr",
    "tbb.org.tr", "turkiyebankalari.com.tr",  # Birlik sitesi
    "ziraat-online.com.tr", "isbank-online.com.tr",  # Online bankacılık
    "garanti-online.com.tr", "akbank-online.com.tr",

    # ===== TÜRKİYE — TELEKOM & İNTERNET =====
    "turkcell.com.tr", "turkcell.com",
    "vodafone.com.tr",
    "turktelekom.com.tr", "ttnet.com.tr",
    "superonline.net",
    "kablonet.com.tr",
    "millenicom.com.tr",
    "turknet.com.tr",
    "d-smart.com.tr",
    "digiturk.com.tr", "bein.com.tr", "beinsports.com.tr",
    "tivibu.com.tr",

    # ===== TÜRKİYE — E-TİCARET & MARKETLER =====
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "gittigidiyor.com",
    "sahibinden.com",
    "letgo.com",
    "dolap.com",
    "ciceksepeti.com",
    "yemeksepeti.com", "yemeksepeti.com.tr",
    "getir.com",
    "migros.com.tr", "sanalmarket.com.tr",
    "a101.com.tr",
    "bim.com.tr",
    "sok.com.tr",
    "carrefoursa.com",
    "teknosa.com",
    "mediamarkt.com.tr",
    "vatanbilgisayar.com",
    "morhipo.com",
    "boyner.com.tr",
    "lcwaikiki.com",
    "defacto.com.tr",
    "koton.com",
    "mavi.com",
    "tommylife.com.tr",
    "mutluisverisepeti.com",
    "bestlove.com.tr",
    "pttavm.com",
    "emag.com.tr",

    # ===== TÜRKİYE — HAVAYOLU & ULAŞIM =====
    "turkishairlines.com", "thy.com",
    "pegasus.com.tr", "flypgs.com",
    "anadolujet.com",
    "sunexpress.com",
    "enuygun.com",
    "obilet.com",
    "biletall.com",
    "biletix.com",

    # ===== TÜRKİYE — MEDYA & HABER =====
    "hurriyet.com.tr",
    "milliyet.com.tr",
    "sabah.com.tr",
    "sozcu.com.tr",
    "haberturk.com",
    "ntv.com.tr",
    "cnnturk.com",
    "bbc.com",
    "cumhuriyet.com.tr",
    "t24.com.tr",
    "diken.com.tr",
    "medyascope.tv",
    "gazeteduvar.com.tr",
    "birgun.net",

    # ===== TÜRKİYE — ÜNİVERSİTELER (Popüler) =====
    "itu.edu.tr", "boun.edu.tr", "metu.edu.tr", "odtu.edu.tr",
    "hacettepe.edu.tr", "ankara.edu.tr", "bilkent.edu.tr",
    "sabanciuniv.edu", "ku.edu.tr",
    "yildiz.edu.tr", "gazi.edu.tr", "deu.edu.tr",
    "ege.edu.tr", "uludag.edu.tr", "erciyes.edu.tr",
    "atauni.edu.tr", "selcuk.edu.tr", "akdeniz.edu.tr",
    "cu.edu.tr", "firat.edu.tr", "ktu.edu.tr",
    "iuc.edu.tr", "istanbul.edu.tr", "medipol.edu.tr",
    "ozyegin.edu.tr", "isikun.edu.tr", "yeditepe.edu.tr",

    # ===== GLOBAL — BÜYÜK TEKNOLOJİ =====
    "google.com", "google.com.tr",
    "youtube.com",
    "gmail.com", "mail.google.com",
    "drive.google.com", "docs.google.com", "maps.google.com",
    "play.google.com", "cloud.google.com",
    "android.com",
    "apple.com", "icloud.com", "itunes.apple.com",
    "microsoft.com", "office.com", "office365.com",
    "live.com", "outlook.com", "outlook.live.com",
    "hotmail.com", "msn.com",
    "bing.com",
    "azure.com", "azure.microsoft.com",
    "windows.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com",
    "mozilla.org", "firefox.com",
    "opera.com", "brave.com",
    "oracle.com", "ibm.com",
    "salesforce.com", "sap.com",
    "adobe.com", "creativecloud.com",
    "atlassian.com", "jira.com",
    "slack.com", "zoom.us", "zoom.com",
    "teams.microsoft.com", "skype.com",
    "notion.so", "notion.com",
    "figma.com", "canva.com",
    "vercel.com", "netlify.com",
    "heroku.com", "digitalocean.com",
    "cloudflare.com", "fastly.com",
    "aws.amazon.com", "console.aws.amazon.com",

    # ===== GLOBAL — SOSYAL MEDYA =====
    "facebook.com", "fb.com", "messenger.com",
    "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "tiktok.com", "douyin.com",  # TikTok China
    "snapchat.com",
    "pinterest.com",
    "reddit.com",
    "tumblr.com",
    "discord.com", "discord.gg",
    "telegram.org", "t.me", "web.telegram.org",
    "whatsapp.com", "web.whatsapp.com",
    "signal.org",
    "twitch.tv", "twitch.com",
    "youtube.com",
    "viber.com",
    "nextdoor.com",

    # ===== GLOBAL — E-TİCARET & FİNANS =====
    "amazon.com", "amazon.com.tr", "amazon.co.uk", "amazon.de",
    "amazon.fr", "amazon.it", "amazon.es",
    "ebay.com",
    "aliexpress.com", "alibaba.com",
    "etsy.com", "shopify.com",
    "paypal.com",
    "stripe.com",
    "wise.com", "transferwise.com",
    "revolut.com",
    "binance.com", "coinbase.com",
    "blockchain.com",
    "kraken.com",
    "gemini.com",
    "huobi.com",
    "okx.com",

    # ===== GLOBAL — EĞLENCE & İÇERİK =====
    "netflix.com",
    "spotify.com",
    "disneyplus.com",
    "hbo.com", "hbomax.com",
    "primevideo.com",
    "twitch.tv",
    "soundcloud.com",
    "deezer.com",
    "imdb.com",
    "rottentomatoes.com",

    # ===== GLOBAL — HABER & BİLGİ =====
    "wikipedia.org", "en.wikipedia.org", "tr.wikipedia.org",
    "bbc.co.uk", "bbc.com",
    "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com",
    "washingtonpost.com", "forbes.com",
    "bloomberg.com", "ft.com",
    "medium.com", "substack.com",
    "quora.com",

    # ===== GLOBAL — E-POSTA & ÜRETKENLİK =====
    "protonmail.com", "proton.me",
    "tutanota.com",
    "yahoo.com", "mail.yahoo.com",
    "yandex.com", "yandex.com.tr",
    "dropbox.com", "box.com",
    "evernote.com",
    "trello.com",
    "asana.com",

    # ===== GLOBAL — GÜVENLİK =====
    "virustotal.com",
    "malwarebytes.com",
    "kaspersky.com",
    "norton.com", "nortonlifelock.com",
    "avast.com", "avg.com",
    "mcafee.com",
    "eset.com",
    "bitdefender.com",
    "crowdstrike.com",
    "sophos.com",
    "paloaltonetworks.com",
    "fortinet.com",
    "trendmicro.com",
}

# Whitelist'ten kısa isim seti (uzantısız) — "google", "youtube" vb.
WHITELIST_SHORT = set()
for d in WHITELIST:
    name = d.split(".")[0]
    if len(name) > 3:  # Çok kısa olanları alma (n11, fb vb. hariç)
        WHITELIST_SHORT.add(name)
# Kısa olanları da ekle
WHITELIST_SHORT.update({"n11", "fb", "x", "bim", "sok", "ing", "teb"})


# =========================================================
# YARDIMCI FONKSİYONLAR
# =========================================================

import sqlite3

WHITELIST_DB_PATH = os.path.join(os.path.dirname(__file__), '../../data/whitelist.db')

def check_whitelist(domain: str, db: Session = None) -> dict:
    """
    Global whitelist'te domain'i kontrol et (SQLite)
    Güvenilir şirket domain'leri phishing işaretlemez
    """
    try:
        if not os.path.exists(WHITELIST_DB_PATH):
            return {"whitelisted": False, "category": None, "trusted_level": None}
        
        # Normalize domain
        domain_norm = domain.lower().strip()
        if domain_norm.startswith("www."):
            domain_norm = domain_norm[4:]
        
        conn = sqlite3.connect(WHITELIST_DB_PATH)
        cursor = conn.cursor()
        
        # Exact match ara
        cursor.execute("""
            SELECT id, category, trusted_level, company_name 
            FROM whitelist_domains 
            WHERE domain_norm = ?
        """, (domain_norm,))
        result = cursor.fetchone()
        
        if result:
            conn.close()
            return {
                "whitelisted": True,
                "category": result[1],
                "trusted_level": result[2],
                "company_name": result[3]
            }
        
        # Subdomain check
        for part_count in range(1, len(domain_norm.split('.'))):
            partial_domain = '.'.join(domain_norm.split('.')[-part_count-1:])
            cursor.execute("""
                SELECT id, category, trusted_level, company_name 
                FROM whitelist_domains 
                WHERE domain_norm = ?
            """, (partial_domain,))
            result = cursor.fetchone()
            
            if result:
                conn.close()
                return {
                    "whitelisted": True,
                    "category": result[1],
                    "trusted_level": result[2],
                    "company_name": result[3],
                    "subdomain": True
                }
        
        conn.close()
        return {"whitelisted": False, "category": None, "trusted_level": None}
        
    except Exception as e:
        logger.error(f"Whitelist check error for {domain}: {e}")
        return {"whitelisted": False, "category": None, "trusted_level": None}

def check_ssl_certificate(domain):
    """SSL sertifikasını kontrol eder ve bilgileri döndürür."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, 443))
            cert = s.getpeercert()

            # Sertifika geçerlilik tarihi
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            # Sertifika veren kurum
            issuer = dict(x[0] for x in cert.get('issuer', []))
            issuer_org = issuer.get('organizationName', 'Bilinmiyor')

            return {
                "valid": True,
                "issuer": issuer_org,
                "days_left": days_left,
                "expired": days_left < 0
            }
    except Exception:
        return {"valid": False, "issuer": None, "days_left": 0, "expired": True}


def check_redirect_chain(url):
    """URL yönlendirme zincirini kontrol eder."""
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
        chain = resp.history
        final_url = resp.url
        return {
            "redirect_count": len(chain),
            "final_url": final_url,
            "suspicious": len(chain) > 3
        }
    except Exception:
        return {"redirect_count": 0, "final_url": url, "suspicious": False}


def analyze_domain_structure(domain, raw_input):
    """Domain yapısını analiz eder (typosquatting, homograph vb.)."""
    findings = []
    score_penalty = 0

    # 1. Aşırı subdomain kullanımı
    parts = domain.split(".")
    if len(parts) > 4:
        findings.append("Çok fazla subdomain kullanılıyor.")
        score_penalty += 15

    # 2. Bilinen marka taklit kontrolü (typosquatting)
    brand_keywords = [
        "google", "youtube", "facebook", "instagram", "twitter",
        "apple", "microsoft", "amazon", "netflix", "paypal",
        "whatsapp", "telegram", "linkedin", "github",
        "ziraat", "garanti", "isbank", "akbank", "yapikredi",
        "halkbank", "vakifbank", "turkcell", "vodafone",
        "turktelekom", "trendyol", "hepsiburada", "sahibinden",
        "edevlet", "turkiye", "sgk", "ptt", "thy",
    ]
    for brand in brand_keywords:
        if brand in domain:
            # Bu brand'in resmi sitesi mi?
            is_official = False
            for wl in WHITELIST:
                if brand in wl and (domain == wl or domain.endswith("." + wl)):
                    is_official = True
                    break
            if not is_official:
                findings.append(f"'{brand}' markası taklit ediliyor olabilir!")
                score_penalty += 30
                break

    # 3. Şüpheli TLD kontrolü
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top",
                       ".xyz", ".click", ".link", ".info", ".work", ".rest",
                       ".icu", ".cam", ".quest", ".surf", ".monster"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            findings.append(f"Şüpheli uzantı: {tld}")
            score_penalty += 15
            break

    # 4. Rakam/tire yoğunluğu
    domain_name = parts[0] if parts else domain
    digit_ratio = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
    dash_count = domain_name.count("-")

    if digit_ratio > 0.4:
        findings.append("Domain adında çok fazla rakam var.")
        score_penalty += 10
    if dash_count > 2:
        findings.append("Domain adında çok fazla tire (-) var.")
        score_penalty += 10

    # 5. Çok uzun domain adı
    if len(domain_name) > 30:
        findings.append("Domain adı anormal şekilde uzun.")
        score_penalty += 10

    # 6. Homograph attack (karışık karakter) — basit kontrol
    non_ascii = sum(1 for c in domain if ord(c) > 127)
    if non_ascii > 0:
        findings.append("Domain'de ASCII dışı karakterler var (Homograph saldırısı olabilir).")
        score_penalty += 25

    return findings, score_penalty


# =========================================================
# ANA ANALİZ FONKSİYONU
# =========================================================
def calculate_safety_score(input_url, db: Session = None):
    # 0. URL DÜZENLEME
    input_url = (input_url or "").strip().lower()
    if not input_url:
        raise ValueError("URL boş olamaz")

    if not input_url.startswith(("http://", "https://")):
        input_url = "https://" + input_url

    normalized_input = normalize_url_record(input_url)
    check_url = normalized_input.get("canonical_url", input_url)
    domain_norm = normalized_input.get("domain_norm")

    parsed = urlparse(check_url)
    domain = (parsed.netloc or parsed.path or "").replace("www.", "")
    raw_domain = domain_norm or domain

    # ---------------------------------------------------------
    # 1. KATMAN: GLOBAL WHITELIST (DATABASE VE BUILTIN)
    # ---------------------------------------------------------
    is_safe = False
    whitelist_info = None

    # Önce database'den kontrol et (global whitelist)
    if db:
        whitelist_info = check_whitelist(domain, db)
        if whitelist_info.get("whitelisted"):
            is_safe = True

    # Eğer database'de yoksa, builtin WHITELIST'i kontrol et
    if not is_safe:
        # Tam eşleşme
        if raw_domain in WHITELIST or domain in WHITELIST:
            is_safe = True

        # Alt domain kontrolü (mail.google.com → google.com whitelist'te)
        if not is_safe:
            for wl_domain in WHITELIST:
                if domain == wl_domain or domain.endswith("." + wl_domain):
                    is_safe = True
                    break

        # Uzantısız kısa isim kontrolü (kullanıcı sadece "google" yazdıysa)
        if not is_safe and "." not in raw_domain and raw_domain in WHITELIST_SHORT:
            is_safe = True

    # Whitelist check - ama hemen dönme, full tarama yap
    whitelist_info = None
    is_whitelisted = False
    if is_safe:
        is_whitelisted = True
        whitelist_info = whitelist_info or {"category": "Verified", "company_name": "Trusted Site"}

    # ---------------------------------------------------------
    # 2. KATMAN: INTERNAL DB (VERİTABANI) — hash / tam URL / domain (indeksli)
    # ---------------------------------------------------------
    # Initialize score, risks, sources early for threat_intelligence
    score = 100
    risks = []
    sources = []
    
    domain_match = None
    if db:
        exact_match = None
        normalized_lookup = normalize_url_record(check_url)
        canon = normalized_lookup.get("canonical_url")
        url_hash = normalized_lookup.get("url_hash")
        domain_norm = normalized_lookup.get("domain_norm")
        if url_hash:
            exact_match = db.query(PhishingURL).filter(PhishingURL.url_hash == url_hash).first()
        if exact_match is None and canon:
            exact_match = db.query(PhishingURL).filter(PhishingURL.url == canon).first()
        if exact_match is None:
            exact_match = db.query(PhishingURL).filter(PhishingURL.url == check_url).first()
        if exact_match is None:
            exact_match = db.query(PhishingURL).filter(PhishingURL.url == input_url).first()
        if exact_match is None and domain_norm and len(domain_norm) > 3:
            domain_match = (
                db.query(PhishingURL)
                .filter(PhishingURL.domain_norm == domain_norm)
                .first()
            )

        if exact_match:
            return {
                "url": input_url, "score": 0,
                "risk_level": "🚨 ÇOK TEHLİKELİ (DB Kayıtlı)",
                "details": [
                    f"Tehlikeli site veritabanında tespit edildi! (ID: {exact_match.phish_id})",
                    f"Hedef: {exact_match.target}",
                    "Bu siteye kesinlikle bilgi girmeyin!"
                ],
                "sources": [{"name": "Internal DB", "status": "TEHDİT 🚨"}]
            }

    # ---------------------------------------------------------
    # 3. KATMAN: PHISHTANK (JSON)
    # ---------------------------------------------------------
    if domain in PHISHTANK_DB or raw_domain in PHISHTANK_DB:
        return {
            "url": input_url, "score": 0,
            "risk_level": "🚨 ÇOK TEHLİKELİ (PhishTank)",
            "details": [
                "Bu site global kara listede (PhishTank) mevcut!",
                "Kesinlikle veri girmeyin, siteyi terk edin."
            ],
            "sources": [{"name": "PhishTank", "status": "TEHDİT 🚨"}]
        }

    # ---------------------------------------------------------
    # 4. KATMAN: CANLILIK TESTİ
    # ---------------------------------------------------------
    site_is_up = False
    restricted_access = False
    http_status = 0
    transport_error = None
    page_content = None
    request_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    candidates = [check_url]
    # Varsayılan https denemesi başarısız olursa http fallback dene.
    if check_url.startswith("https://"):
        candidates.append("http://" + check_url.replace("https://", "", 1))

    response = None
    for candidate_url in candidates:
        try:
            response = requests.get(candidate_url, timeout=8, allow_redirects=True, headers=request_headers)
            check_url = candidate_url
            http_status = response.status_code
            site_is_up = True
            break
        except Exception as e:
            transport_error = str(e)

    if site_is_up and response is not None:
        if response.status_code in (401, 403, 405, 406, 429):
            restricted_access = True
        # Sayfa içeriğini AI analizi için sadece başarılı yanıtlarda kullan.
        if response.status_code < 400:
            try:
                response.encoding = response.apparent_encoding or 'utf-8'
                page_content = response.text[:500_000]
            except Exception:
                page_content = None

    # ---------------------------------------------------------
# 8. KATMAN: HARİCİ TEHDİT İSTİHBARATI (Local - site reachability'den önce)
# ---------------------------------------------------------
    threat_result = None
    try:
        ssl_meta = check_ssl_certificate(domain.split(":")[0]) if domain else {"valid": False, "expired": True}
        redirect_chain = []
        if response is not None and getattr(response, "history", None):
            for hop in response.history:
                redirect_chain.append(
                    {
                        "status_code": int(getattr(hop, "status_code", 0) or 0),
                        "url": str(getattr(hop, "url", "")),
                    }
                )

        http_meta = {
            "status_code": http_status,
            "restricted_access": restricted_access,
            "final_url": str(getattr(response, "url", check_url) if response is not None else check_url),
            "redirect_chain": redirect_chain,
            "ssl": {
                "valid": bool(ssl_meta.get("valid", False)),
                "expired": bool(ssl_meta.get("expired", True)),
                "issuer": ssl_meta.get("issuer"),
                "days_left": ssl_meta.get("days_left"),
            },
        }
        threat_result = run_threat_intelligence(
            check_url,
            http_meta=http_meta,
            page_text=(page_content or "")[:3000],
            is_whitelisted=is_whitelisted,
        )
        if threat_result["total_penalty"] > 0:
            score -= threat_result["total_penalty"]
            risks.extend(threat_result["findings"])
        else:
            # VirusTotal temiz (penalty 0) + SSL geçerli = BONUS +25
            vt_status = threat_result.get("virustotal") or {}
            if vt_status.get("available") and vt_status.get("malicious", 0) == 0 and vt_status.get("suspicious", 0) == 0:
                ssl_status = check_ssl_certificate(domain.split(":")[0])
                if ssl_status["valid"] and not ssl_status["expired"]:
                    score += 25  # VirusTotal + SSL bonus
                    risks.append("✅ VirusTotal temiz + SSL geçerli = Yüksek güvenlik")
        sources.extend(threat_result.get("sources", []))
    except Exception as e:
        logger.error(f"Threat Intelligence hatası: {e}")

    if not site_is_up:
        return {
            "url": input_url, "score": score,
            "risk_level": "❌ Siteye Ulaşılamıyor",
            "details": [
                "Böyle bir site bulunamadı veya sunucusu kapalı.",
                f"HTTP Durum Kodu: {http_status or 'Bağlantı hatası'}",
                f"Ağ hatası: {transport_error or 'bilinmiyor'}"
            ] + risks,
            "sources": sources + [{"name": "HTTP Erişim", "status": "Başarısız ❌"}],
            "threat_intel": threat_result,
        }

    # ---------------------------------------------------------
    # 5. KATMAN: ÇOKLU ANALİZ
    # ---------------------------------------------------------
    if restricted_access:
        score -= 5
        risks.append(f"⚠️ Site erişimi kısıtlı görünüyor (HTTP {http_status}). Anti-bot/WAF olabilir.")
        sources.append({"name": "HTTP Erişim", "status": f"Kısıtlı (HTTP {http_status})"})
    else:
        sources.append({"name": "HTTP Erişim", "status": f"Ulaşılabilir (HTTP {http_status})"})
        if http_status >= 500:
            score -= 10
            risks.append(f"⚠️ Sunucu hata kodu döndürüyor (HTTP {http_status}).")
        elif http_status == 404:
            score -= 3
            risks.append("⚠️ URL yolu bulunamadı (HTTP 404), ancak alan adı erişilebilir.")
    
    # Whitelist flag ekle
    if is_whitelisted:
        sources.append({"name": "Whitelist", "status": f"✅ {whitelist_info.get('company_name', 'Verified')}"})

    # Domain seviyesinde tehdit kaydı, exact URL kadar kesin olmadığı için soft-penalty uygula.
    if domain_match and not is_whitelisted:
        score -= 20
        risks.append(
            f"⚠️ Bu domain altında daha önce phishing kaydı görülmüş: {domain_match.target or 'Unknown'}"
        )
        sources.append({"name": "Internal DB", "status": "Domain eşleşmesi (soft risk)"})

    # --- IOC DB + ThreatFox cross-check (domain + resolved IP) ---
    domain_lookup = domain.split(":")[0]
    resolved_ip = None
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", domain):
        resolved_ip = domain_lookup
    else:
        try:
            resolved_ip = socket.gethostbyname(domain_lookup)
        except Exception:
            resolved_ip = None

    local_ioc_hits = []
    if db:
        ioc_candidates = [domain_lookup]
        if resolved_ip:
            ioc_candidates.append(resolved_ip)
        local_ioc_hits = (
            db.query(IndicatorOfCompromise)
            .filter(
                or_(
                    IndicatorOfCompromise.status == "active",
                    IndicatorOfCompromise.status.is_(None),
                ),
                IndicatorOfCompromise.ioc_value.in_(ioc_candidates),
            )
            .all()
        )

    threatfox_hits = []
    for candidate in [domain_lookup, resolved_ip]:
        if not candidate:
            continue
        tf_result = check_ioc_threatfox(candidate, timeout=10)
        if tf_result.get("found"):
            threatfox_hits.append((candidate, tf_result))

    if (local_ioc_hits or threatfox_hits) and not is_whitelisted:
        score -= 30
        risks.append("🚨 IOC listesinde bulundu (local DB veya ThreatFox eşleşmesi).")
        if local_ioc_hits:
            first_local = local_ioc_hits[0]
            sources.append(
                {
                    "name": "IOC Local DB",
                    "status": f"Eşleşme: {first_local.ioc_type}:{first_local.ioc_value}",
                }
            )
        if threatfox_hits:
            first_tf = threatfox_hits[0]
            sources.append(
                {
                    "name": "ThreatFox",
                    "status": f"Eşleşme: {first_tf[0]} ({first_tf[1].get('threat_type', 'unknown')})",
                }
            )

    # --- 5a. HTTPS Kontrolü ---
    if check_url.startswith("http://"):
        score -= 25
        risks.append("❌ HTTPS yok — güvensiz (HTTP) bağlantı.")

    # --- 5c. Yönlendirme Zinciri ---
    redirect_info = check_redirect_chain(check_url)
    if redirect_info["suspicious"]:
        score -= 5  # Düşürüldü: 20 → 5
        risks.append(f"⚠️ Çok fazla yönlendirme ({redirect_info['redirect_count']} adet).")
    if redirect_info["final_url"] != check_url and redirect_info["redirect_count"] > 0:
        final_domain = urlparse(redirect_info["final_url"]).netloc.replace("www.", "")
        if final_domain != domain:
            score -= 3  # Düşürüldü: 15 → 3
            risks.append(f"⚠️ Farklı siteye yönleniyor: {final_domain}")
    sources.append({"name": "Redirect Analiz", "status": "Tamamlandı"})

    # --- 5d. IP Adresi Kontrolü ---
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
        score -= 35
        risks.append("❌ Domain yerine IP adresi kullanılıyor.")

    # --- 5e. Port Kontrolü ---
    if ":" in domain:
        port = domain.split(":")[-1]
        if port not in ["80", "443", "8080", "8443"]:
            score -= 5  # Düşürüldü: 15 → 5
            risks.append(f"⚠️ Standart dışı port kullanılıyor: {port}")

    # --- 5f. URL Uzunluk Kontrolü ---
    if len(input_url) > 100:
        score -= 5  # Düşürüldü: 15 → 5
        risks.append("⚠️ URL aşırı uzun (phishing göstergesi).")
    elif len(input_url) > 75:
        score -= 2  # Düşürüldü: 8 → 2
        risks.append("⚠️ URL normalden uzun.")

    # --- 5g. Şüpheli Kelime Kontrolü ---
    suspicious_words = [
        "login", "signin", "sign-in", "log-in",
        "giris", "giriş", "oturum",
        "verify", "verification", "dogrula", "doğrula", "onay",
        "bank", "banka", "hesap", "account",
        "update", "güncelle", "guncelle",
        "secure", "security", "güvenlik", "guvenlik",
        "confirm", "onayla",
        "password", "parola", "sifre", "şifre",
        "credit", "kredi", "kart", "card",
        "bonus", "ödül", "odul", "hediye", "prize", "winner",
        "suspend", "suspended", "locked", "kilitli",
        "expire", "urgent", "acil", "hemen",
        "free", "bedava", "ücretsiz", "ucretsiz",
        "wallet", "cüzdan", "cuzdan",
        ".exe", ".zip", ".rar", ".scr", ".bat",
    ]
    found = [w for w in suspicious_words if w in input_url.lower()]
    if found and not is_whitelisted:
        penalty = min(30, len(found) * 8)
        score -= penalty
        risks.append(f"⚠️ Şüpheli kelimeler: {', '.join(found[:5])}")

    # --- 5h. @ ve çift // kontrolü (URL karıştırma) ---
    if "@" in input_url:
        score -= 25
        risks.append("❌ URL'de @ işareti var (adres gizleme tekniği).")
    if "//" in parsed.path:
        score -= 10
        risks.append("⚠️ URL'de çift // var (path karıştırma).")

    # --- 5i. Domain Yapı Analizi ---
    domain_findings, domain_penalty = analyze_domain_structure(domain, input_url)
    score -= domain_penalty
    risks.extend(domain_findings)

    # --- 5j. URL encoding kontrolü ---
    encoded_chars = input_url.count("%")
    if encoded_chars > 5:
        score -= 15
        risks.append(f"⚠️ URL'de çok fazla encoded karakter var ({encoded_chars} adet).")

    sources.append({"name": "Yapısal Analiz", "status": "Tamamlandı"})

    # ---------------------------------------------------------
    # 6. KATMAN: ML TABANLI URL SINIFLANDIRMA
    # ---------------------------------------------------------
    try:
        ml_result = classify_url(input_url)
        if ml_result["ml_penalty"] > 0:
            score -= ml_result["ml_penalty"]
            risks.extend(ml_result["ml_findings"])
        sources.append({"name": "ML Sınıflandırma", "status": f"{ml_result['ml_label']} ({ml_result['ml_score']}/100)"})
    except Exception as e:
        logger.error(f"ML Classifier hatası: {e}")
        ml_result = None

    # ---------------------------------------------------------
    # 7. KATMAN: AI İÇERİK ANALİZİ (NLP + Brand + Credential)
    # ---------------------------------------------------------
    ai_result = None
    try:
        if page_content:
            ai_result = analyze_page_content(page_content, check_url)
            if ai_result["ai_score_penalty"] > 0 and not is_whitelisted:
                score -= ai_result["ai_score_penalty"]
                risks.extend(ai_result["ai_findings"])
            sources.append({"name": "AI İçerik Analizi", "status": "Tamamlandı"})

            if ai_result.get("brand_impersonation") and not is_whitelisted:
                sources.append({"name": "Marka Taklidi", "status": f"⚠️ {ai_result['brand_impersonation'].upper()}"})
            if ai_result.get("credential_harvesting") and not is_whitelisted:
                sources.append({"name": "Credential Harvesting", "status": "🚨 Tespit Edildi"})
    except Exception as e:
        logger.error(f"AI Analyzer hatası: {e}")

    # ---------------------------------------------------------
    # 8. KATMAN: HARİCİ TEHDİT İSTİHBARATI (Local - already called before site reachability)
    # ---------------------------------------------------------
    # threat_intelligence already called before site reachability check

    # ---------------------------------------------------------
    # 9. SONUÇ
    # ---------------------------------------------------------
    final_score = max(0, min(100, score))
    if is_whitelisted:
        final_score = max(final_score, 95)
        risks.append("✅ Whitelist eşleşmesi nedeniyle skor güvenli seviyeye yükseltildi.")

    if final_score >= 80:
        risk_level = "✅ Güvenli"
    elif final_score >= 60:
        risk_level = "⚠️ Şüpheli"
    elif final_score >= 40:
        risk_level = "🟠 Riskli"
    else:
        risk_level = "🚨 Tehlikeli"

    if not risks:
        risks.append("✅ Herhangi bir risk faktörü tespit edilmedi.")

    result = {
        "url": input_url,
        "score": final_score,
        "risk_level": risk_level,
        "details": risks,
        "sources": sources,
        "threat_intel": threat_result,
    }

    # AI ek bilgileri (frontend için)
    if ai_result:
        result["ai_analysis"] = {
            "nlp_risk_score": ai_result.get("nlp_risk_score", 0),
            "brand_impersonation": ai_result.get("brand_impersonation"),
            "credential_harvesting": ai_result.get("credential_harvesting", False),
            "malicious_scripts": len(ai_result.get("malicious_scripts", [])),
            "content_anomalies": len(ai_result.get("content_anomalies", [])),
        }
    if ml_result:
        result["ml_analysis"] = {
            "ml_score": ml_result.get("ml_score", 0),
            "ml_label": ml_result.get("ml_label", ""),
            "triggered_features": len(ml_result.get("triggered_features", [])),
        }
    if threat_result:
        result["threat_intel"] = {
            "virustotal": threat_result.get("virustotal"),
            "screenshot_analysis": threat_result.get("screenshot_analysis"),
            "google_safe_browsing": threat_result.get("google_safe_browsing"),
            "abuseipdb": threat_result.get("abuseipdb"),
            "urlhaus": threat_result.get("urlhaus"),
            "spamhaus_domain": threat_result.get("spamhaus_domain"),
            "spamhaus_ip": threat_result.get("spamhaus_ip"),
            "threatfox": threat_result.get("threatfox"),
        }

    return result
