import re
import json
import os
import ssl
import socket
import requests
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.models import PhishingURL
from datetime import datetime

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
    "tiktok.com",
    "snapchat.com",
    "pinterest.com",
    "reddit.com",
    "tumblr.com",
    "discord.com", "discord.gg",
    "telegram.org", "t.me", "web.telegram.org",
    "whatsapp.com", "web.whatsapp.com",
    "signal.org",
    "twitch.tv",

    # ===== GLOBAL — E-TİCARET & FİNANS =====
    "amazon.com", "amazon.com.tr", "amazon.co.uk", "amazon.de",
    "ebay.com",
    "aliexpress.com", "alibaba.com",
    "etsy.com", "shopify.com",
    "paypal.com",
    "stripe.com",
    "wise.com", "transferwise.com",
    "revolut.com",
    "binance.com", "coinbase.com",
    "blockchain.com",

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

def check_ssl_certificate(domain):
    """SSL sertifikasını kontrol eder ve bilgileri döndürür."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
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
        resp = requests.get(url, timeout=5, allow_redirects=True)
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
    input_url = input_url.strip().lower()

    if not input_url.startswith(("http://", "https://")):
        check_url = "https://" + input_url
    else:
        check_url = input_url

    parsed = urlparse(check_url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace("www.", "")

    raw_domain = input_url.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]

    # ---------------------------------------------------------
    # 1. KATMAN: WHITELIST (BEYAZ LİSTE)
    # ---------------------------------------------------------
    is_safe = False

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

    if is_safe:
        return {
            "url": input_url, "score": 100, "risk_level": "✅ Güvenli (Doğrulanmış)",
            "details": [
                "Güvenilir Siteler Listesinde (Whitelist) mevcut.",
                "Resmi ve doğrulanmış kurum/site."
            ],
            "sources": [{"name": "Whitelist", "status": "Temiz ✅"}]
        }

    # ---------------------------------------------------------
    # 2. KATMAN: INTERNAL DB (VERİTABANI)
    # ---------------------------------------------------------
    if db:
        match = db.query(PhishingURL).filter(PhishingURL.url == check_url).first()
        if not match:
            match = db.query(PhishingURL).filter(PhishingURL.url == input_url).first()
        if not match and len(raw_domain) > 6:
            potential = db.query(PhishingURL).filter(
                PhishingURL.url.contains(raw_domain)
            ).limit(5).all()
            for pm in potential:
                pm_domain = pm.url.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]
                if pm_domain == raw_domain:
                    match = pm
                    break

        if match:
            return {
                "url": input_url, "score": 0,
                "risk_level": "🚨 ÇOK TEHLİKELİ (DB Kayıtlı)",
                "details": [
                    f"Tehlikeli site veritabanında tespit edildi! (ID: {match.phish_id})",
                    f"Hedef: {match.target}",
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
    http_status = 0
    try:
        response = requests.get(check_url, timeout=5, allow_redirects=True)
        http_status = response.status_code
        if response.status_code < 400:
            site_is_up = True
    except Exception:
        site_is_up = False

    if not site_is_up:
        return {
            "url": input_url, "score": 0,
            "risk_level": "❌ Siteye Ulaşılamıyor",
            "details": [
                "Böyle bir site bulunamadı veya sunucusu kapalı.",
                f"HTTP Durum Kodu: {http_status or 'Bağlantı hatası'}"
            ],
            "sources": [{"name": "Ping", "status": "Başarısız ❌"}]
        }

    # ---------------------------------------------------------
    # 5. KATMAN: ÇOKLU ANALİZ
    # ---------------------------------------------------------
    score = 100
    risks = []
    sources = []

    # --- 5a. HTTPS Kontrolü ---
    if check_url.startswith("http://"):
        score -= 25
        risks.append("❌ HTTPS yok — güvensiz (HTTP) bağlantı.")

    # --- 5b. SSL Sertifika Kontrolü ---
    ssl_info = check_ssl_certificate(domain)
    if ssl_info["valid"]:
        if ssl_info["expired"]:
            score -= 30
            risks.append(f"❌ SSL sertifikası süresi dolmuş!")
        elif ssl_info["days_left"] < 30:
            score -= 10
            risks.append(f"⚠️ SSL sertifikası {ssl_info['days_left']} gün içinde dolacak.")
        else:
            risks.append(f"✅ SSL geçerli — Veren: {ssl_info['issuer']} ({ssl_info['days_left']} gün kaldı)")
        sources.append({"name": "SSL Analiz", "status": "Tamamlandı"})
    else:
        score -= 20
        risks.append("⚠️ SSL sertifikası doğrulanamadı.")

    # --- 5c. Yönlendirme Zinciri ---
    redirect_info = check_redirect_chain(check_url)
    if redirect_info["suspicious"]:
        score -= 20
        risks.append(f"⚠️ Çok fazla yönlendirme ({redirect_info['redirect_count']} adet).")
    if redirect_info["final_url"] != check_url and redirect_info["redirect_count"] > 0:
        final_domain = urlparse(redirect_info["final_url"]).netloc.replace("www.", "")
        if final_domain != domain:
            score -= 15
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
            score -= 15
            risks.append(f"⚠️ Standart dışı port kullanılıyor: {port}")

    # --- 5f. URL Uzunluk Kontrolü ---
    if len(input_url) > 100:
        score -= 15
        risks.append("⚠️ URL aşırı uzun (phishing göstergesi).")
    elif len(input_url) > 75:
        score -= 8
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
    if found:
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
    # 6. SONUÇ
    # ---------------------------------------------------------
    final_score = max(0, min(100, score))

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

    return {
        "url": input_url,
        "score": final_score,
        "risk_level": risk_level,
        "details": risks,
        "sources": sources
    }
