"""
AI-Powered Phishing Content Analyzer
=====================================
Check Point ve sektör standartlarına uygun AI tabanlı analiz modülü.
- NLP İçerik Analizi (sayfa metni üzerinden phishing tespiti)
- Marka Taklidi Tespiti (brand impersonation)
- Credential Harvesting Tespiti (form, şifre alanları)
- Zararlı JavaScript / Obfuscation Tespiti
- Sayfa Yapısal Anomali Analizi
"""

import re
import math
import logging
from urllib.parse import urlparse
from collections import Counter

logger = logging.getLogger(__name__)

# =========================================================
# 1. NLP PHİSHİNG İÇERİK ANALİZİ
# =========================================================

# Phishing e-posta/sayfa kalıpları — ağırlıklı kelime grupları
PHISHING_PATTERNS = {
    # --- Aciliyet & Korku ---
    "urgency": {
        "weight": 3,
        "patterns": [
            r"acil\w*", r"hemen\b", r"derhal\b", r"son\s*şans", r"son\s*sans",
            r"süre\s*dol", r"sure\s*dol", r"hesab\w*\s*kapat", r"hesab\w*\s*askı",
            r"urgent\w*", r"immediate\w*", r"act\s*now", r"expires?\s*(today|soon|now)",
            r"limited\s*time", r"last\s*chance", r"don'?t\s*miss", r"hurry",
            r"within\s*\d+\s*(hour|minute|day|saat|dakika|gün)",
            r"account\s*(will\s*be\s*)?(suspend|clos|lock|terminat|block)",
            r"hesab\w*\s*(kapat|dondur|engel|askı)",
        ]
    },
    # --- Doğrulama & Giriş İsteği ---
    "verification": {
        "weight": 4,
        "patterns": [
            r"verify\s*your\s*(account|identity|email|information)",
            r"doğrula\w*", r"dogrula\w*", r"kimli\w*\s*doğrula",
            r"confirm\s*your\s*(account|identity|details|password)",
            r"onayla\w*\s*(hesab|kimli|bilgi)",
            r"update\s*your\s*(account|payment|billing|information)",
            r"bilgilerinizi\s*güncelle", r"bilgilerinizi\s*guncelle",
            r"re-?enter\s*your\s*(password|credentials)",
            r"şifrenizi\s*(girin|güncelleyin|değiştirin|sıfırlayın)",
            r"sifrenizi\s*(girin|guncelleyin|degistirin|sifirlayin)",
        ]
    },
    # --- Ödül & Tuzak ---
    "reward_lure": {
        "weight": 3,
        "patterns": [
            r"congratulations", r"tebrikler", r"kazandınız", r"kazandiniz",
            r"you\s*(have\s*)?won", r"winner", r"prize", r"ödül\w*", r"odul\w*",
            r"free\s*(gift|iphone|samsung|money|bitcoin)",
            r"bedava\w*", r"ücretsiz\w*", r"ucretsiz\w*",
            r"hediye\s*(çek|kart|kazan)", r"hediye\s*(cek|kart|kazan)",
            r"claim\s*your\s*(reward|prize|gift)",
            r"bonus\w*", r"kampanya\w*\s*kazan",
        ]
    },
    # --- Tehdit & Ceza ---
    "threat": {
        "weight": 4,
        "patterns": [
            r"suspend\w*", r"terminat\w*", r"delet\w*\s*(your\s*)?account",
            r"unauthorized\s*(access|transaction|activity)",
            r"yetkisiz\s*(erişim|giriş|işlem)", r"yetkisiz\s*(erisim|giris|islem)",
            r"legal\s*action", r"yasal\s*işlem", r"yasal\s*islem",
            r"police|polis|savcılık|mahkeme",
            r"fraud\s*(alert|detected|warning)",
            r"dolandırıcılık\s*(tespit|uyarı)",
            r"your\s*account\s*(has\s*been|is)\s*(compromised|hacked|breached)",
            r"hesabınız\s*(ele\s*geçiril|hacklen|ihlal)",
        ]
    },
    # --- Finansal Bilgi Talebi ---
    "financial": {
        "weight": 5,
        "patterns": [
            r"credit\s*card\s*(number|detail|info)",
            r"kredi\s*kart\w*\s*(numara|bilgi)",
            r"bank\s*(account|detail|info|transfer)",
            r"banka\s*(hesap|bilgi|transfer)",
            r"social\s*security", r"tc\s*kimlik",
            r"cvv|cvc|güvenlik\s*kodu|guvenlik\s*kodu",
            r"expir\w*\s*date|son\s*kullanma",
            r"iban|swift|routing\s*number",
            r"payment\s*(detail|method|info)",
            r"ödeme\s*(bilgi|yöntem)", r"odeme\s*(bilgi|yontem)",
            r"bitcoin|crypto|wallet\s*address",
        ]
    },
}

# Bilinen marka imzaları — sayfa içeriğinde brand impersonation tespiti
BRAND_SIGNATURES = {
    "google": {
        "keywords": ["google", "gmail", "google drive", "g suite", "workspace"],
        "official_domains": ["google.com", "google.com.tr", "gmail.com", "googleapis.com"],
        "visual_cues": [r"accounts\.google\.com", r"myaccount\.google", r"sign\s*in\s*with\s*google"],
    },
    "microsoft": {
        "keywords": ["microsoft", "outlook", "office 365", "onedrive", "teams", "azure"],
        "official_domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "azure.com"],
        "visual_cues": [r"login\.microsoftonline", r"microsoft\s*account", r"sign\s*in\s*to\s*your\s*microsoft"],
    },
    "apple": {
        "keywords": ["apple", "icloud", "apple id", "itunes", "app store"],
        "official_domains": ["apple.com", "icloud.com"],
        "visual_cues": [r"appleid\.apple", r"apple\s*id", r"sign\s*in\s*with\s*apple"],
    },
    "facebook": {
        "keywords": ["facebook", "meta", "instagram", "whatsapp", "messenger"],
        "official_domains": ["facebook.com", "fb.com", "instagram.com", "meta.com"],
        "visual_cues": [r"log\s*in\s*to\s*facebook", r"facebook\.com/login"],
    },
    "amazon": {
        "keywords": ["amazon", "aws", "prime", "kindle"],
        "official_domains": ["amazon.com", "amazon.com.tr", "aws.amazon.com"],
        "visual_cues": [r"amazon\.com/ap/signin", r"sign\s*in\s*to\s*amazon"],
    },
    "paypal": {
        "keywords": ["paypal"],
        "official_domains": ["paypal.com"],
        "visual_cues": [r"paypal\.com/signin", r"log\s*in\s*to\s*paypal"],
    },
    "netflix": {
        "keywords": ["netflix"],
        "official_domains": ["netflix.com"],
        "visual_cues": [r"netflix\.com/login", r"sign\s*in\s*to\s*netflix"],
    },
    # Türk bankaları
    "ziraat": {
        "keywords": ["ziraat", "ziraatbank", "ziraat bankası"],
        "official_domains": ["ziraatbank.com.tr", "ziraat.com.tr"],
        "visual_cues": [r"ziraat\s*bank", r"ziraat\s*mobil", r"ziraat\s*internet"],
    },
    "garanti": {
        "keywords": ["garanti", "garantibbva", "garanti bankası"],
        "official_domains": ["garantibbva.com.tr", "garanti.com.tr"],
        "visual_cues": [r"garanti\s*bbva", r"garanti\s*mobil", r"garanti\s*internet"],
    },
    "isbank": {
        "keywords": ["işbank", "isbank", "iş bankası", "is bankasi"],
        "official_domains": ["isbank.com.tr", "isbank.com"],
        "visual_cues": [r"isbank|iş\s*bank", r"işbank\s*mobil"],
    },
    "yapikredi": {
        "keywords": ["yapı kredi", "yapi kredi", "yapikredi", "ykb"],
        "official_domains": ["yapikredi.com.tr", "ykb.com"],
        "visual_cues": [r"yap[ıi]\s*kredi", r"world\s*card"],
    },
    "akbank": {
        "keywords": ["akbank"],
        "official_domains": ["akbank.com", "akbank.com.tr"],
        "visual_cues": [r"akbank\s*direkt", r"akbank\s*mobil"],
    },
    # E-ticaret
    "trendyol": {
        "keywords": ["trendyol"],
        "official_domains": ["trendyol.com"],
        "visual_cues": [r"trendyol\.com", r"trendyol\s*express"],
    },
    "hepsiburada": {
        "keywords": ["hepsiburada"],
        "official_domains": ["hepsiburada.com"],
        "visual_cues": [r"hepsiburada\.com"],
    },
    # E-devlet
    "edevlet": {
        "keywords": ["e-devlet", "edevlet", "turkiye.gov", "e devlet"],
        "official_domains": ["turkiye.gov.tr", "e-devlet.gov.tr"],
        "visual_cues": [r"e-?devlet", r"turkiye\.gov\.tr"],
    },
}

# Zararlı JavaScript kalıpları
MALICIOUS_JS_PATTERNS = [
    # Obfuscation
    (r"eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)", "JavaScript obfuscation (eval + decode)"),
    (r"document\.write\s*\(\s*(unescape|decodeURIComponent)", "document.write ile obfuscation"),
    (r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", "Hex-encoded string (olası obfuscation)"),
    (r"String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){5,}", "CharCode ile string oluşturma"),

    # Keylogger / Data Exfiltration
    (r"addEventListener\s*\(\s*['\"]key(down|up|press)['\"]", "Klavye dinleyici (keylogger şüphesi)"),
    (r"navigator\.(credentials|clipboard)", "Credential/Clipboard erişimi"),
    (r"\.onkeypress|\.onkeydown|\.onkeyup", "Inline key event handler"),

    # Form Hijacking
    (r"form\w*\.action\s*=\s*['\"]https?://", "Form action dinamik değiştirme"),
    (r"XMLHttpRequest|fetch\s*\(.*password|fetch\s*\(.*token", "Hassas veri gönderimi (XHR/fetch)"),

    # Cloaking / Anti-detection
    (r"navigator\.webdriver", "Bot tespit kontrolü (cloaking şüphesi)"),
    (r"window\.location\s*=.*setTimeout", "Gecikmeli yönlendirme"),
    (r"display\s*:\s*none.*<form|visibility\s*:\s*hidden.*<form", "Gizli form"),

    # Crypto mining
    (r"coinhive|cryptonight|minero|JSEcoin", "Kripto madencilik scripti"),
]


def analyze_page_content(html_content, url):
    """
    Ana AI analiz fonksiyonu.
    Sayfa HTML içeriğini çoklu katmanlarla analiz eder.
    """
    if not html_content:
        return {
            "ai_score_penalty": 0,
            "ai_findings": ["Sayfa içeriği alınamadı, içerik analizi atlandı."],
            "brand_impersonation": None,
            "credential_harvesting": False,
            "nlp_risk_score": 0,
            "malicious_scripts": [],
            "content_anomalies": [],
        }

    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    domain = parsed.netloc.replace("www.", "")
    html_lower = html_content.lower()

    # 1. NLP Phishing Skoru
    nlp_result = _nlp_phishing_analysis(html_lower)

    # 2. Marka Taklidi
    brand_result = _detect_brand_impersonation(html_lower, domain)

    # 3. Credential Harvesting
    cred_result = _detect_credential_harvesting(html_content, html_lower)

    # 4. Zararlı JavaScript
    js_result = _detect_malicious_scripts(html_content)

    # 5. İçerik Anomalileri
    anomaly_result = _detect_content_anomalies(html_content, html_lower, domain)

    # --- Toplam skor cezası hesapla ---
    total_penalty = 0
    all_findings = []

    # NLP
    total_penalty += nlp_result["penalty"]
    all_findings.extend(nlp_result["findings"])

    # Brand
    total_penalty += brand_result["penalty"]
    all_findings.extend(brand_result["findings"])

    # Credential
    total_penalty += cred_result["penalty"]
    all_findings.extend(cred_result["findings"])

    # JS
    total_penalty += js_result["penalty"]
    all_findings.extend(js_result["findings"])

    # Anomaly
    total_penalty += anomaly_result["penalty"]
    all_findings.extend(anomaly_result["findings"])

    return {
        "ai_score_penalty": min(total_penalty, 60),
        "ai_findings": all_findings,
        "brand_impersonation": brand_result.get("brand"),
        "credential_harvesting": cred_result["detected"],
        "nlp_risk_score": nlp_result["risk_score"],
        "malicious_scripts": js_result.get("details", []),
        "content_anomalies": anomaly_result.get("details", []),
    }


# =========================================================
# INTERNAL HELPERS
# =========================================================

def _nlp_phishing_analysis(html_lower):
    """NLP tabanlı phishing kelime/kalıp analizi."""
    findings = []
    total_score = 0
    category_hits = {}

    for category, config in PHISHING_PATTERNS.items():
        hits = 0
        for pattern in config["patterns"]:
            matches = re.findall(pattern, html_lower)
            hits += len(matches)

        if hits > 0:
            category_score = min(hits * config["weight"], 20)  # Kategori başına max 20
            total_score += category_score
            category_hits[category] = hits

    # Sonuç yorumlama (çok düşük penalty - NLP noisy)
    penalty = 0
    if total_score >= 40:  # Sadece çok yüksek risk
        penalty = 2
        findings.append(f"🤖 NLP: Yüksek phishing riski tespit edildi (skor: {total_score})")
    elif total_score >= 25:
        penalty = 1
        findings.append(f"🤖 NLP: Orta düzey phishing belirtileri (skor: {total_score})")
    # else: penalty 0 (low scores ignored)

    # Detay
    category_names = {
        "urgency": "Aciliyet/Korku",
        "verification": "Doğrulama İsteği",
        "reward_lure": "Ödül/Tuzak",
        "threat": "Tehdit/Ceza",
        "financial": "Finansal Bilgi Talebi",
    }
    for cat, count in category_hits.items():
        if count >= 2:
            findings.append(f"  ↳ {category_names.get(cat, cat)}: {count} eşleşme")

    return {"penalty": penalty, "findings": findings, "risk_score": total_score}


def _detect_brand_impersonation(html_lower, domain):
    """Sayfa içeriğinde marka taklidi tespit eder (azaltılmış agresiflik)."""
    findings = []
    penalty = 0
    detected_brand = None

    for brand_name, brand_info in BRAND_SIGNATURES.items():
        # Domain zaten resmi mi?
        is_official = any(
            domain == d or domain.endswith("." + d)
            for d in brand_info["official_domains"]
        )
        if is_official:
            continue

        # Keyword eşleşme sayısı
        keyword_hits = sum(1 for kw in brand_info["keywords"] if kw in html_lower)

        # Visual cue eşleşmeleri
        visual_hits = sum(1 for vc in brand_info["visual_cues"] if re.search(vc, html_lower))

        # Agresiflik azaltılmış: 3 keyword + 2 visual cue gerekli VEYA 2 visual cue yeterli
        if keyword_hits >= 3 and visual_hits >= 2:
            detected_brand = brand_name
            penalty = 3  # Düşürüldü: 25 → 3
            findings.append(f"🎭 MARKA TAKLİDİ: '{brand_name.upper()}' markası taklit ediliyor olabilir!")
            findings.append(f"  ↳ {keyword_hits} anahtar kelime + {visual_hits} görsel ipucu eşleşti")
            break
        elif visual_hits >= 2:
            detected_brand = brand_name
            penalty = 2  # Düşürüldü: 20 → 2
            findings.append(f"🎭 Marka şüphesi: '{brand_name}' ile ilgili {visual_hits} görsel ipucu bulundu")
            break
        elif keyword_hits >= 5:
            detected_brand = brand_name
            penalty = 1  # Düşürüldü: 15 → 1
            findings.append(f"🎭 Hafif marka şüphesi: '{brand_name}' ile ilgili {keyword_hits} referans bulundu")
            break

    return {"penalty": penalty, "findings": findings, "brand": detected_brand}


def _detect_credential_harvesting(html_raw, html_lower):
    """Login formları ve hassas veri toplama girişimlerini tespit eder."""
    findings = []
    penalty = 0
    detected = False

    # Password alanı sayısı
    password_fields = len(re.findall(r'type\s*=\s*["\']password["\']', html_lower))
    # Email/text input alanları
    email_fields = len(re.findall(r'type\s*=\s*["\']email["\']', html_lower))
    text_fields = len(re.findall(r'type\s*=\s*["\']text["\']', html_lower))
    # Form sayısı
    form_count = len(re.findall(r'<form\b', html_lower))
    # Submit button
    submit_buttons = len(re.findall(r'type\s*=\s*["\']submit["\']|<button\b', html_lower))

    # Hidden input'lar (veri toplama için)
    hidden_inputs = len(re.findall(r'type\s*=\s*["\']hidden["\']', html_lower))

    # Kredi kartı alanları
    cc_patterns = len(re.findall(
        r'(card.?number|kart.?numara|cvv|cvc|expir|son.?kullanma|credit.?card|kredi.?kart)',
        html_lower
    ))

    # SSN / TC Kimlik
    id_patterns = len(re.findall(
        r'(social.?security|tc.?kimlik|kimlik.?no|identity.?number)',
        html_lower
    ))

    # Form action harici domain'e mi gidiyor?
    external_form = False
    form_actions = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', html_raw)
    for action in form_actions:
        if action.startswith("http") and not any(
            d in action for d in ["localhost", "127.0.0.1"]
        ):
            action_domain = urlparse(action).netloc.replace("www.", "")
            # Form action URL tamamen farklı bir domain'e mi?
            if action_domain and action_domain not in html_lower[:500]:
                external_form = True

    # --- Değerlendirme ---
    if password_fields > 0 and form_count > 0:
        detected = True
        penalty += 2  # Düşürüldü: 15 → 2
        findings.append(f"🔑 Credential Harvesting: {password_fields} şifre alanı + {form_count} form tespit edildi")

    if cc_patterns > 0:
        detected = True
        penalty += 3  # Düşürüldü: 20 → 3
        findings.append(f"💳 Kredi kartı bilgisi toplama girişimi ({cc_patterns} kalıp)")

    if id_patterns > 0:
        detected = True
        penalty += 2  # Düşürüldü: 15 → 2
        findings.append(f"🆔 Kimlik bilgisi toplama girişimi ({id_patterns} kalıp)")

    if external_form:
        penalty += 1  # Düşürüldü: 10 → 1
        findings.append("⚠️ Form verisi harici bir sunucuya gönderiliyor")

    if hidden_inputs > 5:
        penalty += 5
        findings.append(f"⚠️ {hidden_inputs} gizli (hidden) input alanı var")

    return {"penalty": penalty, "findings": findings, "detected": detected}


def _detect_malicious_scripts(html_raw):
    """Zararlı JavaScript kalıplarını tespit eder."""
    findings = []
    details = []
    penalty = 0

    for pattern, description in MALICIOUS_JS_PATTERNS:
        if re.search(pattern, html_raw, re.IGNORECASE):
            details.append(description)
            penalty += 10

    if details:
        findings.append(f"🦠 {len(details)} zararlı JavaScript kalıbı tespit edildi:")
        for d in details[:5]:  # En fazla 5 tane göster
            findings.append(f"  ↳ {d}")

    penalty = min(penalty, 25)
    return {"penalty": penalty, "findings": findings, "details": details}


def _detect_content_anomalies(html_raw, html_lower, domain):
    """Yapısal içerik anomalilerini tespit eder."""
    findings = []
    details = []
    penalty = 0

    # 1. Çok kısa sayfa (sadece form olan phishing sayfası)
    text_content = re.sub(r'<[^>]+>', '', html_raw)
    text_content = re.sub(r'\s+', ' ', text_content).strip()
    if len(text_content) < 200 and '<form' in html_lower:
        penalty += 10
        detail = "Çok az içerikli sayfa + form (phishing sayfası şüphesi)"
        findings.append(f"📄 {detail}")
        details.append(detail)

    # 2. iframe yükleme (credential overlay)
    iframe_count = len(re.findall(r'<iframe\b', html_lower))
    if iframe_count > 0:
        # iframe src farklı domain mi?
        iframe_srcs = re.findall(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', html_raw, re.IGNORECASE)
        external_iframes = [s for s in iframe_srcs if s.startswith("http") and domain not in s]
        if external_iframes:
            penalty += 15
            detail = f"{len(external_iframes)} harici iframe yükleniyor"
            findings.append(f"🖼️ {detail}")
            details.append(detail)

    # 3. Meta refresh redirect
    meta_refresh = re.findall(r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\']([^"\']+)["\']', html_raw, re.IGNORECASE)
    if meta_refresh:
        penalty += 10
        detail = "Meta refresh yönlendirmesi tespit edildi"
        findings.append(f"🔄 {detail}")
        details.append(detail)

    # 4. Base64 encoded data (gömülü zararlı içerik)
    base64_data = re.findall(r'data:[^;]+;base64,', html_lower)
    if len(base64_data) > 3:
        penalty += 5
        detail = f"{len(base64_data)} base64 encoded veri bloğu"
        findings.append(f"📦 {detail}")
        details.append(detail)

    # 5. Title ile domain uyumsuzluğu
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html_lower, re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        # Title'da bilinen bir marka var ama domain'de yok?
        for brand_name, brand_info in BRAND_SIGNATURES.items():
            if any(kw in title for kw in brand_info["keywords"]):
                is_official = any(
                    domain == d or domain.endswith("." + d)
                    for d in brand_info["official_domains"]
                )
                if not is_official:
                    penalty += 10
                    detail = f"Sayfa başlığı '{brand_name}' markasını referans ediyor ama domain resmi değil"
                    findings.append(f"⚠️ {detail}")
                    details.append(detail)
                    break

    # 6. Çok fazla external script
    external_scripts = re.findall(r'<script[^>]+src\s*=\s*["\']https?://([^"\']+)["\']', html_raw, re.IGNORECASE)
    unique_script_domains = set()
    for s in external_scripts:
        sd = s.split("/")[0]
        if domain not in sd:
            unique_script_domains.add(sd)
    if len(unique_script_domains) > 5:
        penalty += 5
        detail = f"{len(unique_script_domains)} farklı harici domain'den script yükleniyor"
        findings.append(f"📡 {detail}")
        details.append(detail)

    # 7. Entropy kontrolü — çok yüksek entropi = obfuscation
    entropy = _calculate_entropy(html_raw[:5000])
    if entropy > 5.5:
        penalty += 5
        detail = f"Yüksek içerik entropisi ({entropy:.2f}) — obfuscation şüphesi"
        findings.append(f"🔢 {detail}")
        details.append(detail)

    return {"penalty": penalty, "findings": findings, "details": details}


def _calculate_entropy(text):
    """Shannon entropy hesaplar."""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def fetch_page_content(url, timeout=8):
    """Sayfa HTML içeriğini güvenli şekilde çeker."""
    import requests
    import certifi

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=certifi.where()
        )
        response.encoding = response.apparent_encoding or 'utf-8'

        # Çok büyük sayfaları sınırla (max 500KB)
        content = response.text[:500_000]
        return content
    except Exception as e:
        logger.warning(f"Sayfa içeriği alınamadı: {url} — {e}")
        return None
