"""
ML-Based URL Classifier
========================
URL'den özellik çıkarımı yaparak makine öğrenmesi tabanlı sınıflandırma.
Heuristic-ML hybrid yaklaşım — harici model gerektirmez.
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs
from collections import Counter


# =========================================================
# URL ÖZELLİK ÇIKARIMI (Feature Extraction)
# =========================================================

def extract_url_features(url):
    """URL'den 25+ özellik çıkarır."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Domain parçaları
    domain_parts = domain.split(".")
    domain_name = domain_parts[0] if domain_parts else ""

    features = {}

    # --- Uzunluk metrikleri ---
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["fragment_length"] = len(fragment)

    # --- Karakter dağılımı ---
    features["dot_count"] = url.count(".")
    features["dash_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["question_count"] = url.count("?")
    features["equal_count"] = url.count("=")
    features["ampersand_count"] = url.count("&")
    features["at_count"] = url.count("@")
    features["percent_count"] = url.count("%")
    features["tilde_count"] = url.count("~")

    # --- Rakam/harf oranları ---
    features["digit_count"] = sum(c.isdigit() for c in url)
    features["letter_count"] = sum(c.isalpha() for c in url)
    features["digit_ratio"] = features["digit_count"] / max(len(url), 1)
    features["letter_ratio"] = features["letter_count"] / max(len(url), 1)
    features["special_char_ratio"] = 1 - features["digit_ratio"] - features["letter_ratio"]

    # --- Domain özellikleri ---
    features["subdomain_count"] = max(len(domain_parts) - 2, 0)
    features["has_ip_address"] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features["is_https"] = 1 if parsed.scheme == "https" else 0
    features["has_port"] = 1 if ":" in domain else 0

    # Domain adındaki rakam oranı
    features["domain_digit_ratio"] = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
    features["domain_dash_count"] = domain_name.count("-")

    # --- Path özellikleri ---
    features["path_depth"] = len([p for p in path.split("/") if p])
    features["has_exe_extension"] = 1 if re.search(r"\.(exe|zip|rar|scr|bat|cmd|msi|js|vbs)$", path, re.I) else 0

    # --- Query string ---
    params = parse_qs(query)
    features["query_param_count"] = len(params)

    # --- Entropy ---
    features["url_entropy"] = _shannon_entropy(url)
    features["domain_entropy"] = _shannon_entropy(domain)

    # --- Suspicious keyword count ---
    suspicious_kw = [
        "login", "signin", "verify", "account", "update", "secure", "bank",
        "confirm", "password", "credential", "suspend", "locked", "alert",
        "urgent", "free", "winner", "prize", "bonus", "wallet",
        "giris", "giriş", "dogrula", "hesap", "sifre", "banka",
    ]
    features["suspicious_keyword_count"] = sum(1 for kw in suspicious_kw if kw in url.lower())

    # --- TLD riski ---
    risky_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
                  ".click", ".link", ".info", ".work", ".rest", ".icu", ".cam",
                  ".quest", ".surf", ".monster", ".loan", ".win"}
    features["risky_tld"] = 1 if any(domain.endswith(t) for t in risky_tlds) else 0

    # --- URL shortener kontrolü ---
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"}
    features["is_shortened"] = 1 if domain in shorteners else 0

    # --- Punycode (IDN) ---
    features["has_punycode"] = 1 if "xn--" in domain else 0

    return features


def _shannon_entropy(text):
    """Shannon entropy hesaplar."""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = 0
    for count in counter.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return round(entropy, 3)


# =========================================================
# ML HYBRID CLASSIFIER
# =========================================================

# Her özellik için ağırlık ve eşik değerleri (heuristic ML)
FEATURE_WEIGHTS = {
    "url_length": {"threshold": 54, "weight": 0.8, "type": "above"},
    "domain_length": {"threshold": 20, "weight": 0.6, "type": "above"},
    "dot_count": {"threshold": 3, "weight": 0.7, "type": "above"},
    "dash_count": {"threshold": 2, "weight": 0.5, "type": "above"},
    "at_count": {"threshold": 0, "weight": 1.5, "type": "above"},
    "percent_count": {"threshold": 3, "weight": 0.6, "type": "above"},
    "digit_ratio": {"threshold": 0.25, "weight": 0.8, "type": "above"},
    "special_char_ratio": {"threshold": 0.35, "weight": 0.7, "type": "above"},
    "subdomain_count": {"threshold": 2, "weight": 0.9, "type": "above"},
    "has_ip_address": {"threshold": 0, "weight": 2.0, "type": "above"},
    "is_https": {"threshold": 1, "weight": 1.2, "type": "below"},
    "has_port": {"threshold": 0, "weight": 1.0, "type": "above"},
    "domain_digit_ratio": {"threshold": 0.25, "weight": 0.7, "type": "above"},
    "path_depth": {"threshold": 4, "weight": 0.5, "type": "above"},
    "has_exe_extension": {"threshold": 0, "weight": 2.0, "type": "above"},
    "query_param_count": {"threshold": 3, "weight": 0.4, "type": "above"},
    "url_entropy": {"threshold": 4.2, "weight": 0.6, "type": "above"},
    "domain_entropy": {"threshold": 3.5, "weight": 0.5, "type": "above"},
    "suspicious_keyword_count": {"threshold": 0, "weight": 1.2, "type": "above"},
    "risky_tld": {"threshold": 0, "weight": 1.5, "type": "above"},
    "is_shortened": {"threshold": 0, "weight": 0.8, "type": "above"},
    "has_punycode": {"threshold": 0, "weight": 1.5, "type": "above"},
    "domain_dash_count": {"threshold": 1, "weight": 0.6, "type": "above"},
}


def classify_url(url):
    """
    URL'yi ML-hybrid yöntemle sınıflandırır.
    Döndürür: {
        "ml_score": float (0-100, yüksek=tehlikeli),
        "ml_label": str,
        "ml_penalty": int,
        "ml_findings": list,
        "features": dict
    }
    """
    features = extract_url_features(url)

    # Her özellik için risk puanı hesapla
    risk_score = 0
    max_possible = 0
    triggered_features = []

    for feature_name, config in FEATURE_WEIGHTS.items():
        value = features.get(feature_name, 0)
        threshold = config["threshold"]
        weight = config["weight"]
        check_type = config["type"]
        max_possible += weight

        triggered = False
        if check_type == "above" and value > threshold:
            triggered = True
        elif check_type == "below" and value < threshold:
            triggered = True

        if triggered:
            risk_score += weight
            triggered_features.append(feature_name)

    # Normalize (0-100)
    ml_score = round((risk_score / max_possible) * 100, 1) if max_possible > 0 else 0

    # Label
    if ml_score >= 60:
        label = "Yüksek Risk"
        penalty = 20
    elif ml_score >= 35:
        label = "Orta Risk"
        penalty = 12
    elif ml_score >= 20:
        label = "Düşük Risk"
        penalty = 5
    else:
        label = "Düşük Risk / Normal"
        penalty = 0

    # Findings
    findings = []
    if ml_score >= 25:
        findings.append(f"🧠 ML Sınıflandırma: {label} (skor: {ml_score}/100)")

        # En önemli tetiklenen özellikler
        feature_descriptions = {
            "url_length": "Aşırı uzun URL",
            "domain_length": "Uzun domain adı",
            "dot_count": "Çok fazla nokta",
            "dash_count": "Çok fazla tire",
            "at_count": "@ işareti mevcut",
            "percent_count": "Çok fazla URL-encoding",
            "digit_ratio": "Yüksek rakam oranı",
            "subdomain_count": "Çok fazla alt domain",
            "has_ip_address": "IP adresi kullanımı",
            "is_https": "HTTPS yok",
            "has_port": "Standart dışı port",
            "has_exe_extension": "Çalıştırılabilir dosya uzantısı",
            "suspicious_keyword_count": "Şüpheli anahtar kelimeler",
            "risky_tld": "Riskli TLD uzantısı",
            "is_shortened": "URL kısaltma servisi",
            "has_punycode": "Punycode (IDN homograph)",
            "url_entropy": "Yüksek URL entropisi",
            "domain_entropy": "Yüksek domain entropisi",
            "domain_digit_ratio": "Domain'de çok rakam",
        }

        important_triggers = [
            f for f in triggered_features
            if FEATURE_WEIGHTS[f]["weight"] >= 0.7
        ]
        for ft in important_triggers[:5]:
            desc = feature_descriptions.get(ft, ft)
            findings.append(f"  ↳ {desc}")

    return {
        "ml_score": ml_score,
        "ml_label": label,
        "ml_penalty": penalty,
        "ml_findings": findings,
        "features": features,
        "triggered_features": triggered_features
    }
