"""
URL Güvenlik Kontrolü - Veritabanı ve API entegrasyonu
"""
import re
from urllib.parse import urlparse

import requests
from sqlalchemy.orm import Session


class URLSecurityChecker:
    """URL güvenlik analizi"""

    def __init__(self, db: Session = None):
        self.db = db
        self.virustotal_key = ""
        self.urlscan_key = ""

    def check_url(self, url: str) -> dict:
        """
        URL güvenlik kontrolü

        Returns:
            {
                "url": url,
                "is_safe": bool,
                "risk_score": 0-100,
                "in_database": bool,
                "threat_info": {},
                "scan_results": {}
            }
        """
        result = {
            "url": url,
            "is_safe": True,
            "risk_score": 0,
            "in_database": False,
            "threat_info": None,
            "scan_results": {},
            "checks": [],
            "safety_verified": False,
            "limitation": "Yerel işaretler ve mevcut kayıtlar incelendi; eşleşme olmaması güvenlik garantisi değildir."
        }

        # 1. Format kontrolü
        if not self._is_valid_url(url):
            result["risk_score"] = 100
            result["is_safe"] = False
            result["checks"].append("Invalid URL format")
            return result

        parsed = urlparse(url)
        domain = (parsed.hostname or '').lower().rstrip('.')

        # 2. Şüpheli TLD kontrolü
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.link', '.work', '.gq', '.cc', '.pw']
        has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
        if has_suspicious_tld:
            result["risk_score"] += 35
            result["checks"].append(f"Şüpheli TLD: {domain}")

        # 3. HTTP kullanımı (HTTPS yoksa şüpheli)
        if url.startswith('http://') and not url.startswith('https://'):
            result["risk_score"] += 20
            result["checks"].append("Güvensiz HTTP bağlantısı (HTTPS yok)")

        # 4. Phishing anahtar kelimeleri domain içinde
        phishing_keywords = ['fake', 'phish', 'scam', 'fraud', 'spoof', 'clone', 'mirror']
        domain_lower = domain.lower()
        for keyword in phishing_keywords:
            if keyword in domain_lower:
                result["risk_score"] += 40
                result["checks"].append(f"PHISHING KELİMESİ: '{keyword}' domain içinde tespit edildi!")

        # 5. Banka/Kurum taklitleri (sahte banka domainleri)
        bank_names = [
            'bank', 'garanti', 'akbank', 'isbank', 'halkbank', 'vakifbank',
            'ziraat', 'yapikredi', 'finans', 'denizbank', 'teb', 'ing',
            'hsbc', 'paypal', 'apple', 'google', 'microsoft', 'amazon',
            # Türk kamu kurumları
            'ptt', 'kargo', 'sgk', 'edevlet', 'e-devlet', 'turkiye',
            'maliye', 'gib', 'emniyet', 'jandarma', 'saglik', 'meb',
            'ekurye', 'yurtici', 'aras', 'mng', 'ups',
            # Telekom
            'turkcell', 'vodafone', 'turktelekom', 'superonline',
            # Fintech / ödeme
            'papara', 'enpara', 'n11', 'trendyol', 'hepsiburada',
        ]
        official_hosts = {
            'google': ('google.com', 'google.com.tr'), 'apple': ('apple.com',),
            'microsoft': ('microsoft.com', 'live.com', 'office.com'), 'amazon': ('amazon.com', 'amazon.com.tr'),
            'paypal': ('paypal.com',), 'garanti': ('garantibbva.com.tr', 'garanti.com.tr'),
            'akbank': ('akbank.com',), 'isbank': ('isbank.com.tr',), 'halkbank': ('halkbank.com.tr',),
            'vakifbank': ('vakifbank.com.tr',), 'ziraat': ('ziraatbank.com.tr',),
            'yapikredi': ('yapikredi.com.tr',), 'denizbank': ('denizbank.com',),
            'teb': ('teb.com.tr',), 'ing': ('ing.com', 'ing.com.tr'), 'hsbc': ('hsbc.com', 'hsbc.com.tr'),
            'turkiye': ('turkiye.gov.tr',), 'edevlet': ('turkiye.gov.tr',), 'e-devlet': ('turkiye.gov.tr',),
            'ptt': ('ptt.gov.tr',), 'sgk': ('sgk.gov.tr',), 'gib': ('gib.gov.tr',),
            'turkcell': ('turkcell.com.tr',), 'vodafone': ('vodafone.com.tr',),
            'turktelekom': ('turktelekom.com.tr',), 'papara': ('papara.com',),
            'trendyol': ('trendyol.com',), 'hepsiburada': ('hepsiburada.com',),
        }
        has_brand_domain = False
        labels = re.split(r'[.-]', domain_lower)
        for bank in bank_names:
            # Short brand strings must be complete labels ("ing" is not "spring").
            matches_brand = bank in labels if len(bank) <= 3 else bank in domain_lower
            known_host = any(domain_lower == official or domain_lower.endswith('.' + official)
                             for official in official_hosts.get(bank, ()))
            if matches_brand and not known_host:
                result['risk_score'] += 40
                result['checks'].append(f"Kurum adı benzerliği: '{bank}' kullanılıyor; resmi adresle doğrulayın.")
                has_brand_domain = True
                break

        # 5b. Kombinasyon: şüpheli TLD + kurum adı → direkt yüksek risk
        if has_suspicious_tld and has_brand_domain:
            result["risk_score"] = max(result["risk_score"], 90)
            result["checks"].insert(0, "🚨 KRİTİK: Şüpheli TLD + Kurum adı kombinasyonu — phishing neredeyse kesin!")

        # 5c. .net / .org ile kurum adı → ekstra risk (resmi değil)
        if has_brand_domain and any(domain.endswith(tld) for tld in ['.net', '.org', '.info', '.biz']):
            result["risk_score"] = max(result["risk_score"], 75)
            result["checks"].append("⚠️ Kurum adı .net/.org uzantılı domain'de — resmi değil!")

        # 6. Şüpheli path'ler (/verify, /login, /confirm, /secure)
        suspicious_paths = [
            '/verify', '/confirm', '/secure', '/login', '/auth',
            '/validate', '/update', '/account', '/billing', '/payment',
            # Türkçe phishing path'leri
            '/dogrula', '/dogrulama', '/giris', '/hesap', '/odeme',
            '/islem', '/cek', '/guncelle', '/sifre', '/onay',
            '/pay', '/aktivasyon', '/kayit', '/uye',
        ]
        path_lower = parsed.path.lower()
        for spath in suspicious_paths:
            if spath in path_lower:
                result["risk_score"] += 18
                result["checks"].append(f"Şüpheli path: '{spath}' (kimlik doğrulama/işlem sayfası)")

        # 7. Çok uzun subdomain veya rastgele karakterler
        subdomain = domain.split('.')[0]
        if len(subdomain) > 30:
            result["risk_score"] += 20
            result["checks"].append("Çok uzun subdomain (obfuscation şüphesi)")

        # 8. Rastgele karakter içeren domain (otomatik oluşturulmuş)
        if re.search(r'[a-z0-9]{20,}', domain_lower):
            result["risk_score"] += 25
            result["checks"].append("Rastgele karakterler içeren domain (otomatik phishing)")

        # 9. IP tabanlı URL
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            result["risk_score"] += 25
            result["checks"].append("IP-based URL (suspicious)")

        # 10. Veritabanında var mı? (Phishing DB)
        if self.db:
            db_result = self._check_database(url, domain)
            if db_result["found"]:
                result["in_database"] = True
                result["threat_info"] = db_result["info"]
                result["risk_score"] = 100
                result["is_safe"] = False
                result["checks"].append(f"TEHDİT VERİTABANINDA BULUNDU: {db_result['info'].get('target', 'Unknown')}")
                return result

        # 11. URLScan.io kontrolü (opsiyonel)
        if self.urlscan_key:
            scan_result = self._check_urlscan(url)
            result["scan_results"]["urlscan"] = scan_result
            if scan_result.get("malicious"):
                result["risk_score"] += 40
                result["checks"].append("URLScan: Zararlı olarak işaretlendi")

        # 12. VirusTotal kontrolü (opsiyonel)
        if self.virustotal_key:
            vt_result = self._check_virustotal(url)
            result["scan_results"]["virustotal"] = vt_result
            if vt_result.get("positives", 0) > 0:
                result["risk_score"] += min(vt_result["positives"] * 10, 50)
                result["checks"].append(f"VirusTotal: {vt_result['positives']}/{vt_result['total']} tespit")

        result["risk_score"] = min(100, result["risk_score"])

        # 13. Son Karar
        if result["risk_score"] >= 70:
            result["is_safe"] = False
            result["checks"].insert(0, f"🔴 YÜKSEK RİSKLİ URL! Skor: {result['risk_score']}/100")
        elif result["risk_score"] >= 40:
            result["is_safe"] = False  # Medium risk = not safe
            result["checks"].insert(0, f"⚠️  ŞÜPHELİ URL! Skor: {result['risk_score']}/100")
        elif result["risk_score"] > 0:
            result["checks"].insert(0, f"ℹ️  Düşük risk: {result['risk_score']}/100")

        return result

    def _is_valid_url(self, url: str) -> bool:
        """URL format kontrolü"""
        try:
            parsed = urlparse(url)
            if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
                return False
            if parsed.username or parsed.password or any(c.isspace() for c in url) or '\\' in url:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            host = parsed.hostname.rstrip('.').encode('idna').decode('ascii')
            import ipaddress
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                return len(host) <= 253 and '.' in host and all(
                    re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
                    for label in host.split('.'))
        except (ValueError, UnicodeError):
            return False

    def _check_database(self, url: str, domain: str) -> dict:
        """Veritabanında ara (Phishing URLs)"""
        try:
            from app.models import PhishingURL

            # Tam URL ara
            exact_match = self.db.query(PhishingURL).filter(
                PhishingURL.url == url
            ).first()

            if exact_match:
                return {
                    "found": True,
                    "info": {
                        "url": exact_match.url,
                        "target": exact_match.target,
                        "status": exact_match.status,
                        "submission_time": str(exact_match.submission_time)
                    }
                }

            # Domain ara
            domain_match = self.db.query(PhishingURL).filter(
                PhishingURL.domain_norm == domain
            ).first()

            if domain_match:
                return {
                    "found": True,
                    "info": {
                        "domain": domain,
                        "url": domain_match.url,
                        "target": domain_match.target
                    }
                }

            return {"found": False}

        except Exception as e:
            print(f"Database check error: {e}")
            return {"found": False}

    def _check_urlscan(self, url: str) -> dict:
        """URLScan.io API kontrolü"""
        try:
            headers = {"API-Key": self.urlscan_key}
            response = requests.get(
                f"https://urlscan.io/api/v1/scan/?url={url}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "score": data.get("verdicts", {}).get("overall", {}).get("score", 0),
                    "screenshot": data.get("task", {}).get("screenshotURL")
                }
            return {"error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def _check_virustotal(self, url: str) -> dict:
        """VirusTotal API kontrolü"""
        try:
            import hashlib
            url_hash = hashlib.sha256(url.encode()).hexdigest()

            headers = {"x-apikey": self.virustotal_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_hash}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values()),
                    "harmless": stats.get("harmless", 0)
                }
            return {"error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def extract_urls(self, text: str) -> list[str]:
        """Metinden URL çıkar"""
        # URL pattern
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        urls = url_pattern.findall(text)

        # www. ile başlayanları da bul
        www_pattern = re.compile(r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        www_matches = www_pattern.findall(text)
        urls.extend([f"http://{w}" for w in www_matches])

        return list(set(urls))  # Unique
