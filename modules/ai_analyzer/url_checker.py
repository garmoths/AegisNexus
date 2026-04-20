"""
URL Güvenlik Kontrolü - Veritabanı ve API entegrasyonu
"""
import re
import requests
from urllib.parse import urlparse
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

class URLSecurityChecker:
    """URL güvenlik analizi"""
    
    def __init__(self, db: Session = None):
        self.db = db
        self.virustotal_key = ""
        self.urlscan_key = ""
    
    def check_url(self, url: str) -> Dict:
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
            "checks": []
        }
        
        # 1. Format kontrolü
        if not self._is_valid_url(url):
            result["risk_score"] = 100
            result["is_safe"] = False
            result["checks"].append("Invalid URL format")
            return result
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # 2. Şüpheli TLD kontrolü
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.link']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result["risk_score"] += 30
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
        bank_names = ['bank', 'garanti', 'akbank', 'isbank', 'halkbank', 'vakifbank', 
                      'ziraat', 'yapikredi', 'finans', 'denizbank', 'teb', 'ING',
                      'hsbc', 'paypal', 'apple', 'google', 'microsoft', 'amazon']
        for bank in bank_names:
            if bank in domain_lower and not any(official in domain_lower for official in 
                ['.com.tr', '.gov.tr', '.org.tr', '.gov', '.edu']):
                # Eğer banka adı var ama resmi TLD yoksa
                result["risk_score"] += 35
                result["checks"].append(f"SAHTE BANKA/KURUM TESPİTİ: '{bank}' adı kullanılıyor!")
                break
        
        # 6. Şüpheli path'ler (/verify, /login, /confirm, /secure)
        suspicious_paths = ['/verify', '/confirm', '/secure', '/login', '/auth', 
                           '/validate', '/update', '/account', '/billing', '/payment']
        path_lower = parsed.path.lower()
        for spath in suspicious_paths:
            if spath in path_lower:
                result["risk_score"] += 15
                result["checks"].append(f"Şüpheli path: '{spath}' (kimlik doğrulama sayfası olabilir)")
        
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
        pattern = re.compile(
            r'^(http|https)://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        return bool(pattern.match(url))
    
    def _check_database(self, url: str, domain: str) -> Dict:
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
    
    def _check_urlscan(self, url: str) -> Dict:
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
    
    def _check_virustotal(self, url: str) -> Dict:
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
    
    def extract_urls(self, text: str) -> List[str]:
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
