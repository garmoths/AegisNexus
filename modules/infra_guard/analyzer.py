"""
Infrastructure Security Analyzer
Domain SSL, port ve yapı analizi
"""
from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests


class InfraAnalyzer:
    """
    Altyapı Güvenlik Analizörü
    - SSL sertifikası kontrolü
    - Port taraması
    - Yönlendirme zinciri
    - Domain yapısı analizi
    """
    
    COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995]
    
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    
    @classmethod
    def check_ssl(cls, domain: str) -> Dict:
        """SSL sertifikası detaylı analizi"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Sertifika bitiş tarihi
                    not_after = cert.get("notAfter")
                    if not_after:
                        expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.utcnow()).days
                    else:
                        days_left = -1
                    
                    # Güvenlik puanlama
                    score = 100
                    issues = []
                    
                    if version == "TLSv1" or version == "TLSv1.1":
                        score -= 40
                        issues.append(f"Eski TLS versiyonu: {version} - Güncelleme gerekli")
                    elif version == "TLSv1.2":
                        score -= 10
                        issues.append("TLS 1.2 kullanılıyor - TLS 1.3 önerilir")
                    
                    if days_left < 0:
                        score -= 50
                        issues.append("Sertifika GEÇERSİZ!")
                    elif days_left < 7:
                        score -= 30
                        issues.append(f"Sertifika {days_left} gün içinde süresi doluyor!")
                    elif days_left < 30:
                        score -= 15
                        issues.append(f"Sertifika {days_left} gün içinde süresi dolacak")
                    
                    return {
                        "valid": True,
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_before": cert.get("notBefore"),
                        "not_after": not_after,
                        "days_left": days_left,
                        "serial_number": cert.get("serialNumber"),
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "score": max(0, score),
                        "issues": issues,
                        "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "F",
                    }
        except ssl.SSLError as e:
            return {
                "valid": False,
                "error": f"SSL Hatası: {str(e)}",
                "score": 0,
                "grade": "F",
                "issues": ["SSL sertifikası geçersiz veya yapılandırma hatası"],
            }
        except socket.error as e:
            return {
                "valid": False,
                "error": f"Bağlantı hatası: {str(e)}",
                "score": 0,
                "grade": "F",
                "issues": ["443 portuna bağlanılamadı - SSL devre dışı olabilir"],
            }
    
    @classmethod
    def scan_ports(cls, domain: str, ports: Optional[List[int]] = None) -> List[Dict]:
        """Port taraması - Hızlı kontrol"""
        ports = ports or [80, 443, 8080, 8443]
        results = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                is_open = result == 0
                sock.close()
                
                results.append({
                    "port": port,
                    "open": is_open,
                    "service": cls._get_service_name(port),
                    "risk": "HIGH" if port in [21, 23, 3389] and is_open else "MEDIUM" if is_open else "LOW",
                })
            except Exception:
                results.append({
                    "port": port,
                    "open": False,
                    "service": cls._get_service_name(port),
                    "error": "Tarama hatası",
                })
        
        return results
    
    @classmethod
    def check_redirects(cls, url: str, max_redirects: int = 5) -> Dict:
        """Yönlendirme zincirini takip et"""
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=10,
                headers={"User-Agent": "AegisNexus-Security-Scanner/1.0"}
            )
            
            redirect_chain = []
            if response.history:
                for resp in response.history:
                    redirect_chain.append({
                        "status": resp.status_code,
                        "url": resp.url,
                    })
            
            redirect_chain.append({
                "status": response.status_code,
                "url": response.url,
            })
            
            # Şüpheli yönlendirme kontrolü
            suspicious = False
            indicators = []
            
            if len(redirect_chain) > 3:
                suspicious = True
                indicators.append("Çok fazla yönlendirme (3+)")
            
            final_url = response.url
            original_domain = urlparse(url).netloc
            final_domain = urlparse(final_url).netloc
            
            if original_domain != final_domain and len(redirect_chain) > 1:
                suspicious = True
                indicators.append(f"Domain değişimi: {original_domain} -> {final_domain}")
            
            # Güvenlik başlıkları kontrolü
            headers = response.headers
            security_headers_present = {h: h in headers for h in cls.SECURITY_HEADERS}
            missing_headers = [h for h, present in security_headers_present.items() if not present]
            
            return {
                "redirect_count": len(redirect_chain) - 1,
                "chain": redirect_chain,
                "final_url": final_url,
                "suspicious": suspicious,
                "indicators": indicators,
                "security_headers": security_headers_present,
                "missing_security_headers": missing_headers,
                "xss_protection": "X-XSS-Protection" in headers,
            }
        except requests.RequestException as e:
            return {
                "error": str(e),
                "redirect_count": 0,
                "suspicious": True,
                "indicators": ["Site erişilemez veya engellendi"],
            }
    
    @classmethod
    def analyze_domain_structure(cls, domain: str) -> Dict:
        """Domain yapısı analizi - Phishing göstergeleri"""
        findings = []
        penalty = 0
        
        # Typosquatting kontrolü (örn: gogle.com)
        brand_indicators = ["google", "facebook", "apple", "microsoft", "amazon", "paypal", "bank", "ziraat", "garanti", "akbank"]
        domain_lower = domain.lower()
        
        for brand in brand_indicators:
            if brand in domain_lower and not domain_lower.startswith(brand + "."):
                if domain_lower != brand + ".com" and domain_lower != brand + ".tr":
                    findings.append(f"⚠️ Marka taklidi: '{brand}' içeriyor")
                    penalty += 30
        
        # Şüpheli anahtar kelimeler
        suspicious_keywords = ["login", "signin", "secure", "verify", "account", "update", "confirm"]
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                findings.append(f"Şüpheli anahtar kelime: '{keyword}'")
                penalty += 10
        
        # Çok uzun subdomain
        parts = domain.split(".")
        if len(parts) > 3:
            findings.append("Çok fazla subdomain - Şüpheli yapı")
            penalty += 15
        
        # Sayı içeren domain
        if any(c.isdigit() for c in domain.split(".")[0]):
            findings.append("Domain içinde rakam var")
            penalty += 5
        
        return {
            "domain": domain,
            "findings": findings,
            "penalty": penalty,
            "risk_level": "HIGH" if penalty >= 50 else "MEDIUM" if penalty >= 20 else "LOW",
        }
    
    @classmethod
    def full_analysis(cls, url: str) -> Dict:
        """Tam altyapı analizi - Tüm kontroller"""
        # URL normalizasyon
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        
        # SSL kontrolü
        ssl_info = cls.check_ssl(domain)
        
        # Port taraması (temel)
        port_results = cls.scan_ports(domain)
        
        # Yönlendirme kontrolü
        redirect_info = cls.check_redirects(url)
        
        # Domain yapısı
        structure = cls.analyze_domain_structure(domain)
        
        # Genel puanlama
        score = ssl_info.get("score", 0)
        
        # SSL dışındaki faktörler
        if redirect_info.get("suspicious"):
            score -= 20
        
        if structure.get("penalty", 0) > 30:
            score -= 15
        
        # Güvenlik başlıkları puanı
        missing_headers = redirect_info.get("missing_security_headers", [])
        score -= len(missing_headers) * 5
        
        score = max(0, min(100, score))
        
        return {
            "url": url,
            "domain": domain,
            "ssl": ssl_info,
            "ports": port_results,
            "redirects": redirect_info,
            "domain_structure": structure,
            "overall_score": score,
            "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F",
            "recommendations": cls._generate_recommendations(ssl_info, redirect_info, structure, missing_headers),
        }
    
    @classmethod
    def _get_service_name(cls, port: int) -> str:
        """Port numarasına göre servis adı"""
        services = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            3389: "RDP",
        }
        return services.get(port, "Unknown")
    
    @classmethod
    def _generate_recommendations(cls, ssl_info: Dict, redirects: Dict, structure: Dict, missing_headers: List) -> List[str]:
        """İyileştirme önerileri"""
        recs = []
        
        # SSL önerileri
        if not ssl_info.get("valid"):
            recs.append("DERHAL SSL sertifikası yükleyin!")
        elif ssl_info.get("days_left", 0) < 30:
            recs.append(f"SSL sertifikası {ssl_info.get('days_left')} gün içinde yenilenmeli")
        
        if ssl_info.get("tls_version") in ["TLSv1", "TLSv1.1"]:
            recs.append("TLS 1.2 veya 1.3'e yükseltin (eski versiyon güvensiz)")
        
        # Yönlendirme önerileri
        if redirects.get("suspicious"):
            recs.append("Şüpheli yönlendirme zinciri tespit edildi - Domain yapısını kontrol edin")
        
        # Domain yapısı
        if structure.get("penalty", 0) > 30:
            recs.append("Domain adı şüpheli anahtar kelimeler içeriyor - Phishing kontrolü yapın")
        
        # Güvenlik başlıkları
        if "Strict-Transport-Security" in missing_headers:
            recs.append("HSTS başlığı ekleyin (HTTPS zorlaması)")
        
        if "Content-Security-Policy" in missing_headers:
            recs.append("CSP (Content Security Policy) başlığı ekleyin (XSS koruma)")
        
        if "X-Frame-Options" in missing_headers:
            recs.append("X-Frame-Options başlığı ekleyin (Clickjacking koruma)")
        
        return recs


# Kolay kullanım fonksiyonları
def analyze_infrastructure(url: str) -> Dict:
    """Tam altyapı analizi"""
    return InfraAnalyzer.full_analysis(url)


def check_ssl_only(domain: str) -> Dict:
    """Sadece SSL kontrolü"""
    return InfraAnalyzer.check_ssl(domain)
