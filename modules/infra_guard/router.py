"""
05 - Infrastructure Guard Module Router (Altyapı Kalkanı)
SSL, port ve domain güvenlik analizi endpointleri
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List

from .analyzer import InfraAnalyzer, analyze_infrastructure, check_ssl_only

router = APIRouter(tags=["05-infra-guard"])


class URLAnalyzeRequest(BaseModel):
    url: str


class SSLCheckRequest(BaseModel):
    domain: str


class PortScanRequest(BaseModel):
    domain: str
    ports: Optional[List[int]] = None


@router.post("/analyze")
def analyze_url(req: URLAnalyzeRequest):
    """
    Tam altyapı analizi - SSL, port, yönlendirme ve domain yapısı.
    KOBİ'lerin sitesini ücretsiz check-up yapar.
    """
    result = InfraAnalyzer.full_analysis(req.url)
    
    return {
        "status": "success" if "error" not in result else "partial",
        "analysis": result,
        "module": "05_infra_guard",
        "target_audience": "KOBİ'ler ve küçük işletmeler",
        "value_proposition": "Büyük şirketlerin siber güvenlik ekipleri var, sizin Aegis Nexus var",
        "next_steps": [
            "Düşük not alanları giderin",
            "SSL sertifikasını yenileyin" if result.get("ssl", {}).get("days_left", 100) < 30 else "SSL sağlam ✓",
            "Eksik güvenlik başlıklarını ekleyin" if result.get("redirects", {}).get("missing_security_headers") else "Başlıklar tam ✓",
        ]
    }


@router.post("/ssl-check")
def check_ssl_certificate(req: SSLCheckRequest):
    """SSL sertifikası detaylı analizi"""
    result = InfraAnalyzer.check_ssl(req.domain)
    
    return {
        "status": "success" if result.get("valid") else "error",
        "domain": req.domain,
        "ssl_info": result,
        "module": "05_infra_guard",
        "urgency": "CRITICAL" if not result.get("valid") else "HIGH" if result.get("days_left", 100) < 7 else "MEDIUM" if result.get("days_left", 100) < 30 else "LOW",
    }


@router.post("/port-scan")
def scan_ports(req: PortScanRequest):
    """Port taraması - Temel güvenlik kontrolü"""
    ports = req.ports or [80, 443, 8080, 8443]
    results = InfraAnalyzer.scan_ports(req.domain, ports)
    
    open_ports = [r for r in results if r.get("open")]
    high_risk_ports = [r for r in results if r.get("risk") == "HIGH" and r.get("open")]
    
    return {
        "status": "success",
        "domain": req.domain,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "high_risk_open": high_risk_ports,
        "all_results": results,
        "module": "05_infra_guard",
        "warning": "High risk ports (FTP, RDP, Telnet) should be closed or restricted" if high_risk_ports else "Port configuration looks good",
    }


@router.get("/security-headers")
def get_security_headers_info():
    """Güvenlik başlıkları referansı"""
    return {
        "critical_headers": {
            "Strict-Transport-Security": "HTTPS zorlaması - Man-in-the-middle koruma",
            "Content-Security-Policy": "XSS ve injection saldırılarına karşı koruma",
            "X-Frame-Options": "Clickjacking saldırılarına karşı koruma",
            "X-Content-Type-Options": "MIME type sniffing engelleme",
        },
        "recommended_headers": {
            "Referrer-Policy": "Referrer bilgisi kontrolü",
            "Permissions-Policy": "Browser özellikleri kısıtlama",
        },
        "module": "05_infra_guard",
        "implementation_note": "Bu başlıklar nginx/Apache config veya app seviyesinde eklenir",
    }


@router.get("/stats")
def get_infra_stats():
    """Altyapı analizi modülü istatistikleri"""
    return {
        "ssl_ports_checked": [443, 8443],
        "common_ports": InfraAnalyzer.COMMON_PORTS,
        "security_headers_tracked": len(InfraAnalyzer.SECURITY_HEADERS),
        "grading_system": "A (90-100), B (70-89), C (50-69), D (30-49), F (0-29)",
        "module": "05_infra_guard",
        "social_impact": "KOBİ'leri fidye yazılımı iflaslarından korur - Ücretsiz siber güvenlik denetçisi",
    }
