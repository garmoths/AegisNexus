"""Altyapı analizi: SSL, yönlendirme, domain yapısı, yaygın portlar (kendi domain'iniz için)."""
from __future__ import annotations

import socket
from urllib.parse import urlparse

import requests

from app.scanner import analyze_domain_structure, check_redirect_chain, check_ssl_certificate


def _host_from_input(raw: str) -> tuple[str, str]:
    u = raw.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    p = urlparse(u)
    host = (p.netloc or p.path.split("/")[0]).replace("www.", "")
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return u, host


def _probe_tcp(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for fam, _, _, _, sockaddr in infos[:3]:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(sockaddr)
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


def build_infra_report(target: str, check_http: bool = True) -> dict:
    check_url, domain = _host_from_input(target)
    if not domain:
        return {"ok": False, "error": "Geçersiz adres"}

    ssl_info = check_ssl_certificate(domain)
    redirect_info = {"redirect_count": 0, "final_url": check_url, "suspicious": False}
    if check_http:
        try:
            redirect_info = check_redirect_chain(check_url)
        except Exception:
            pass

    findings, penalty = analyze_domain_structure(domain, target)

    common_ports = [80, 443, 8080, 8443, 22]
    ports = []
    for port in common_ports:
        ports.append({"port": port, "open": _probe_tcp(domain, port)})

    https_ok = ssl_info.get("valid") and not ssl_info.get("expired")
    score = 100
    if not https_ok:
        score -= 35
    if redirect_info.get("suspicious"):
        score -= 15
    if ssl_info.get("valid") and 0 <= ssl_info.get("days_left", 0) < 14:
        score -= 10
    score -= min(30, penalty // 2)
    score = max(0, min(100, score))

    if score >= 75:
        grade = "İyi"
    elif score >= 50:
        grade = "Orta"
    else:
        grade = "Zayıf — inceleme önerilir"

    return {
        "ok": True,
        "input": target.strip(),
        "domain": domain,
        "ssl": ssl_info,
        "redirects": redirect_info,
        "domain_structure": {"findings": findings, "raw_penalty": penalty},
        "ports_checked": ports,
        "summary": {
            "score": score,
            "grade": grade,
            "notes": [
                "Sadece sizin kontrol ettiğiniz hostname için bağlantı denemesi yapılır.",
                "Başkasının sistemine izinsiz agresif tarama yapmayın.",
            ],
        },
    }
