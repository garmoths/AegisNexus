"""
PhishTank Canlı TI Entegrasyon Testi
======================================
PhishTank'tan onaylı phishing URL'lerini çekip run_threat_intelligence ile
test eder. Bayesian scoring (Faz A/B/C) çıktısını analiz eder.

Kullanım:
    python3 tests/phishtank_live_test.py [--count 10] [--delay 4]

Ortam değişkenleri (.env):
    PHISHTANK_API_KEY  — opsiyonel, public feed için gerekli değil
    VT_API_KEY, GSB_API_KEY, ABUSEIPDB_API_KEY — canlı TI için zorunlu
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

# Proje kökünü Python path'e ekle
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from modules.phishing_detector.threat_intel import run_threat_intelligence

# ── Renkler (ANSI) ────────────────────────────────────────────────────────────
R  = "\033[91m"   # kırmızı
Y  = "\033[93m"   # sarı
G  = "\033[92m"   # yeşil
B  = "\033[94m"   # mavi
W  = "\033[0m"    # reset
BOLD = "\033[1m"


def _color_prob(p: float) -> str:
    s = f"{p:.3f}"
    if p >= 0.70:
        return f"{R}{BOLD}{s}{W}"
    if p >= 0.40:
        return f"{Y}{s}{W}"
    return f"{G}{s}{W}"


def _color_risk(level: str) -> str:
    l = (level or "").lower()
    if "critical" in l or "yüksek" in l or "high" in l:
        return f"{R}{BOLD}{level}{W}"
    if "medium" in l or "orta" in l:
        return f"{Y}{level}{W}"
    return f"{G}{level}{W}"


# ── PhishTank URL çekimi ──────────────────────────────────────────────────────

def fetch_phishtank_urls(count: int = 10) -> list[str]:
    """
    PhishTank URL listesi (kullanıcı tarafından sağlandı).
    """
    urls = [
        "https://ussef-amragaie.bubbleapps.io/version-test",
        "https://ussef-amragaie.bubbleapps.io/version-test/index?debug_mode=true",
        "https://securesparkeze.online",
        "https://flowcode.com/p/ejDzFbtvQ2?fc=0",
        "https://augustinadvocatuur.nl/wp-admin/includes/rd/dkb",
        "https://ailoscancelamento.app.br/",
        "http://meritkingtry1.com",
        "https://missionbharat.org/wp-blog/",
        "https://govbr.irpf-receitafederal.com/home.php",
        "https://pedagiodigital-mu.vercel.app/",
        "https://www.seniorshoppertip.com/mail/campaigns/gr233azn7m435/track-url",
        "https://comfortachados.shop/",
        "http://www.comfortachados.shop",
        "http://compensations-aave.com/",
        "https://giris.inter-bahis-gel.vip/",
        "https://giris.inter-bahis-mobil.vip/",
        "https://m.interbahis-bahisadres.icu/",
        "https://m.interbahis-affkoruma.icu/",
    ]
    print(f"{G}[+] {len(urls)} URL alındı (PhishTank).{W}\n")
    return urls[:count]


def _hardcoded_samples() -> list[str]:
    """PhishTank'tan manuel seçilmiş bilinen phishing URL'leri (fallback)."""
    return [
        "http://secure-paypal-verification.com/login",
        "http://appleid-icloud-security.com/verify",
        "http://microsoft-account-unlock.info/login.html",
        "http://amazon-security-alert.net/signin",
        "http://halifax-online-banking.com/auth",
        "http://netflix-billing-update.com/account",
        "http://dhl-package-delivery-info.com/track",
        "http://chase-secure-login.net/signin",
        "http://instagram-support-verify.com/account",
        "http://wellsfargo-secure.com/login",
    ]


# ── Sonuç yazdırıcı ──────────────────────────────────────────────────────────

def _bar(p: float, width: int = 20) -> str:
    filled = int(p * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar


def print_result(idx: int, url: str, result: dict) -> dict:
    ti = result.get("threat_intel") or result
    sd = ti.get("scoring_details") or result.get("scoring_details") or {}
    crp = ti.get("combined_risk_probability") or result.get("combined_risk_probability") or 0.0
    pre = sd.get("pre_boost_probability", crp)
    boosts = sd.get("correlation_boosts") or []
    events = sd.get("penalty_events") or []
    legacy = sd.get("legacy_penalty") or ti.get("total_penalty") or result.get("total_penalty") or 0
    risk_level = ti.get("risk_level") or result.get("risk_level") or "—"

    print(f"\n{'─'*70}")
    print(f"{BOLD}[{idx}] {url[:70]}{W}")
    print(f"  Risk Level       : {_color_risk(risk_level)}")
    print(f"  Pre-boost prob   : {_color_prob(pre)}  {_bar(pre)}")
    print(f"  Combined prob    : {_color_prob(crp)}  {_bar(crp)}")
    print(f"  Legacy penalty   : {legacy}")
    if boosts:
        print(f"  Correlation boost:")
        for b in boosts:
            print(f"    ✦ {b['rule']:45s}  ×{b['factor']}  {b['before']:.3f}→{b['after']:.3f}")
    if events:
        print(f"  Penalty events ({len(events)}):")
        for ev in events[:6]:
            wp = ev.get("weighted_probability", 0)
            bp = ev.get("probability", 0)
            key = ev.get("source_key", "?")[:30]
            reason = (ev.get("reason") or "")[:50]
            print(f"    • {key:<32s}  base={bp:.3f}  wt={wp:.3f}  {reason}")
    return {
        "url": url,
        "combined_risk_probability": crp,
        "pre_boost_probability": pre,
        "risk_level": risk_level,
        "legacy_penalty": legacy,
        "boost_rules": [b["rule"] for b in boosts],
        "event_sources": [e.get("source_key") for e in events],
    }


# ── Özet & tuning önerileri ──────────────────────────────────────────────────

def print_summary(records: list[dict]) -> None:
    if not records:
        print(f"\n{Y}Sonuç yok.{W}")
        return

    probs = [r["combined_risk_probability"] for r in records]
    n = len(probs)
    above_90 = sum(1 for p in probs if p >= 0.90)
    above_70 = sum(1 for p in probs if p >= 0.70)
    above_50 = sum(1 for p in probs if p >= 0.50)
    above_30 = sum(1 for p in probs if p >= 0.30)
    below_30 = sum(1 for p in probs if p < 0.30)
    avg_prob = sum(probs) / n

    # En çok tetiklenen kaynaklar
    source_counter: dict[str, int] = {}
    for r in records:
        for src in r.get("event_sources") or []:
            if src:
                source_counter[src] = source_counter.get(src, 0) + 1

    boost_counter: dict[str, int] = {}
    for r in records:
        for rule in r.get("boost_rules") or []:
            boost_counter[rule] = boost_counter.get(rule, 0) + 1

    print(f"\n{'═'*70}")
    print(f"{BOLD}ÖZET  ({n} URL test edildi){W}")
    print(f"{'═'*70}")
    print(f"  Ortalama combined prob : {_color_prob(avg_prob)}")
    print(f"  ≥ 0.90 (Kritik)        : {R}{above_90}/{n}{W}")
    print(f"  ≥ 0.70 (Yüksek)        : {Y}{above_70}/{n}{W}")
    print(f"  ≥ 0.50 (Orta)          : {above_50}/{n}")
    print(f"  ≥ 0.30 (Düşük)         : {above_30}/{n}")
    print(f"  < 0.30 (Tespit edilemedi): {G}{below_30}/{n}{W}")

    if source_counter:
        print(f"\n  En çok tetiklenen kaynaklar:")
        for src, cnt in sorted(source_counter.items(), key=lambda x: -x[1])[:8]:
            print(f"    {src:<35s}  {cnt} URL")

    if boost_counter:
        print(f"\n  Tetiklenen boost kuralları:")
        for rule, cnt in sorted(boost_counter.items(), key=lambda x: -x[1]):
            print(f"    {rule:<50s}  {cnt}×")

    # Tuning önerileri
    print(f"\n{BOLD}TUNING ÖNERİLERİ:{W}")
    if below_30 > 0:
        low_urls = [r["url"] for r in records if r["combined_risk_probability"] < 0.30]
        print(f"  {R}⚠ {below_30} URL'de combined_risk < 0.30 — bunlar kaçırıldı:{W}")
        for u in low_urls:
            print(f"      {u}")
        print(f"     → Önerim: SOURCE_WEIGHTS'i artır veya to_probability eşiğini düşür")
    if avg_prob < 0.50:
        print(f"  {Y}⚠ Ortalama prob {avg_prob:.2f} — genel skor düşük.{W}")
        print(f"     → Önerim: DEFAULT_SOURCE_WEIGHT değerini 0.35→0.45 dene")
    if above_70 == n:
        print(f"  {G}✓ Tüm URL'ler ≥ 0.70 — scoring başarılı görünüyor.{W}")
    if not boost_counter:
        print(f"  {Y}ℹ Hiçbir correlation boost tetiklenmedi.{W}")
        print(f"     → Önerim: suspicious_tld/credential_form sinyal eşiklerini gözden geçir")


# ── Ana akış ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishTank Canlı TI Testi")
    parser.add_argument("--count", type=int, default=8, help="Test edilecek URL sayısı (varsayılan: 8)")
    parser.add_argument("--delay", type=float, default=4.0, help="URL'ler arası bekleme süresi (s)")
    parser.add_argument("--out", type=str, default="", help="JSON çıktı dosyası (opsiyonel)")
    args = parser.parse_args()

    print(f"{BOLD}{'═'*70}{W}")
    print(f"{BOLD}  PhishTank Canlı TI Entegrasyon Testi — AegisNexus{W}")
    print(f"{BOLD}{'═'*70}{W}")
    print(f"  Tarih    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  URL sayısı: {args.count}  |  Bekleme: {args.delay}s")

    # API key kontrol
    missing = [k for k in ("VT_API_KEY", "GSB_API_KEY") if not os.getenv(k)]
    if missing:
        print(f"\n{Y}[!] Eksik API key'ler: {', '.join(missing)}{W}")
        print(f"    TI sonuçları eksik olabilir.\n")

    urls = fetch_phishtank_urls(args.count)
    if not urls:
        print(f"{R}URL bulunamadı, çıkılıyor.{W}")
        sys.exit(1)

    records: list[dict] = []
    for idx, url in enumerate(urls, 1):
        print(f"\n{B}[{idx}/{len(urls)}] Analiz ediliyor: {url[:80]}{W}")
        try:
            result = run_threat_intelligence(url)
            rec = print_result(idx, url, result)
            records.append(rec)
        except Exception as exc:
            print(f"  {R}HATA: {exc}{W}")
            records.append({"url": url, "combined_risk_probability": 0.0,
                            "pre_boost_probability": 0.0, "risk_level": "ERROR",
                            "legacy_penalty": 0, "boost_rules": [], "event_sources": []})

        if idx < len(urls):
            print(f"  {B}...{args.delay}s bekleniyor (rate limit){W}")
            time.sleep(args.delay)

    print_summary(records)

    # JSON kaydet
    out_path = args.out or f"tests/phishtank_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "results": records}, f,
                  ensure_ascii=False, indent=2)
    print(f"\n{G}[✓] Sonuçlar kaydedildi: {out_path}{W}\n")


if __name__ == "__main__":
    main()
