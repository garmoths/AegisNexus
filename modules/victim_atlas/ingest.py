from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape
from typing import Any, Dict, Iterable, List, Optional
from xml.etree import ElementTree

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .database import (
    add_case_evidence,
    finish_ingest_run,
    mark_source_error,
    mark_source_success,
    prune_hot_set,
    start_ingest_run,
    upsert_case,
    upsert_raw_document,
    upsert_source,
)


@dataclass(frozen=True)
class SourceConfig:
    name: str
    url: str
    source_type: str
    trust_tier: str
    enabled_by_default: bool = True


TRUSTED_SOURCES: List[SourceConfig] = [
    SourceConfig("cisa_advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "rss", "tier1", enabled_by_default=False),
    SourceConfig("krebsonsecurity", "https://krebsonsecurity.com/feed/", "rss", "tier1"),
    SourceConfig("bleepingcomputer", "https://www.bleepingcomputer.com/feed/", "rss", "tier1"),
    SourceConfig("proofpoint_blog", "https://www.proofpoint.com/us/rss.xml", "rss", "tier1"),
    SourceConfig(
        "google_news_tr_dolandiricilik",
        "https://news.google.com/rss/search?q=dolandiricilik+banka+uygulamasi+phishing&hl=tr&gl=TR&ceid=TR:tr",
        "rss",
        "tier2",
    ),
    SourceConfig(
        "google_news_tr_sahte_uygulama",
        "https://news.google.com/rss/search?q=sahte+banka+uygulamasi+magduriyet&hl=tr&gl=TR&ceid=TR:tr",
        "rss",
        "tier2",
    ),
    SourceConfig("reddit_scam", "https://www.reddit.com/r/Scams/.rss", "rss", "tier2"),
]

ATTACK_METHOD_KEYWORDS: Dict[str, Iterable[str]] = {
    "sahte_mobil_uygulama": (
        "fake app",
        "fake application",
        "sahte uygulama",
        "klon uygulama",
        "apk",
        "play store",
        "app store",
        "mobile app",
        "mobil uygulama",
    ),
    "banka_taklit": (
        "banka taklit",
        "bank clone",
        "bank impersonation",
        "bank alert",
        "hesabiniz bloke",
        "hesabiniz donduruldu",
    ),
    "smishing": ("sms", "text message", "mesaj", "short code"),
    "vishing": ("call", "phone", "voice", "arama", "telefon"),
    "social_engineering": ("impersonat", "spoof", "social engineering", "ikna", "taklit"),
    "phishing": ("phish", "credential", "login page", "oltalama", "fake login", "konto"),
    "malware_assisted": ("malware", "trojan", "stealer", "keylogger", "payload"),
}

LOSS_TYPE_KEYWORDS: Dict[str, Iterable[str]] = {
    "bank_account": (
        "bank",
        "iban",
        "transfer",
        "wire",
        "credit card",
        "payment",
        "hesap bosalt",
        "kredi karti",
        "mobil bankacilik",
    ),
    "social_media": ("instagram", "facebook", "x account", "social account", "tiktok", "hesap calindi"),
    "ecommerce": ("marketplace", "cargo", "delivery", "order", "shipping", "sahte kargo"),
    "corporate_account": ("m365", "office365", "slack", "vpn", "corporate", "enterprise"),
    "crypto_wallet": ("wallet", "seed phrase", "crypto", "usdt", "bitcoin"),
    "device_compromise": ("endpoint", "device", "ransomware", "implant", "backdoor"),
}

PLATFORM_KEYWORDS: Dict[str, Iterable[str]] = {
    "instagram": ("instagram",),
    "whatsapp": ("whatsapp",),
    "telegram": ("telegram",),
    "microsoft365": ("m365", "office365", "outlook"),
    "banking": ("bank", "credit card", "payment", "mobil bankacilik", "internet sube"),
    "ecommerce": ("cargo", "delivery", "order", "marketplace", "shop"),
    "crypto": ("wallet", "crypto", "bitcoin", "usdt"),
    "sikayet_platformu": ("sikayet", "magdur", "dolandirildim"),
}

DEFENSE_STEPS: Dict[str, List[str]] = {
    "sahte_mobil_uygulama": [
        "Uygulamayi sadece resmi store'dan ve resmi yayinci adindan indir.",
        "Yukledikten sonra uygulama izinlerini (SMS, erisilebilirlik, ekran) kontrol et.",
        "Banka girisini uygulama linki yerine bankanin resmi uygulamasindan manuel ac.",
        "Supheli APK veya yan yukleme dosyalarini cihazdan sil ve antivir taramasi yap.",
    ],
    "banka_taklit": [
        "Bankadan geldigi iddia edilen arama/SMS icin resmi cagrı merkezini kendin ara.",
        "Hesap bloke/hesap kapandi bahanesiyle gelen linklerden giris yapma.",
        "Kart ve hesap hareketlerine anlik bildirim ac, supheli islemi aninda bankaya bildir.",
    ],
    "smishing": [
        "SMS icindeki linke tiklamadan once resmi uygulamadan kontrol et.",
        "Gelen mesaji kurumun resmi numarasindan dogrula.",
        "2FA acik degilse hemen etkinlestir.",
    ],
    "vishing": [
        "Telefonda kod veya sifre bilgisi paylasma.",
        "Aramayi kapatip resmi cagri merkezini kendin ara.",
        "Supheli gorusmeyi olay kaydi olarak raporla.",
    ],
    "social_engineering": [
        "Acil baski olusturan taleplere dur-kontrol uygula.",
        "Kanal dogrulamasi yapmadan para/islem onayi verme.",
        "Kritik islemlerde cift onay kuralini zorunlu tut.",
    ],
    "malware_assisted": [
        "Supheli dosyalari sandbox/antivirus ile taramadan acma.",
        "Cihaz ve tarayici yamalarini guncel tut.",
        "Yetkisiz process veya eklenti tespitinde cihaz izole et.",
    ],
    "phishing": [
        "Giris linki yerine dogrudan resmi siteye git.",
        "Parola yoneticisi kullan ve benzersiz sifre belirle.",
        "MFA/2FA aktif tut ve oturum hareketlerini duzenli izle.",
    ],
}

CRITICAL_WARNING: Dict[str, str] = {
    "sahte_mobil_uygulama": "Sahte banka uygulamalari cihazdan izin alarak hesap ele gecirme yapabilir.",
    "banka_taklit": "Banka adina gelen acil hesap uyarilarinda linke degil resmi uygulamaya gidin.",
    "smishing": "SMS ile gelen acil odeme/link mesajlarinda resmi kaynagi dogrulamadan tiklama.",
    "vishing": "Telefonla arayan kisiye kod veya parola bilgisi verme.",
    "social_engineering": "Acil baski ve korku yaratan talepler en kritik sosyal muhendislik isaretidir.",
    "malware_assisted": "Supheli dosya ve eklentiler hesap ele gecirme zincirini baslatabilir.",
    "phishing": "Sadece resmi alana manuel gidisle oturum ac; e-posta linkinden giris yapma.",
}

ATTACK_METHOD_TR: Dict[str, str] = {
    "phishing": "Oltalama",
    "smishing": "SMS Oltalamasi",
    "vishing": "Telefon Dolandiriciligi",
    "social_engineering": "Sosyal Muhendislik",
    "malware_assisted": "Zararli Yazilim Destekli Saldiri",
    "sahte_mobil_uygulama": "Sahte Mobil Uygulama Tuzagi",
    "banka_taklit": "Banka Taklit Senaryosu",
}

LOSS_TYPE_TR: Dict[str, str] = {
    "bank_account": "Banka Hesabi Magduriyeti",
    "social_media": "Sosyal Medya Hesap Magduriyeti",
    "ecommerce": "E-Ticaret Magduriyeti",
    "corporate_account": "Kurumsal Hesap Magduriyeti",
    "crypto_wallet": "Kripto Cuzdan Magduriyeti",
    "device_compromise": "Cihaz Ele Gecirme Magduriyeti",
}

PLATFORM_TR: Dict[str, str] = {
    "banking": "Bankacilik",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "microsoft365": "Microsoft 365",
    "ecommerce": "E-Ticaret",
    "crypto": "Kripto",
    "sikayet_platformu": "Sikayet Platformu",
    "general": "Genel",
}

GENERIC_DEFENSE_STEPS = [
    "Resmi kurum/marka baglantisini tarayicidan kendin yazarak ac.",
    "2FA/MFA aktif degilse hemen ac ve tek kullanimlik kodlarini paylasma.",
    "Supheli olayda banka/kurum destek hattina resmi kanaldan kayit olustur.",
]


def _http_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "AegisVictimAtlas/1.0"})
    return session


def _clean_text(value: str) -> str:
    text = unescape(value or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _first_non_empty(values: Iterable[Optional[str]], default: str = "") -> str:
    for value in values:
        normalized = _clean_text(value or "")
        if normalized:
            return normalized
    return default


def _find_text_anywhere(node: ElementTree.Element, tags: Iterable[str]) -> str:
    lower_tags = {t.lower() for t in tags}
    for child in node.iter():
        tag = child.tag.split("}")[-1].lower()
        if tag in lower_tags and child.text:
            cleaned = _clean_text(child.text)
            if cleaned:
                return cleaned
    return ""


def _fetch_rss_documents(session: requests.Session, source: SourceConfig, max_items: int) -> List[Dict[str, str]]:
    response = session.get(source.url, timeout=40)
    response.raise_for_status()
    root = ElementTree.fromstring(response.content)

    docs: List[Dict[str, str]] = []
    lang = "tr" if "_tr_" in source.name or "sikayet" in source.name else "en"
    entries = list(root.iterfind(".//item")) or list(root.iterfind(".//entry"))
    for entry in entries[:max_items]:
        title = _first_non_empty([_find_text_anywhere(entry, ("title",))], default="Untitled alert")
        link = _find_text_anywhere(entry, ("link",))
        if not link:
            for child in entry.iter():
                if child.tag.split("}")[-1].lower() == "link":
                    link = (child.attrib.get("href") or "").strip()
                    if link:
                        break
        summary = _first_non_empty(
            [
                _find_text_anywhere(entry, ("description", "summary", "content")),
                title,
            ],
            default=title,
        )
        published = _first_non_empty([_find_text_anywhere(entry, ("pubdate", "updated", "published"))])
        guid = _first_non_empty([_find_text_anywhere(entry, ("guid", "id")), link, title], default=title)
        docs.append(
            {
                "external_id": guid[:255],
                "url": link or source.url,
                "title": title[:300],
                "published_at": published,
                "raw_text": summary[:4000],
                "lang": lang,
            }
        )
    return docs


def _load_extra_sources_from_env() -> List[SourceConfig]:
    extra: List[SourceConfig] = []
    sikayetvar_rss = os.getenv("VICTIM_ATLAS_SIKAYETVAR_RSS_URL", "").strip()
    if sikayetvar_rss:
        extra.append(
            SourceConfig(
                "sikayetvar_rss",
                sikayetvar_rss,
                "rss",
                os.getenv("VICTIM_ATLAS_SIKAYETVAR_TRUST_TIER", "tier2").strip() or "tier2",
                enabled_by_default=True,
            )
        )

    tr_cert_feed = os.getenv("VICTIM_ATLAS_TR_CERT_FEED_URL", "").strip()
    if tr_cert_feed:
        extra.append(
            SourceConfig(
                "tr_cert_feed",
                tr_cert_feed,
                "rss",
                os.getenv("VICTIM_ATLAS_TR_CERT_TRUST_TIER", "tier1").strip() or "tier1",
                enabled_by_default=True,
            )
        )
    return extra


def _source_enabled(name: str, default: bool) -> bool:
    env_name = f"VICTIM_ATLAS_SOURCE_{name.upper()}"
    raw = os.getenv(env_name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def get_enabled_sources() -> List[SourceConfig]:
    configured_sources = [*TRUSTED_SOURCES, *_load_extra_sources_from_env()]
    enabled = []
    for source in configured_sources:
        if _source_enabled(source.name, source.enabled_by_default):
            enabled.append(source)
    return enabled


def _pick_label(blob: str, mapping: Dict[str, Iterable[str]], fallback: str) -> str:
    lowered = blob.lower()
    for label, keywords in mapping.items():
        if any(keyword in lowered for keyword in keywords):
            return label
    return fallback


def _tr_method(value: str) -> str:
    return ATTACK_METHOD_TR.get(value, value)


def _tr_loss(value: str) -> str:
    return LOSS_TYPE_TR.get(value, value)


def _tr_platform(value: str) -> str:
    return PLATFORM_TR.get(value, value)


def _is_probably_turkish(text: str) -> bool:
    lowered = text.lower()
    tr_keywords = (
        "dolandir",
        "magdur",
        "banka",
        "hesap",
        "sahte",
        "uygulama",
        "sms",
        "kargo",
        "odeme",
        "sifre",
    )
    return any(keyword in lowered for keyword in tr_keywords)


def _build_case_title(document_title: str, attack_method: str, loss_type: str, target_platform: str) -> str:
    attack_tr = _tr_method(attack_method)
    loss_tr = _tr_loss(loss_type)
    platform_tr = _tr_platform(target_platform)
    if _is_probably_turkish(document_title):
        base = document_title
    else:
        base = f"{platform_tr} hedefli {attack_tr}"
    return f"{base} - {loss_tr}"


def _build_summary(document_title: str, raw_text: str, attack_method: str, loss_type: str, target_platform: str) -> str:
    attack_tr = _tr_method(attack_method)
    loss_tr = _tr_loss(loss_type)
    platform_tr = _tr_platform(target_platform)
    evidence = (raw_text or document_title or "").strip()
    evidence_short = evidence[:220]
    return (
        f"Bu vaka, {platform_tr} alaninda {attack_tr} yontemiyle gelisen bir {loss_tr.lower()} senaryosudur. "
        f"Kullanici genellikle sahte baglanti, sahte uygulama veya taklit iletisime yonlendirilir. "
        f"Olay ozeti: {evidence_short}"
    )


def _build_defense_steps(attack_method: str, loss_type: str) -> List[str]:
    base_steps = list(DEFENSE_STEPS.get(attack_method, DEFENSE_STEPS["phishing"]))
    if loss_type == "bank_account":
        base_steps.append("Hesap hareketleri icin anlik bildirim ac; supheli transferde bankadan kart/hesap dondurma talep et.")
    elif loss_type == "social_media":
        base_steps.append("Hesap kurtarma e-postasi ve telefonunu guncelle; bilinmeyen cihaz oturumlarini kapat.")
    elif loss_type == "ecommerce":
        base_steps.append("Satici ve odeme sayfasinin alan adini resmi site ile karsilastir; sanal kart kullan.")

    for step in GENERIC_DEFENSE_STEPS:
        if step not in base_steps:
            base_steps.append(step)
    return base_steps[:7]


def _build_slug(title: str, attack_method: str, loss_type: str, target_platform: str, seed: str) -> str:
    tokens = re.findall(r"[a-z0-9]{4,}", title.lower())
    base = "-".join(tokens[:6]) if tokens else "incident"
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10]
    return f"{attack_method}-{loss_type}-{target_platform}-{base}-{digest}"[:180]


def extract_case_fields(document: Dict[str, str], trust_tier: str) -> Dict[str, Any]:
    title = _clean_text(document.get("title", "Unknown incident"))
    raw_text = _clean_text(document.get("raw_text", ""))
    blob = f"{title} {raw_text}"

    attack_method = _pick_label(blob, ATTACK_METHOD_KEYWORDS, "phishing")
    loss_type = _pick_label(blob, LOSS_TYPE_KEYWORDS, "social_media")
    target_platform = _pick_label(blob, PLATFORM_KEYWORDS, "general")

    confidence = 45
    if attack_method != "phishing":
        confidence += 10
    if loss_type != "social_media":
        confidence += 10
    if target_platform != "general":
        confidence += 10
    if trust_tier == "tier1":
        confidence += 20
    confidence = max(0, min(100, confidence))

    severity = 35
    if any(k in blob.lower() for k in ("credential", "password", "account takeover", "bank", "wallet", "2fa")):
        severity += 20
    if any(k in blob.lower() for k in ("ransomware", "financial", "payment", "wire", "crypto")):
        severity += 20
    severity = max(0, min(100, severity))

    first_seen = datetime.now(timezone.utc).isoformat()
    incident_start = document.get("published_at") or first_seen
    incident_end = first_seen
    seed = f"{document.get('url','')}-{title}-{attack_method}-{loss_type}-{target_platform}"

    generated_title = _build_case_title(title, attack_method, loss_type, target_platform)
    summary = _build_summary(title, raw_text, attack_method, loss_type, target_platform)
    defense_steps = _build_defense_steps(attack_method, loss_type)
    warning = CRITICAL_WARNING.get(attack_method, CRITICAL_WARNING["phishing"])

    return {
        "case_slug": _build_slug(generated_title, attack_method, loss_type, target_platform, seed),
        "case_title": generated_title[:240],
        "incident_period_start": incident_start[:64],
        "incident_period_end": incident_end[:64],
        "attack_method": attack_method,
        "loss_type": loss_type,
        "target_platform": target_platform,
        "critical_warning": warning,
        "narrative_summary": summary,
        "defense_steps": defense_steps,
        "confidence_score": confidence,
        "severity_score": severity,
        "first_seen": first_seen,
        "last_seen": first_seen,
    }


def run_daily_pipeline(max_items_per_source: int = 120) -> Dict[str, Any]:
    run_id = start_ingest_run()
    errors: Dict[str, str] = {}
    documents_fetched = 0
    cases_created = 0
    cases_updated = 0
    session = _http_session()

    try:
        for source in get_enabled_sources():
            source_id = upsert_source(
                name=source.name,
                base_url=source.url,
                trust_tier=source.trust_tier,
                enabled=True,
            )
            try:
                if source.source_type != "rss":
                    raise ValueError(f"unsupported source type: {source.source_type}")
                documents = _fetch_rss_documents(session, source, max_items=max_items_per_source)
                source_new_count = 0
                for doc in documents:
                    doc_hash = hashlib.sha1(
                        f"{doc['url']}|{doc['title']}|{doc['raw_text']}".encode("utf-8")
                    ).hexdigest()
                    raw_document_id, inserted = upsert_raw_document(
                        source_id=source_id,
                        external_id=doc["external_id"],
                        url=doc["url"],
                        title=doc["title"],
                        published_at=doc.get("published_at"),
                        raw_text=doc["raw_text"],
                        lang=doc.get("lang", "unknown"),
                        doc_hash=doc_hash,
                    )
                    if not inserted:
                        continue

                    source_new_count += 1
                    case = extract_case_fields(doc, trust_tier=source.trust_tier)
                    case_id, created = upsert_case(case)
                    add_case_evidence(
                        case_id=case_id,
                        raw_document_id=int(raw_document_id or 0),
                        snippet=doc["raw_text"][:240],
                        evidence_weight=1.0 if source.trust_tier == "tier1" else 0.7,
                    )
                    if created:
                        cases_created += 1
                    else:
                        cases_updated += 1
                documents_fetched += source_new_count
                mark_source_success(source_id)
            except Exception as exc:
                errors[source.name] = str(exc)
                mark_source_error(source_id, str(exc))

        hot_limit = int(os.getenv("VICTIM_ATLAS_HOT_SET_LIMIT", "1000"))
        hot_state = prune_hot_set(limit=hot_limit)
        finish_ingest_run(
            run_id=run_id,
            status="success",
            documents_fetched=documents_fetched,
            cases_created=cases_created,
            cases_updated=cases_updated,
            errors=errors,
        )
        return {
            "status": "success",
            "run_id": run_id,
            "documents_fetched": documents_fetched,
            "cases_created": cases_created,
            "cases_updated": cases_updated,
            "errors": errors,
            "hot_set": hot_state,
        }
    except Exception as exc:
        finish_ingest_run(
            run_id=run_id,
            status="failed",
            documents_fetched=documents_fetched,
            cases_created=cases_created,
            cases_updated=cases_updated,
            errors={**errors, "pipeline": str(exc)},
        )
        raise
    finally:
        session.close()


def run_enrichment_pass(limit: int = 500) -> Dict[str, Any]:
    # Current enrichment is deterministic during ingest. Keep a distinct task
    # contract to allow future LLM-based expansion without changing scheduler wiring.
    return {"status": "success", "updated_cases": 0, "limit": limit}


def run_hotset_maintenance() -> Dict[str, Any]:
    hot_limit = int(os.getenv("VICTIM_ATLAS_HOT_SET_LIMIT", "1000"))
    result = prune_hot_set(limit=hot_limit)
    return {"status": "success", **result}
