from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
import unicodedata
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .database import (
    add_case_evidence,
    finish_ingest_run,
    sync_source_registry,
    mark_source_error,
    mark_source_success,
    prune_hot_set,
    find_similar_case_id,
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
    SourceConfig("aa_guncel", "https://www.aa.com.tr/tr/rss/default?cat=guncel", "rss", "tier1"),
    SourceConfig("trt_haber_guncel", "https://www.trthaber.com/sondakika_articles.rss", "rss", "tier1"),
    SourceConfig("ntv_gundem", "https://www.ntv.com.tr/gundem.rss", "rss", "tier1"),
    SourceConfig("haberturk_gundem", "https://www.haberturk.com/rss/gundem.xml", "rss", "tier1"),
    SourceConfig("hurriyet_gundem", "https://www.hurriyet.com.tr/rss/gundem", "rss", "tier1"),
    SourceConfig("milliyet_gundem", "https://www.milliyet.com.tr/rss/rssNew/gundemRss.xml", "rss", "tier1"),
    SourceConfig("cumhuriyet_turkiye", "https://www.cumhuriyet.com.tr/rss/turkiye.xml", "rss", "tier1", enabled_by_default=False),
    SourceConfig("sozcu_gundem", "https://www.sozcu.com.tr/feeds-rss-category-gundem", "rss", "tier1"),
]

ATTACK_METHOD_KEYWORDS: Dict[str, Iterable[str]] = {
    "sahte_mobil_uygulama": (
        "fake app",
        "fake application",
        "sahte uygulama",
        "sahte mobil",
        "sahte banka uygulamasi",
        "sahte banka uygulaması",
        "klon uygulama",
        "apk",
        "play store",
        "app store",
        "mobile app",
        "mobil uygulama",
    ),
    "banka_taklit": (
        "banka taklit",
        "banka gorevlisi",
        "banka görevlisi",
        "bankaci",
        "bankacı",
        "bank clone",
        "bank impersonation",
        "bank alert",
        "hesabiniz bloke",
        "hesabiniz donduruldu",
        "hesabınız bloke",
        "hesabınız donduruldu",
    ),
    "smishing": ("sms", "text message", "mesaj", "short code", "sahte kargo", "kargo mesaji", "kargo mesajı"),
    "vishing": ("call", "phone", "voice", "arama", "telefon", "telefonla arayip", "telefonla arayıp"),
    "social_engineering": ("impersonat", "spoof", "social engineering", "ikna", "taklit", "polis", "savci", "savcı"),
    "phishing": ("phish", "credential", "login page", "oltalama", "fake login", "sahte link", "sahte site", "hesap calindi", "hesap çalındı"),
    "malware_assisted": ("malware", "trojan", "stealer", "keylogger", "payload", "zararli yazilim", "zararlı yazılım"),
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
        "hesap boşalt",
        "kredi karti",
        "kredi kartı",
        "mobil bankacilik",
        "mobil bankacılık",
    ),
    "social_media": ("instagram", "facebook", "x account", "social account", "tiktok", "hesap calindi", "hesap çalındı"),
    "ecommerce": ("marketplace", "cargo", "delivery", "order", "shipping", "sahte kargo", "kapora", "alisveris", "alışveriş"),
    "corporate_account": ("m365", "office365", "slack", "vpn", "corporate", "enterprise"),
    "crypto_wallet": ("wallet", "seed phrase", "crypto", "usdt", "bitcoin"),
    "device_compromise": ("endpoint", "device", "ransomware", "implant", "backdoor"),
}

PLATFORM_KEYWORDS: Dict[str, Iterable[str]] = {
    "instagram": ("instagram",),
    "whatsapp": ("whatsapp",),
    "telegram": ("telegram",),
    "microsoft365": ("m365", "office365", "outlook"),
    "banking": ("bank", "credit card", "payment", "mobil bankacilik", "mobil bankacılık", "internet sube", "internet şube"),
    "ecommerce": ("cargo", "delivery", "order", "marketplace", "shop"),
    "crypto": ("wallet", "crypto", "bitcoin", "usdt"),
    "sikayet_platformu": ("sikayet", "magdur", "dolandirildim"),
}

FRAUD_RELEVANCE_KEYWORDS = (
    "dolandir", "dolandır", "magdur", "mağdur", "oltalama", "phishing", "sahte link", "sahte site",
    "sahte kargo", "sahte banka", "sahte uygulama", "telefon dolandir", "telefon dolandır",
    "internet dolandir", "internet dolandır", "banka dolandir", "banka dolandır", "hesap calindi",
    "hesap çalındı", "kredi karti", "kredi kartı", "iban", "kapora", "kripto dolandir", "kripto dolandır",
    "sms dolandir", "sms dolandır", "mobil bankacilik", "mobil bankacılık",
)

SOURCE_RELEVANCE_HINTS: Dict[str, Iterable[str]] = {
    "aa_guncel": ("siber", "oltalama", "dolandir", "dolandır", "sahte", "iban"),
    "trt_haber_guncel": ("siber", "dolandir", "dolandır", "oltalama", "sahte"),
    "ntv_gundem": ("dolandir", "dolandır", "siber", "kargo", "sahte"),
    "haberturk_gundem": ("dolandir", "dolandır", "santaj", "şantaj", "oltalama"),
    "hurriyet_gundem": ("dolandir", "dolandır", "santaj", "şantaj", "vip oda"),
    "milliyet_gundem": ("dolandir", "dolandır", "santaj", "şantaj", "oltalama"),
    "sozcu_gundem": ("dolandir", "dolandır", "siber", "sahte", "kargo"),
}

DEFENSE_STEPS: Dict[str, List[str]] = {
    "sahte_mobil_uygulama": [
        "Uygulamayı yalnızca resmi mağazadan ve doğrulanmış yayıncı adından indir.",
        "Yükledikten sonra uygulama izinlerini (SMS, erişilebilirlik, ekran) kontrol et.",
        "Banka girişini bağlantıdan değil, bankanın resmi uygulamasından manuel aç.",
        "Şüpheli APK veya yandan yükleme dosyalarını cihazdan sil ve antivirüs taraması yap.",
    ],
    "banka_taklit": [
        "Bankadan geldiği iddia edilen arama/SMS için resmi çağrı merkezini kendin ara.",
        "Hesap bloke/hesap kapandı bahanesiyle gelen bağlantılardan giriş yapma.",
        "Kart ve hesap hareketleri için anlık bildirim aç, şüpheli işlemi anında bankaya bildir.",
    ],
    "smishing": [
        "SMS içindeki bağlantıya tıklamadan önce resmi uygulamadan kontrol et.",
        "Gelen mesajı kurumun resmi numarasından doğrula.",
        "İki adımlı doğrulama açık değilse hemen etkinleştir.",
    ],
    "vishing": [
        "Telefonda doğrulama kodu veya şifre bilgisi paylaşma.",
        "Aramayı kapatıp resmi çağrı merkezini kendin ara.",
        "Şüpheli görüşmeyi olay kaydı olarak raporla.",
    ],
    "social_engineering": [
        "Acil baskı oluşturan taleplerde dur ve doğrulama yap.",
        "Kanal doğrulaması yapmadan para/işlem onayı verme.",
        "Kritik işlemlerde çift onay kuralını zorunlu tut.",
    ],
    "malware_assisted": [
        "Şüpheli dosyaları güvenli analiz/antivirüs taraması olmadan açma.",
        "Cihaz ve tarayıcı güncellemelerini düzenli olarak yap.",
        "Yetkisiz süreç veya eklenti tespitinde cihazı ağdan izole et.",
    ],
    "phishing": [
        "Giriş bağlantısı yerine doğrudan resmi siteye git.",
        "Parola yöneticisi kullan ve benzersiz şifre belirle.",
        "İki adımlı doğrulamayı aktif tut ve oturum hareketlerini düzenli izle.",
    ],
}

CRITICAL_WARNING: Dict[str, str] = {
    "sahte_mobil_uygulama": "Sahte banka uygulamaları cihaz izinlerini kötüye kullanarak hesap ele geçirebilir.",
    "banka_taklit": "Banka adına gelen acil uyarılarda bağlantıya değil, resmi uygulamaya gidin.",
    "smishing": "SMS ile gelen acil ödeme/bağlantı mesajlarında resmi kaynağı doğrulamadan işlem yapma.",
    "vishing": "Telefonla arayan kişiye doğrulama kodu veya parola bilgisi verme.",
    "social_engineering": "Acil baskı ve korku yaratan talepler güçlü sosyal mühendislik işaretidir.",
    "malware_assisted": "Şüpheli dosya ve eklentiler hesap ele geçirme zincirini başlatabilir.",
    "phishing": "Yalnızca resmi adrese manuel giderek oturum aç; e-posta bağlantısından giriş yapma.",
}

ATTACK_METHOD_TR: Dict[str, str] = {
    "phishing": "Oltalama",
    "smishing": "SMS Oltalaması",
    "vishing": "Telefon Dolandırıcılığı",
    "social_engineering": "Sosyal Mühendislik",
    "malware_assisted": "Zararlı Yazılım Destekli Saldırı",
    "sahte_mobil_uygulama": "Sahte Mobil Uygulama Tuzağı",
    "banka_taklit": "Banka Taklidi Senaryosu",
}

LOSS_TYPE_TR: Dict[str, str] = {
    "bank_account": "Banka Hesabı Mağduriyeti",
    "social_media": "Sosyal Medya Hesap Mağduriyeti",
    "ecommerce": "E-Ticaret Mağduriyeti",
    "corporate_account": "Kurumsal Hesap Mağduriyeti",
    "crypto_wallet": "Kripto Cüzdan Mağduriyeti",
    "device_compromise": "Cihaz Ele Geçirme Mağduriyeti",
}

PLATFORM_TR: Dict[str, str] = {
    "banking": "Bankacılık",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "microsoft365": "Microsoft 365",
    "ecommerce": "E-Ticaret",
    "crypto": "Kripto",
    "sikayet_platformu": "Şikayet Platformu",
    "general": "Genel",
}

TURKISH_CITIES = [
    "adana", "adiyaman", "afyonkarahisar", "agri", "amasya", "ankara", "antalya", "artvin", "aydin",
    "balikesir", "bilecik", "bingol", "bitlis", "bolu", "burdur", "bursa", "canakkale", "cankiri",
    "corum", "denizli", "diyarbakir", "edirne", "elazig", "erzincan", "erzurum", "eskisehir",
    "gaziantep", "giresun", "gumushane", "hakkari", "hatay", "isparta", "mersin", "istanbul",
    "izmir", "kars", "kastamonu", "kayseri", "kirklareli", "kirsehir", "kocaeli", "konya",
    "kutahya", "malatya", "manisa", "kahramanmaras", "mardin", "mugla", "mus", "nevsehir",
    "nigde", "ordu", "rize", "sakarya", "samsun", "siirt", "sinop", "sivas", "tekirdag",
    "tokat", "trabzon", "tunceli", "sanliurfa", "usak", "van", "yozgat", "zonguldak",
    "aksaray", "bayburt", "karaman", "kirikkale", "batman", "sirnak", "bartin", "ardahan",
    "igdir", "yalova", "karabuk", "kilis", "osmaniye", "duzce",
]

CITY_DISPLAY = {
    "adiyaman": "Adıyaman", "agri": "Ağrı", "aydin": "Aydın", "balikesir": "Balıkesir",
    "bingol": "Bingöl", "canakkale": "Çanakkale", "cankiri": "Çankırı", "corum": "Çorum",
    "diyarbakir": "Diyarbakır", "elazig": "Elazığ", "eskisehir": "Eskişehir",
    "gumushane": "Gümüşhane", "istanbul": "İstanbul", "izmir": "İzmir", "kirklareli": "Kırklareli",
    "kirsehir": "Kırşehir", "kutahya": "Kütahya", "kahramanmaras": "Kahramanmaraş",
    "mugla": "Muğla", "mus": "Muş", "nevsehir": "Nevşehir", "nigde": "Niğde",
    "sanliurfa": "Şanlıurfa", "usak": "Uşak", "kirikkale": "Kırıkkale", "sirnak": "Şırnak",
    "bartin": "Bartın", "igdir": "Iğdır", "karabuk": "Karabük", "duzce": "Düzce",
}

CITY_ALIASES = {
    "istanbul": ("istanbul",),
    "ankara": ("ankara",),
    "izmir": ("izmir",),
    "sanliurfa": ("sanliurfa", "sanli urfa", "urfa"),
    "tekirdag": ("tekirdag", "tekir dag"),
    "kahramanmaras": ("kahramanmaras", "kahraman maras", "maras"),
    "igdir": ("igdir", "igdır"),
    "canakkale": ("canakkale", "canak kale"),
    "kirklareli": ("kirklareli", "kirklar eli"),
    "kirsehir": ("kirsehir", "kir sehir"),
    "kirikkale": ("kirikkale", "kirik kale"),
    "duzce": ("duzce",),
    "usak": ("usak",),
    "mugla": ("mugla",),
    "eskisehir": ("eskisehir", "eski sehir"),
}

GENERIC_DEFENSE_STEPS = [
    "Resmi kurum/marka bağlantısını tarayıcıya kendin yazarak aç.",
    "İki adımlı doğrulama aktif değilse hemen aç ve tek kullanımlık kodları paylaşma.",
    "Şüpheli olayda banka/kurum destek hattına resmi kanaldan kayıt oluştur.",
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


def _canonical_url(url: str) -> str:
    parsed = urlsplit((url or "").strip())
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=False)
        if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "yclid"}
    ]
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/"), urlencode(query), ""))


def _parse_published_at(value: str) -> Optional[datetime]:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _within_lookback(value: str) -> bool:
    parsed = _parse_published_at(value)
    if not parsed:
        return os.getenv("VICTIM_ATLAS_ALLOW_UNDATED", "false").strip().lower() in {"1", "true", "yes", "on"}
    lookback_days = int(os.getenv("VICTIM_ATLAS_LOOKBACK_DAYS", "365"))
    return parsed >= datetime.now(timezone.utc) - timedelta(days=lookback_days)


def _is_relevant_fraud_document(title: str, summary: str, source_name: str = "") -> bool:
    blob = _ascii_tr(f"{title} {summary}")
    base_match = any(_ascii_tr(keyword) in blob for keyword in FRAUD_RELEVANCE_KEYWORDS)
    source_hints = SOURCE_RELEVANCE_HINTS.get(source_name, ())
    source_match = any(_ascii_tr(keyword) in blob for keyword in source_hints)
    return base_match or source_match


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


def _fetch_rss_documents(session: requests.Session, source: SourceConfig, max_items: int) -> tuple[List[Dict[str, str]], Dict[str, int]]:
    response = session.get(source.url, timeout=40)
    response.raise_for_status()
    root = ElementTree.fromstring(response.content)

    docs: List[Dict[str, str]] = []
    stats: Dict[str, int] = {
        "entries_seen": 0,
        "skipped_lookback": 0,
        "skipped_relevance": 0,
        "accepted": 0,
    }
    lang = "tr" if "_tr_" in source.name or "sikayet" in source.name else "en"
    entries = list(root.iterfind(".//item")) or list(root.iterfind(".//entry"))
    for entry in entries[:max_items]:
        stats["entries_seen"] += 1
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
        published_raw = _first_non_empty([_find_text_anywhere(entry, ("pubdate", "updated", "published"))])
        published_dt = _parse_published_at(published_raw)
        if published_dt is None and not os.getenv("VICTIM_ATLAS_ALLOW_UNDATED", "false").strip().lower() in {"1", "true", "yes", "on"}:
            stats["skipped_lookback"] += 1
            continue
        if published_dt is not None and not _within_lookback(published_raw):
            stats["skipped_lookback"] += 1
            continue
        if not _is_relevant_fraud_document(title, summary, source.name):
            stats["skipped_relevance"] += 1
            continue
        canonical_link = _canonical_url(link or source.url)
        guid = _first_non_empty([_find_text_anywhere(entry, ("guid", "id")), canonical_link, title], default=title)
        docs.append(
            {
                "external_id": guid[:255],
                "url": canonical_link,
                "title": title[:300],
                "published_at": published_dt.isoformat() if published_dt else "",
                "raw_text": summary[:4000],
                "source_name": source.name,
                "lang": "tr",
            }
        )
        stats["accepted"] += 1
    return docs, stats


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


def _ascii_tr(value: str) -> str:
    text = (value or "")
    text = text.translate(str.maketrans({
        "Ç": "C", "Ğ": "G", "İ": "I", "I": "I", "Ö": "O", "Ş": "S", "Ü": "U",
        "ç": "c", "ğ": "g", "ı": "i", "i": "i", "ö": "o", "ş": "s", "ü": "u",
    }))
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.lower().strip()


def _extract_region(blob: str) -> Optional[str]:
    normalized = _ascii_tr(blob)
    suffix = r"(?:['’]?(?:da|de|ta|te|dan|den|tan|ten|ya|ye|a|e|li|lu|lu|lü|li|lu|lar|ler))?"
    for city in TURKISH_CITIES:
        if re.search(rf"(^|[^a-z0-9]){re.escape(city)}{suffix}([^a-z0-9]|$)", normalized):
            return CITY_DISPLAY.get(city, city.title())

    for city, aliases in CITY_ALIASES.items():
        for alias in aliases:
            alias_norm = _ascii_tr(alias)
            if re.search(rf"(^|[^a-z0-9]){re.escape(alias_norm)}{suffix}([^a-z0-9]|$)", normalized):
                return CITY_DISPLAY.get(city, city.title())
    return None


def _extract_region_from_source_metadata(url: str, external_id: str, source_name: str) -> Optional[str]:
    parsed = urlsplit(url or "")
    parts = [parsed.netloc or "", parsed.path or "", external_id or "", source_name or ""]
    metadata_blob = _ascii_tr(" ".join(parts)).replace("-", " ").replace("_", " ").replace("/", " ")
    return _extract_region(metadata_blob)


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


_NARRATIVE_TEMPLATES: Dict[str, str] = {
    "phishing": (
        "Bu vaka, {platform_tr} platformunu hedef alan bir oltalama saldırısını kapsamaktadır. "
        "Saldırgan, kurbanı gerçek gibi görünen sahte bir web sayfasına veya bağlantıya yönlendirerek "
        "giriş bilgilerini, kimlik verilerini ya da finansal bilgilerini ele geçirmeye çalışmaktadır. "
        "Mağdur, genellikle resmi kurumdan geliyormuş gibi görünen bir e-posta, SMS veya anlık mesaj alır "
        "ve kandırılarak sahte sayfada oturum açar. Bu süreçte {loss_tr_lower} meydana gelmektedir. "
        "Oltalama saldırıları, Türkiye'de en yaygın siber dolandırıcılık yöntemlerinden biri olup "
        "özellikle bankacılık, sosyal medya ve e-ticaret platformlarını hedef almaktadır."
    ),
    "smishing": (
        "Bu vaka, SMS tabanlı oltalama yöntemiyle gerçekleştirilen bir siber dolandırıcılık "
        "senaryosunu içermektedir. Saldırgan, kurbanın telefon numarasına kargo bildirimi, banka uyarısı "
        "veya kampanya mesajı kılığında sahte bir SMS göndermektedir. Mesajın içindeki kısa bağlantıya "
        "tıklayan kullanıcı, sahte {platform_tr} sayfasına yönlendirilmekte ve kişisel ya da finansal "
        "bilgilerini girmesi sağlanmaktadır. Bu süreçte {loss_tr_lower} yaşanmaktadır. "
        "Sahte kargo SMS'leri ve banka bildirim mesajları, Türkiye'de bu saldırı türünün en sık görülen biçimleridir."
    ),
    "vishing": (
        "Bu vaka, telefon araması yoluyla gerçekleştirilen sesli oltalama saldırısını kapsamaktadır. "
        "Dolandırıcı, kurbanı {platform_tr} çalışanı, banka yetkilisi veya resmi kurum temsilcisi olarak "
        "tanıtarak arar. Acil durum, hesap güvenliği ihlali veya para transferi gibi bahanelerle kurbanı "
        "panikletir ve şifre, OTP kodu ya da kart bilgilerini paylaşmaya ikna eder. "
        "Bu süreçte {loss_tr_lower} gerçekleşmektedir. "
        "Telefon dolandırıcıları genellikle sahte banka numaraları veya resmi kurumları taklit eden numaralar kullanır."
    ),
    "social_engineering": (
        "Bu vaka, sosyal mühendislik tekniklerine dayanan bir siber dolandırıcılık senaryosunu kapsamaktadır. "
        "Saldırgan, kurbanın güvenini kazanmak amacıyla uzun süreli iletişim kurabilir; bir yetkili, "
        "tanıdık veya hizmet sağlayıcı gibi davranabilir. Aciliyet, korku veya merak duyguları "
        "üzerinden baskı oluşturularak kurban, {platform_tr} üzerinden hassas bilgilerini paylaşmaya "
        "ya da belirli işlemleri onaylamaya yönlendirilir. Bu süreçte {loss_tr_lower} yaşanmaktadır. "
        "Sosyal mühendislik saldırıları teknik engelleri aşarak doğrudan insan psikolojisini hedef alır."
    ),
    "malware_assisted": (
        "Bu vaka, zararlı yazılım destekli bir siber saldırı senaryosunu kapsamaktadır. "
        "Kurban, genellikle sahte bir uygulama, e-posta eki veya güncelleme kılığına girmiş zararlı "
        "bir dosyayı indirmektedir. Zararlı yazılım cihaza yüklendikten sonra tuş kaydı, ekran görüntüsü "
        "alma veya oturum çerezlerini çalma gibi yöntemlerle {platform_tr} platformuna ait kimlik "
        "bilgilerini ele geçirmektedir. Bu süreçte {loss_tr_lower} meydana gelmektedir. "
        "Cihaza yüklenen bu tür yazılımlar, kurbanın farkında olmadan uzun süre veri sızdırabilir."
    ),
    "sahte_mobil_uygulama": (
        "Bu vaka, sahte mobil uygulama tuzağına dayanan bir siber dolandırıcılık senaryosunu içermektedir. "
        "Saldırgan, {platform_tr} platformunun resmi uygulamasının birebir kopyasını oluşturarak "
        "üçüncü taraf uygulama mağazaları, reklam linkleri veya sahte mesajlar aracılığıyla yaymaktadır. "
        "Kullanıcı, sahte uygulamaya giriş yaptığında kimlik bilgileri doğrudan saldırgana iletilmektedir. "
        "Uygulama aynı zamanda SMS erişimi, erişilebilirlik izni veya bildirim izni isteyerek "
        "OTP kodlarını çalabilmektedir. Bu süreçte {loss_tr_lower} gerçekleşmektedir. "
        "Türkiye'de özellikle banka ve kargo uygulamalarının sahteleri sıkça kullanılmaktadır."
    ),
    "banka_taklit": (
        "Bu vaka, banka taklit senaryosuna dayanan gelişmiş bir siber dolandırıcılık vakasını kapsamaktadır. "
        "Saldırgan, {platform_tr} bankasını ya da finans kuruluşunu taklit ederek kurbanla iletişime geçmektedir. "
        "Hesap kapatma, şüpheli işlem tespiti veya acil güncelleme gibi bahaneler öne sürülmektedir. "
        "Kurban, sahte banka web sitesine yönlendirilmekte ya da telefonda kimliğini doğrulaması "
        "istenmekte; bu süreçte kart numarası, şifre veya OTP bilgileri ele geçirilmektedir. "
        "Bu süreçte {loss_tr_lower} yaşanmaktadır. "
        "Türkiye'deki büyük bankaların isimleri bu dolandırıcılık türünde sıklıkla kötüye kullanılmaktadır."
    ),
}

_LOSS_CONTEXT: Dict[str, str] = {
    "bank_account": (
        "Mağdurun banka hesabından yetkisiz para transferi gerçekleştirilmekte ya da kart bilgileri "
        "dolandırıcılık amacıyla kullanılmaktadır."
    ),
    "social_media": (
        "Mağdurun sosyal medya hesabı ele geçirilmekte; hesap üzerinden dolandırıcılık mesajları "
        "yayılabilmekte veya hesap fidye amaçlı kilitlenebilmektedir."
    ),
    "ecommerce": (
        "Mağdur, sahte e-ticaret sitesi veya satıcı aracılığıyla ödeme yapmakta ancak ürünü "
        "alamamakta ya da kart bilgileri çalınmaktadır."
    ),
    "corporate_account": (
        "Kurumsal hesap veya iş e-postası ele geçirilmekte; bu durum iç sistemlere yetkisiz erişim "
        "ya da iş e-postası ihlali saldırısına zemin hazırlayabilmektedir."
    ),
    "crypto_wallet": (
        "Mağdurun kripto cüzdanı seed phrase çalınması, sahte platform ya da dolandırıcılık "
        "yatırım planları aracılığıyla boşaltılmaktadır."
    ),
    "device_compromise": (
        "Mağdurun cihazı zararlı yazılım tarafından ele geçirilmekte; bu durum tüm hesaplara ve "
        "kişisel verilere yetkisiz erişim riskini doğurmaktadır."
    ),
}


def _build_summary(document_title: str, raw_text: str, attack_method: str, loss_type: str, target_platform: str) -> str:
    attack_tr = _tr_method(attack_method)
    loss_tr = _tr_loss(loss_type)
    platform_tr = _tr_platform(target_platform)
    loss_tr_lower = loss_tr.lower()

    template = _NARRATIVE_TEMPLATES.get(attack_method, _NARRATIVE_TEMPLATES["phishing"])
    main_narrative = template.format(
        platform_tr=platform_tr,
        attack_tr=attack_tr,
        loss_tr=loss_tr,
        loss_tr_lower=loss_tr_lower,
    )

    loss_context = _LOSS_CONTEXT.get(loss_type, "")
    if loss_context:
        main_narrative = main_narrative + " " + loss_context

    return main_narrative


def _build_defense_steps(attack_method: str, loss_type: str) -> List[str]:
    base_steps = list(DEFENSE_STEPS.get(attack_method, DEFENSE_STEPS["phishing"]))
    if loss_type == "bank_account":
        base_steps.append("Hesap hareketleri için anlık bildirim aç; şüpheli transferde bankadan kart/hesap dondurma talep et.")
    elif loss_type == "social_media":
        base_steps.append("Hesap kurtarma e-postası ve telefonunu güncelle; bilinmeyen cihaz oturumlarını kapat.")
    elif loss_type == "ecommerce":
        base_steps.append("Satıcı ve ödeme sayfasının alan adını resmi site ile karşılaştır; sanal kart kullan.")

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

    severity = 60
    if any(k in blob.lower() for k in (
        "credential", "password", "account takeover", "bank", "wallet", "2fa",
        "şifre", "parola", "hesap ele geçir", "banka", "kart", "kimlik", "sms doğrulama",
    )):
        severity += 15
    if any(k in blob.lower() for k in (
        "ransomware", "financial", "payment", "wire", "crypto",
        "fidye", "ödeme", "havale", "kripto", "dolandırıcılık", "sahte",
    )):
        severity += 15
    severity = max(0, min(100, severity))

    published_dt = _parse_published_at(document.get("published_at") or "")
    first_seen = (published_dt or datetime.now(timezone.utc)).isoformat()
    incident_start = first_seen
    incident_end = first_seen
    seed = f"{document.get('url','')}-{title}-{attack_method}-{loss_type}-{target_platform}"

    generated_title = _build_case_title(title, attack_method, loss_type, target_platform)
    summary = _build_summary(title, raw_text, attack_method, loss_type, target_platform)
    defense_steps = _build_defense_steps(attack_method, loss_type)
    warning = CRITICAL_WARNING.get(attack_method, CRITICAL_WARNING["phishing"])
    region = _extract_region(f"{title} {raw_text}")
    if not region:
        region = _extract_region_from_source_metadata(
            document.get("url", ""),
            document.get("external_id", ""),
            document.get("source_name", ""),
        )

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
        "region": region,
        "first_seen": first_seen,
        "last_seen": first_seen,
    }


def run_daily_pipeline(max_items_per_source: int = 120) -> Dict[str, Any]:
    run_id = start_ingest_run()
    errors: Dict[str, str] = {}
    documents_fetched = 0
    cases_created = 0
    cases_updated = 0
    filter_stats: Dict[str, Any] = {
        "entries_seen": 0,
        "skipped_lookback": 0,
        "skipped_relevance": 0,
        "accepted": 0,
        "by_source": {},
    }
    session = _http_session()

    try:
        sources = get_enabled_sources()
        source_sync = sync_source_registry(
            [
                {
                    "name": source.name,
                    "base_url": source.url,
                    "trust_tier": source.trust_tier,
                    "enabled": True,
                }
                for source in sources
            ]
        )

        for source in sources:
            source_id = upsert_source(
                name=source.name,
                base_url=source.url,
                trust_tier=source.trust_tier,
                enabled=True,
            )
            try:
                if source.source_type != "rss":
                    raise ValueError(f"unsupported source type: {source.source_type}")
                documents, rss_stats = _fetch_rss_documents(session, source, max_items=max_items_per_source)
                filter_stats["by_source"][source.name] = rss_stats
                filter_stats["entries_seen"] += int(rss_stats.get("entries_seen", 0))
                filter_stats["skipped_lookback"] += int(rss_stats.get("skipped_lookback", 0))
                filter_stats["skipped_relevance"] += int(rss_stats.get("skipped_relevance", 0))
                filter_stats["accepted"] += int(rss_stats.get("accepted", 0))
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
                    similar_case_id = find_similar_case_id(case)
                    if similar_case_id:
                        case_id, created = similar_case_id, False
                    else:
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
            errors={**errors, "__filter_stats__": filter_stats},
        )
        result = {
            "status": "success",
            "run_id": run_id,
            "documents_fetched": documents_fetched,
            "cases_created": cases_created,
            "cases_updated": cases_updated,
            "errors": errors,
            "filter_stats": filter_stats,
            "source_registry": source_sync,
            "hot_set": hot_state,
        }

        # Event Bus: Yeni vakalar eklendiyse AI Analyzer'a sinyal gönder
        if cases_created > 0 or cases_updated > 0:
            try:
                from modules.shared.events import publish
                from datetime import timezone
                publish("victim_atlas.case_ingested", {
                    "attack_methods": list(filter_stats.get("by_source", {}).keys()),
                    "regions": [],
                    "run_id": run_id,
                    "cases_created": cases_created,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as _ev_err:
                import logging as _log
                _log.getLogger("aegis.ingest").warning(
                    f"Event publish failed (non-critical): {_ev_err}"
                )

        return result
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
