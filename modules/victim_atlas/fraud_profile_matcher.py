"""Dolandırıcılık profil eşleştirici — keyword scoring + attack_method bonusu."""
from __future__ import annotations

import logging
import re
from typing import Optional

_TR_MAP = str.maketrans("şğıüöçŞĞİÜÖÇ", "sgiuocSGIUOC")


def normalize_tr(s: str) -> str:
    """Türkçe karakterleri ASCII karşılıklarına dönüştürür (case-insensitive matching için)."""
    return s.translate(_TR_MAP).lower()

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

STATIC_PROFILES = [
    {
        "slug": "kripto-dolandiricilik",
        "name_tr": "Kripto Dolandırıcılığı",
        "description": (
            "Yatırımcılara sahte kripto para platformları veya 'yüksek getirili' kripto "
            "fırsatları sunulur. Kurbanlar para yatırdıktan sonra platformdan çekim yapamazlar. "
            "Telegram veya WhatsApp grupları ile yaygınlaştırılır."
        ),
        "attack_method": "investment_fraud",
        "keywords": [
            "kripto", "bitcoin", "btc", "ethereum", "eth", "yatırım", "getiri", "borsa",
            "coin", "token", "blockchain", "binance", "matic", "usdt", "staking",
            "pasif gelir", "çekim", "para çekme", "platform", "cüzdan", "wallet",
        ],
        "indicators": [
            "garantili getiri", "günlük kazanç", "çekim sorunu", "hesap donduruldu",
            "komisyon öde", "vergi öde", "para çekemiyorum",
        ],
        "severity": "critical",
        "atlas_search_q": "kripto bitcoin yatirim borsa coin",
    },
    {
        "slug": "banka-phishing",
        "name_tr": "Banka / Fintech Kimlik Avı",
        "description": (
            "Gerçek banka veya ödeme sistemi kurumlarını taklit eden SMS, e-posta veya web "
            "siteleri aracılığıyla kullanıcının IBAN, kart numarası veya internet bankacılığı "
            "şifresi çalınır."
        ),
        "attack_method": "phishing",
        "keywords": [
            "banka", "iban", "kart", "sifre", "sms", "otp", "dogrulama kodu",
            "hesap askiya", "hesabiniz", "guncelleme", "link", "tiklayin",
            "akbank", "yapi kredi", "garanti", "ziraat", "halkbank", "is bankasi",
            "odeme", "transfer", "mobile banking", "internet bankaciligi",
            "tanimsiz cihaz", "giris engellendi",
            "gecici kisitlama", "hesabiniz kapatilacak",
            "musteri hizmetleri",
        ],
        "indicators": [
            "hesabiniz askiya alindi", "acilen giris yapin",
            "dogrulama kodu girin",
            "yetkisiz islem", "suspicious activity",
            "tanimsiz cihazdan giris",
        ],
        "severity": "high",
        "atlas_search_q": "Akbank banka fintech kredi karti internet bankaciligi",
    },
    {
        "slug": "parsel-dolandiricilik",
        "name_tr": "Parsel / Tapu Dolandırıcılığı",
        "description": (
            "Sahte tapu belgesi veya arazi senedi ile arsa ya da tarla satışı yapılır. "
            "Kurban parayı nakit veya havale ile gönderdikten sonra satıcı kaybolur. "
            "Genellikle köy arsaları veya tarım arazileri üzerinden gerçekleşir."
        ),
        "attack_method": "property_fraud",
        "keywords": [
            "arsa", "tarla", "tapu", "parsel", "arazi", "dönüm", "köy", "bahçe",
            "satılık", "tapusu", "kadastro", "hisse", "miras", "vasiyetname",
            "ucuz arsa", "yatırımlık", "imar",
        ],
        "indicators": [
            "nakit ödeme", "avans", "tapuyu sonra veririm", "tapu masrafı",
            "noter masrafı önceden", "banka dışı ödeme",
        ],
        "severity": "high",
        "atlas_search_q": "arsa tapu parsel arazi tarla",
    },
    {
        "slug": "sahte-avukat-icra",
        "name_tr": "Sahte Avukat / İcra Dolandırıcılığı",
        "description": (
            "Sahte avukat veya icra müdürü kimliğine bürünen dolandırıcılar, kurbanı "
            "hakkında dava açıldığını veya icra takibi başlatıldığını söyleyerek "
            "peşin ödeme yapmaya zorlarlar."
        ),
        "attack_method": "impersonation",
        "keywords": [
            "avukat", "icra", "dava", "mahkeme", "icra müdürlüğü", "borç",
            "haciz", "savcılık", "mahkeme celp", "ödeme emri", "takip",
            "baro", "hukuki süreç", "tazminat", "ceza",
        ],
        "indicators": [
            "acil ödeme yapın", "bugün ödeyin", "cezadan kurtulun",
            "savcılık soruşturması", "tutuklama kararı",
        ],
        "severity": "high",
        "atlas_search_q": "avukat icra mahkeme haciz sahte",
    },
    {
        "slug": "sahte-is-teklifi",
        "name_tr": "Sahte İş Teklifi Dolandırıcılığı",
        "description": (
            "İş arayanlara yurt dışı veya yurt içi cazip iş teklifleri sunulur. "
            "İşe alım sürecinde belge ücreti, pasaport harcı veya eğitim bedeli "
            "adı altında para istenir; ücret ödendikten sonra iletişim kesilir."
        ),
        "attack_method": "job_fraud",
        "keywords": [
            "iş teklifi", "yurt dışı", "maaş", "işe alım", "remote", "uzaktan",
            "part time", "yarı zamanlı", "ek gelir", "linkedin", "kariyer",
            "başvuru", "cv", "pasaport", "vize", "belge ücreti", "ön ödeme",
        ],
        "indicators": [
            "para gönderin", "ücret iadesi", "depozito", "evden çalışma fırsatı",
            "işe alınmanız kesin", "ön ödeme zorunlu",
        ],
        "severity": "medium",
        "atlas_search_q": "is teklifi yurt disi maas uzaktan",
    },
    {
        "slug": "edevlet-kimlik-avi",
        "name_tr": "E-Devlet / Kurumsal Kimlik Avı",
        "description": (
            "SGK, PTT, e-Devlet, Bakanlık veya belediye gibi kurumları taklit eden "
            "sahte SMS ve e-postalar ile vatandaşların TC kimlik, şifre veya ödeme "
            "bilgileri çalınır."
        ),
        "attack_method": "phishing",
        "keywords": [
            "e-devlet", "edevlet", "sgk", "ptt", "ptt kargo", "kargo", "gonderiniz",
            "bakanlık", "bakanlik", "belediye", "tc kimlik",
            "nufus mudurlugu", "vergi", "gumruk", "saglik bakanligi",
            "emeklilik", "maas", "resmi bildirim", "devlet", "kamu",
            "kargo ucreti", "adres dogrulama", "teslim edilemedi",
            "gumruk isleme", "kargo iade", "prim borcu", "borcunuz",
        ],
        "indicators": [
            "tc kimlik dogrulayin", "sms kodu girin", "resmi site", "sifrenizi guncelleyin",
            "hesap bilgilerini teyit edin",
            "gumruk isleme ucreti", "adres guncelle", "son gun bugun",
            "yasal surec baslatilmaktadir", "gecikmiş prim", "gecikmiş borcunuz",
        ],
        "severity": "high",
        "atlas_search_q": "PTT kargo sgk e-devlet kurumsal kimlik",
    },
    {
        "slug": "romantik-dolandiricilik",
        "name_tr": "Romantik / Duygusal Dolandırıcılık",
        "description": (
            "Sosyal medya veya tanışma uygulamaları üzerinden uzun süreli duygusal ilişki "
            "kuran dolandırıcılar, güven kazandıktan sonra acil sağlık veya seyahat "
            "masrafı bahanesiyle para talep ederler."
        ),
        "attack_method": "romance_scam",
        "keywords": [
            "tanışma", "sevgili", "aşk", "evlilik", "yurt dışı", "asker",
            "mühendis", "doktor", "yalnız", "dul", "tinder", "instagram",
            "whatsapp", "para gönder", "bilet", "ameliyat", "kaza",
        ],
        "indicators": [
            "para gönderir misin", "acil yardım", "tek sen varsın",
            "bilet parasını göndereceğim", "sana güveniyorum para lazım",
        ],
        "severity": "high",
        "atlas_search_q": "romantik ask sevgili para gonder",
    },
    {
        "slug": "piyango-odul-dolandiricilik",
        "name_tr": "Sahte Piyango / Ödül Dolandırıcılığı",
        "description": (
            "Kişiye 'çekiliş kazandınız' veya 'büyük ödül sizin' mesajı gönderilerek "
            "ödülü almak için vergi, kargo veya işlem ücreti ödenmesi talep edilir."
        ),
        "attack_method": "prize_scam",
        "keywords": [
            "çekiliş", "ödül", "kazandınız", "büyük ikramiye", "piyango",
            "otomobil", "para ödülü", "tebrikler", "kazanan", "seçildiniz",
            "kargo ücreti", "vergi öde", "işlem bedeli",
        ],
        "indicators": [
            "ödülünüzü alın", "vergi ödemesi", "kargo masrafı",
            "hesabınıza yatırılacak", "hemen başvurun",
        ],
        "severity": "medium",
        "atlas_search_q": "piyango odul cekilis kazandiniz",
    },
]


def seed_profiles(db: Session) -> int:
    """Statik profilleri DB'ye yükle (yoksa ekle, varsa keywords/indicators güncelle). Eklenen sayısını döner."""
    from app.models import FraudProfile

    added = 0
    for p in STATIC_PROFILES:
        existing = db.query(FraudProfile).filter(FraudProfile.slug == p["slug"]).first()
        if existing:
            existing.keywords = p["keywords"]
            existing.indicators = p["indicators"]
            existing.description = p["description"]
            existing.severity = p["severity"]
        else:
            db.add(FraudProfile(
                slug=p["slug"],
                name_tr=p["name_tr"],
                description=p["description"],
                attack_method=p["attack_method"],
                keywords=p["keywords"],
                indicators=p["indicators"],
                severity=p["severity"],
                is_static=True,
            ))
            added += 1
    db.commit()
    logger.info("[FraudProfile] seed tamamlandı: %d yeni, mevcut profiller güncellendi", added)
    return added


_DEMO_CASES = [
    {
        "case_slug": "demo-ptt-kargo-sms-dolandiricilik",
        "case_title": "PTT Kargo SMS Dolandırıcılığı: Sahte Gümrük Ücreti Tuzağı",
        "attack_method": "phishing",
        "loss_type": "financial",
        "target_platform": "sms",
        "critical_warning": "PTT hiçbir zaman SMS ile gümrük veya işlem ücreti talep etmez. 'ptt-kargo' içeren alan adları sahte sitelerdir.",
        "narrative_summary": (
            "PTT kargo adına gönderilen sahte SMS mesajlarında kurbanın gönderisi teslim edilemeyen paket olarak gösterilmekte, "
            "14,90 TL ile 50 TL arasında değişen 'gümrük işlem ücreti' ödenmesi talep edilmektedir. "
            "ptt kargo dolandırıcılık kurumsal kimlik avı phishing. "
            "Bağlantı, gerçek PTT sitesini taklit eden 'ptt-kargo-odeme.top', 'ptt-kargo-tr.com' gibi sahte alan adlarına yönlendirmektedir. "
            "Ödeme sayfasında kart numarası, son kullanma tarihi ve CVV bilgileri çalınmaktadır."
        ),
        "defense_steps_json": [
            "PTT resmi sitesi yalnızca ptt.gov.tr'dir. Başka alan adlarına ödeme yapmayın.",
            "Gerçek gönderinizi PTT şubesi veya 444 1 788 hattından teyit edin.",
            "Kısa mesajdaki linklere tıklamak yerine tarayıcıya manuel yazın.",
        ],
        "confidence_score": 95,
        "severity_score": 85,
        "region": "Türkiye",
        "is_hot": True,
        "is_published": True,
    },
    {
        "case_slug": "demo-akbank-hesap-askiya-sms-phishing",
        "case_title": "Akbank Hesap Askıya Alma SMS Kimlik Avı",
        "attack_method": "phishing",
        "loss_type": "financial",
        "target_platform": "sms",
        "critical_warning": "Akbank ve diğer bankalar SMS ile asla şifre, OTP veya hesap doğrulama linki göndermez.",
        "narrative_summary": (
            "Akbank müşterilerine 'tanımsız cihazdan giriş' bahanesiyle sahte SMS gönderilmektedir. "
            "akbank banka fintech internet bankacılığı kredi kartı hesap dolandırıcılık phishing kimlik avı. "
            "SMS'teki bağlantı 'akbank-guvenlik.xyz' veya 'akbank-dogrulama.com' gibi sahte sitelere yönlendirmekte, "
            "girilen internet bankacılığı şifresi ve SMS OTP kodu anlık olarak dolandırıcı tarafından ele geçirilmektedir. "
            "Hesaptan binlerce TL'lik EFT veya alışveriş işlemi gerçekleştirilmektedir."
        ),
        "defense_steps_json": [
            "Bankanızın resmi mobil uygulamasını kullanın, SMS'teki linklere tıklamayın.",
            "Şüpheli işlemlerde kartınızı hemen 444 2 525'ten durdurun.",
            "İnternet bankacılığı şifrenizi asla SMS veya e-posta ile paylaşmayın.",
        ],
        "confidence_score": 95,
        "severity_score": 90,
        "region": "Türkiye",
        "is_hot": True,
        "is_published": True,
    },
    {
        "case_slug": "demo-sgk-edevlet-prim-borcu-phishing",
        "case_title": "SGK / E-Devlet Kimlik Avı: Sahte Prim Borcu Bildirimi",
        "attack_method": "phishing",
        "loss_type": "identity",
        "target_platform": "email_sms",
        "critical_warning": "SGK ve e-Devlet, prim borçları için asla SMS veya e-posta ile şifre ya da TC kimlik numarası istemez.",
        "narrative_summary": (
            "SGK ve e-Devlet adına gönderilen sahte SMS ve e-postalarda, vatandaşın gecikmiş prim borcu olduğu ve "
            "yasal süreç başlatılmadan önce e-Devlet şifresiyle giriş yapılarak ödeme yapılması gerektiği bildirilmektedir. "
            "SGK e-Devlet kurumsal kimlik avı phishing oltalama TC kimlik gecikmiş prim borcu. "
            "Bağlantı 'edevlet-sgk-sorgula.net' gibi sahte sitelere yönlendirmekte; girilen TC kimlik numarası, "
            "e-Devlet şifresi ve SMS doğrulama kodu ele geçirilerek kimlik hırsızlığı yapılmaktadır."
        ),
        "defense_steps_json": [
            "e-Devlet yalnızca turkiye.gov.tr adresidir. Başka sitelere giriş yapmayın.",
            "SGK borç sorgulaması için 170 numaralı ALO 170 hattını arayın.",
            "TC kimlik numaranızı ve e-Devlet şifrenizi yalnızca resmi devlet sitelerinde kullanın.",
        ],
        "confidence_score": 95,
        "severity_score": 88,
        "region": "Türkiye",
        "is_hot": True,
        "is_published": True,
    },
]


def seed_demo_cases(db: Session) -> int:
    """3 sunum amaçlı demo vakasını VictimCase tablosuna yükle (upsert)."""
    from datetime import datetime, timezone
    from app.models import VictimCase

    added = 0
    now = datetime.now(timezone.utc)
    for c in _DEMO_CASES:
        existing = db.query(VictimCase).filter(VictimCase.case_slug == c["case_slug"]).first()
        if existing:
            existing.case_title = c["case_title"]
            existing.narrative_summary = c["narrative_summary"]
            existing.critical_warning = c["critical_warning"]
            existing.defense_steps_json = c["defense_steps_json"]
            existing.severity_score = c["severity_score"]
        else:
            db.add(VictimCase(
                case_slug=c["case_slug"],
                case_title=c["case_title"],
                attack_method=c["attack_method"],
                loss_type=c["loss_type"],
                target_platform=c["target_platform"],
                critical_warning=c["critical_warning"],
                narrative_summary=c["narrative_summary"],
                defense_steps_json=c["defense_steps_json"],
                confidence_score=c["confidence_score"],
                severity_score=c["severity_score"],
                region=c["region"],
                is_hot=c["is_hot"],
                is_published=c["is_published"],
                first_seen=now,
                last_seen=now,
            ))
            added += 1
    db.commit()
    logger.info("[DemoCase] seed tamamlandı: %d yeni, mevcut demolar güncellendi", added)
    return added


def _score_profile(text_norm: str, profile) -> int:
    """Metin ile profil arasındaki keyword benzerlik skoru (0-100)."""
    hits = sum(1 for kw in (profile.keywords or []) if normalize_tr(kw) in text_norm)
    ind_hits = sum(1 for ind in (profile.indicators or []) if normalize_tr(ind) in text_norm)
    return hits * 3 + ind_hits * 5


def match_profile(
    text: str,
    attack_method: Optional[str] = None,
    db: Optional[Session] = None,
    min_score: int = 6,
) -> Optional[dict]:
    """
    Metni ve attack_method'u fraud_profiles ile karşılaştırır.
    En yüksek skorlu profili döner. Eşleşme yoksa None.
    """
    if not db:
        return None

    from app.models import FraudProfile

    profiles = db.query(FraudProfile).all()
    if not profiles:
        seed_profiles(db)
        profiles = db.query(FraudProfile).all()

    text_norm = re.sub(r'\s+', ' ', normalize_tr(text))
    best_profile = None
    best_score = 0

    for p in profiles:
        score = _score_profile(text_norm, p)
        if attack_method and p.attack_method == attack_method:
            score += 10
        if score > best_score:
            best_score = score
            best_profile = p

    if best_profile is None or best_score < min_score:
        return None

    _SEARCH_Q_MAP = {p["slug"]: p.get("atlas_search_q", "") for p in STATIC_PROFILES}
    confidence = min(int((best_score / 30) * 100), 99)
    return {
        "slug": best_profile.slug,
        "name_tr": best_profile.name_tr,
        "description": best_profile.description,
        "attack_method": best_profile.attack_method,
        "severity": best_profile.severity,
        "case_count": best_profile.case_count,
        "avg_loss_try": best_profile.avg_loss_try,
        "confidence": confidence,
        "score": best_score,
        "atlas_search_q": _SEARCH_Q_MAP.get(best_profile.slug, ""),
    }
