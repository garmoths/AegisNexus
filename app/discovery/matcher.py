"""CertStream aday süzgeci.

Bir alan adını (CT kaydından gelen) phishing *adayı* olarak işaretler. Eşleşme
phishing kanıtı DEĞİLDİR; yalnızca incelenmeye değer bir sinyaldir. Karar ve
yayın işini daima insan onayı verir. Bu modül ağa çıkmaz; yalnızca metin inceler.
"""
import re

from rapidfuzz import fuzz

from app.config import get_settings
from app.discovery.analysis import BRANDS

# Phishing sayfalarında sık geçen eylem/konu sözcükleri (TR + EN).
KEYWORDS = (
    'login', 'signin', 'sign-in', 'secure', 'security', 'verify', 'verification',
    'account', 'update', 'confirm', 'recover', 'unlock', 'support', 'billing',
    'invoice', 'payment', 'wallet', 'webscr', 'giris', 'giriş', 'odeme', 'ödeme',
    'dogrulama', 'doğrulama', 'banka', 'bank', 'guvenlik', 'güvenlik', 'hesap',
)

# Suistimale açık, ucuz/ücretsiz TLD'ler. Tek başına kanıt değil, zayıf sinyal.
SUSPICIOUS_TLDS = (
    'xyz', 'top', 'cf', 'gq', 'ml', 'tk', 'ga', 'rest', 'icu', 'buzz', 'click',
    'link', 'live', 'shop', 'online', 'site', 'club', 'work', 'fit', 'cyou',
)

# Aday sayılmak için gereken en düşük puan. AEGIS_CERTSTREAM_THRESHOLD ile ayarlanır.
THRESHOLD = get_settings().aegis_certstream_threshold
# Typosquat benzerlik eşiği (rapidfuzz ratio, 0-100). Uzunluk farkı en fazla 1
# olan etiketlere uygulanır: karakter değiştirme/ekleme kaçamaklarını yakalar
# ('paypa1'↔'paypal'), 'snapple'↔'apple' gibi yanlış pozitifleri yakalamaz.
_TYPO_RATIO = 80
_TYPO_LEN_DELTA = 1


def _brand_tokens():
    """Her marka için ayırt edici etiketler (marka anahtarı + resmi alanın ilk etiketi)."""
    tokens = {}
    for brand, officials in BRANDS.items():
        labels = {brand.replace('-', '')}
        for official in officials:
            labels.add(official.split('.', 1)[0])
        # 'ptt' gibi çok kısa etiketler çok gürültü üretir; yalnızca tam etiket eşleşir.
        tokens[brand] = {label for label in labels if len(label) >= 3}
    return tokens


BRAND_TOKENS = _brand_tokens()
_ALL_OFFICIALS = tuple(sorted({d for officials in BRANDS.values() for d in officials}))


def _is_official(domain):
    return any(domain == official or domain.endswith('.' + official) for official in _ALL_OFFICIALS)


def normalize_domain(value):
    """CT 'all_domains' girdisini sade bir ana bilgisayar adına indirger."""
    if not isinstance(value, str):
        return ''
    domain = value.strip().lower().rstrip('.')
    if domain.startswith('*.'):
        domain = domain[2:]
    return domain


def classify(domain):
    """(matched, score, reason) döndürür. matched=True ise domain bir adaydır."""
    domain = normalize_domain(domain)
    if not domain or '.' not in domain or len(domain) > 253:
        return False, 0, ''
    # Bilinen resmi alanlar ve alt alanları asla işaretlenmez.
    if _is_official(domain):
        return False, 0, 'official'

    labels = [label for label in domain.split('.') if label]
    # Son etiket TLD; marka/keyword karşılaştırmasında dışarıda tutulur.
    inner = labels[:-1] if len(labels) > 1 else labels
    tld = labels[-1] if len(labels) > 1 else ''

    signals = []
    score = 0
    matched_brands = set()

    # 1) Marka etiketi domain içinde (örn. 'paypal-login.xyz', 'apple.verify.tld').
    #    Sözcük sınırına dayanır; 'snapple' içinde 'apple' eşleşmez.
    for brand, tokens in BRAND_TOKENS.items():
        for token in tokens:
            if re.search(r'(?:^|[.-])' + re.escape(token) + r'(?:$|[.-])', domain):
                matched_brands.add(brand)
                break
    if matched_brands:
        score += 40
        signals.append('marka adı: ' + ', '.join(sorted(matched_brands)))

    # 2) Typosquat: bir etiket parçası bir marka etiketine çok benziyor ama birebir
    #    değil (örn. 'paypa1', 'netfl1x-account', 'micr0soft-update'). Tireli etiketler
    #    parçalara bölünür ki 'netfl1x-account' içindeki 'netfl1x' yakalansın.
    parts = {part for label in inner for part in label.split('-') if len(part) >= 3}
    typo_hits = set()
    for part in parts:
        for brand, tokens in BRAND_TOKENS.items():
            if brand in matched_brands:
                continue
            for token in tokens:
                if part == token or abs(len(part) - len(token)) > _TYPO_LEN_DELTA:
                    continue
                if fuzz.ratio(part, token) >= _TYPO_RATIO:
                    typo_hits.add(brand)
    if typo_hits:
        score += 45
        signals.append('benzer yazım: ' + ', '.join(sorted(typo_hits)))

    # 3) Eylem/konu anahtar sözcüğü etiket olarak veya etiket içinde.
    keyword_hits = sorted({kw for kw in KEYWORDS
                           if re.search(r'(?:^|[.-])' + re.escape(kw), domain)})
    if keyword_hits:
        score += 15
        signals.append('anahtar sözcük: ' + ', '.join(keyword_hits[:4]))

    # 4) Zayıf ek sinyaller.
    if tld in SUSPICIOUS_TLDS:
        score += 10
        signals.append('riskli uzantı: .' + tld)
    if any(label.startswith('xn--') for label in labels):
        score += 10
        signals.append('punycode/IDN')
    if domain.count('-') >= 3 or len(domain) >= 40:
        score += 5
        signals.append('olağandışı yapı')

    reason = '; '.join(signals)
    return score >= THRESHOLD, score, reason
