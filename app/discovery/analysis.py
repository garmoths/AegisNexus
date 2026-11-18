"""Bounded static HTML extraction. Scores are rule signals, never probabilities."""
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.outbound import validate_url

VERSION = 'discovery-rules-v1'
BRANDS = {
    'google': ('google.com', 'google.com.tr'), 'microsoft': ('microsoft.com', 'live.com', 'office.com'),
    'apple': ('apple.com', 'icloud.com'), 'paypal': ('paypal.com',), 'instagram': ('instagram.com',),
    'facebook': ('facebook.com',), 'netflix': ('netflix.com',), 'amazon': ('amazon.com', 'amazon.com.tr'),
    'akbank': ('akbank.com',), 'garanti': ('garantibbva.com.tr', 'garanti.com.tr'),
    'ziraat': ('ziraatbank.com.tr',), 'isbank': ('isbank.com.tr',), 'yapikredi': ('yapikredi.com.tr',),
    'papara': ('papara.com',), 'turkiye': ('turkiye.gov.tr',), 'e-devlet': ('turkiye.gov.tr',),
    'ptt': ('ptt.gov.tr',),
}


def canonical_url(value):
    normalized, host, _, _ = validate_url(value, resolve=False)
    if len(normalized) > 4096 or len(host) > 253:
        raise ValueError('Adres çok uzun.')
    return normalized, host, hashlib.sha256(normalized.encode()).hexdigest()


def display_url(value):
    """Query values may be credentials; never include them in list/log evidence."""
    parsed = urlsplit(value)
    return f'{parsed.scheme}://{parsed.netloc}{parsed.path}' + ('?…' if parsed.query else '')


def _target(base, value):
    try:
        return canonical_url(urljoin(base, value))[0]
    except (ValueError, UnicodeError):
        return None


def extract(html, url):
    if len(html.encode('utf-8')) > 2_000_000:
        raise ValueError('HTML boyut sınırı aşıldı.')
    soup = BeautifulSoup(html, 'html.parser')
    host = urlsplit(url).hostname or ''
    base = url
    base_tag = soup.find('base', href=True)
    if base_tag:
        base = _target(url, base_tag['href']) or url
    title = soup.title.get_text(' ', strip=True)[:300] if soup.title else ''
    forms, links, scripts, fingerprints = [], [], [], []
    for form in soup.find_all('form', limit=30):
        fields = form.find_all('input', limit=100)
        kinds = []
        for field in fields:
            descriptor = ' '.join(str(field.get(key, '')) for key in ('type', 'name', 'id', 'autocomplete', 'placeholder')).lower()
            if field.get('type', '').lower() == 'password':
                kinds.append('password')
            if re.search(r'\botp\b|one-time-code|doğrulama|verification', descriptor):
                kinds.append('otp')
            if re.search(r'cc-number|card.?number|cvv|kart.?numara', descriptor):
                kinds.append('card')
        action = _target(base, form.get('action') or url)
        target_host = urlsplit(action).hostname if action else None
        forms.append({'fields': sorted(set(kinds)), 'target_host': target_host,
                      'external': bool(target_host and target_host != host), 'method': form.get('method', 'get').lower()[:10]})
    # Some frameworks create their forms at runtime; do not call absence safe.
    for anchor in soup.find_all('a', href=True, limit=500):
        target = _target(base, anchor['href'])
        if target and target != url:
            links.append(target)
    for script in soup.find_all('script', limit=100):
        if script.get('src'):
            target = _target(base, script['src'])
            if target:
                scripts.append(display_url(target))
        elif script.string and len(script.string.strip()) >= 80:
            fingerprints.append(hashlib.sha256(script.string.encode()).hexdigest())
    favicon = None
    for link in soup.find_all('link', href=True, limit=100):
        if 'icon' in ' '.join(link.get('rel', [])):
            favicon = _target(base, link['href'])
            break
    source = str(soup)
    trackers = sorted(set(re.findall(r'\b(?:GTM-[A-Z0-9]{4,12}|G-[A-Z0-9]{8,12}|UA-\d{4,12}-\d{1,4})\b', source)))[:30]
    for tag in soup(['script', 'style', 'noscript']):
        tag.decompose()
    text = soup.get_text(' ', strip=True)[:100_000].lower()
    brands = [brand for brand in BRANDS if re.search(r'(?<!\w)' + re.escape(brand) + r'(?!\w)', (title + ' ' + text).lower())]
    mismatches = [brand for brand in brands if not any(host == official or host.endswith('.' + official) for official in BRANDS[brand])]
    return {'title': title, 'host': host, 'forms': forms, 'brands': brands, 'brand_mismatches': mismatches,
            'links': list(dict.fromkeys(links))[:100], 'scripts': sorted(set(scripts))[:100],
            'script_hashes': sorted(set(fingerprints))[:50], 'trackers': trackers,
            'favicon_url': favicon, 'content_hash': hashlib.sha256(html.encode()).hexdigest(),
            'has_iframe': bool(soup.find('iframe')), 'text_length': len(text)}


def assess(features, *, http_status=200, truncated=False, rendered=False, live=True):
    evidence = []
    def add(code, group, weight, detail):
        evidence.append({'code': code, 'group': group, 'weight': weight, 'detail': detail})
    forms = features['forms']
    sensitive = [f for f in forms if f['fields']]
    if features['brand_mismatches'] and sensitive:
        add('brand_credential_mismatch', 'identity', 35, 'Marka adı ve hassas bilgi formu, bilinen resmi alan dışında birlikte görülüyor.')
    elif features['brand_mismatches']:
        add('brand_mention', 'identity', 5, 'Marka adı geçiyor; bu tek başına taklit kanıtı değildir.')
    if sensitive:
        add('sensitive_form', 'collection', 15, 'Parola, kart veya doğrulama kodu alanı bulundu.')
    if any(f['external'] for f in sensitive):
        add('external_form', 'collection', 20, 'Hassas bilgi formunun hedefi başka alan adı; meşru SSO olasılığı ayrıca incelenmeli.')
    if any(f['method'] == 'get' for f in sensitive):
        add('sensitive_get', 'collection', 10, 'Hassas bilgi formu GET kullanıyor; bilgi adres satırına yazılabilir.')
    if features['host'].startswith('xn--') or '.xn--' in features['host']:
        add('idn', 'address', 10, 'Uluslararası alan adı kullanılıyor; benzer görünen karakterleri inceleyin.')
    caps = {'identity': 35, 'collection': 35, 'address': 10}
    score = sum(min(cap, sum(e['weight'] for e in evidence if e['group'] == group)) for group, cap in caps.items())
    available = 200 <= http_status < 300 and features['text_length'] > 0
    coverage = 'rendered' if available and rendered else 'static' if available else 'unknown'
    if truncated or not live:
        coverage = 'partial' if available else 'unknown'
    return {'version': VERSION, 'risk': score if available else None, 'coverage': coverage,
            'verdict': 'high' if available and score >= 55 else 'review' if available and score > 0 else 'unknown',
            'evidence': evidence, 'confirmed': False,
            'limitations': ['Risk puanı bir olasılık değildir.', 'Kaynak kodu sunucu tarafındaki uygulamayı göstermez.',
                            'Bulgu yokluğu güvenlik kanıtı değildir.', 'Otomatik phishing onayı verilmez.']}
