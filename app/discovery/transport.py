"""Every hop (including robots/favicon) is pinned to a validated public address."""
from urllib.parse import urlsplit, urljoin
from urllib.robotparser import RobotFileParser
import requests
from app.outbound import safe_get, validate_url, UnsafeTarget

UA = 'AegisNexus-Discovery/1.0'
MAX_HTML = 1_000_000


class CrawlBlocked(ValueError):
    pass


def robots_allows(url, getter=safe_get):
    parsed = urlsplit(url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    response = getter(origin + '/robots.txt', timeout=5, max_bytes=128_000, allow_redirects=False, headers={'User-Agent': UA})
    if response.status_code in (404, 410):
        return True
    if response.status_code in (401, 403) or response.status_code >= 300:
        return False
    rules = RobotFileParser()
    rules.parse(response.text.splitlines())
    delay = rules.crawl_delay(UA) or rules.crawl_delay('*')
    # Page jobs have a gap, but subresources do not. Decline explicit pacing
    # requirements rather than claiming to honor them between every request.
    return rules.can_fetch(UA, url) and (delay is None or delay == 0)


def fetch_page(url, *, allowed=lambda host: True, getter=safe_get):
    chain = []
    for _ in range(6):
        normalized, host, _, _ = validate_url(url)
        if not allowed(host):
            raise CrawlBlocked('excluded_host')
        if not robots_allows(normalized, getter):
            raise CrawlBlocked('robots_denied')
        response = getter(normalized, timeout=8, max_bytes=MAX_HTML, allow_redirects=False, headers={'User-Agent': UA})
        if response.is_redirect:
            destination = urljoin(normalized, response.headers['Location'])
            if normalized.startswith('https:') and destination.startswith('http:'):
                raise CrawlBlocked('https_downgrade')
            chain.append(normalized)
            url = destination
            continue
        if response.status_code == 429 or response.status_code >= 500:
            raise requests.RequestException('transient_http')
        if response.status_code in (401, 403):
            raise CrawlBlocked('access_denied')
        content_type = response.headers.get('Content-Type', '').lower()
        if content_type and 'html' not in content_type:
            raise CrawlBlocked('not_html')
        response.encoding = response.encoding or 'utf-8'
        return {'url': normalized, 'html': response.text, 'status': response.status_code, 'redirects': chain}
    raise CrawlBlocked('redirect_limit')
