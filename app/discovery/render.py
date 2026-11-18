"""Disposable browser capture. No forms, downloads, websocket or private-network access."""
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from app.discovery.analysis import canonical_url
from app.discovery.transport import robots_allows, UA
from app.outbound import safe_request


def capture(url, token, exclusions):
    from playwright.sync_api import sync_playwright
    if not token.isalnum() or len(token) != 32:
        raise ValueError('Invalid capture identity')
    with sync_playwright() as p:
        executable = os.getenv('AEGIS_CHROMIUM_PATH')
        browser = p.chromium.launch(headless=True, **({'executable_path': executable} if executable else {}))
        context = browser.new_context(service_workers='block', accept_downloads=False, user_agent=UA)
        context.add_init_script("Object.defineProperty(window, 'RTCPeerConnection', {value: undefined}); Object.defineProperty(window, 'WebTransport', {value: undefined}); HTMLFormElement.prototype.submit = function(){}; HTMLFormElement.prototype.requestSubmit = function(){}; document.addEventListener('submit', e => e.preventDefault(), true);")
        count = 0
        total = 0
        def guard(route):
            nonlocal count, total
            count += 1
            try:
                request = route.request
                _, host, _ = canonical_url(request.url)
                if url.startswith('https:') and request.url.startswith('http:'):
                    return route.abort()
                if count > 30 or total > 5_000_000 or request.method not in ('GET', 'HEAD') or any(host == h or host.endswith('.' + h) for h in exclusions):
                    return route.abort()
                if request.resource_type in ('media', 'websocket', 'font'):
                    return route.abort()
                if not robots_allows(request.url):
                    return route.abort()
                response = safe_request(request.method, request.url, timeout=3, max_bytes=500_000,
                                        allow_redirects=False, headers={'User-Agent': UA})
                total += len(response.content)
                headers = {k: v for k, v in response.headers.items() if k.lower() not in
                           ('content-length', 'content-encoding', 'transfer-encoding', 'set-cookie')}
                route.fulfill(status=response.status_code, headers=headers, body=response.content)
            except Exception:
                route.abort()
        context.route('**/*', guard)
        context.route_web_socket('**/*', lambda socket: socket.close())
        page = context.new_page()
        page.set_default_timeout(10000)
        try:
            response = page.goto(url, wait_until='domcontentloaded', timeout=20000)
            if response is None or not 200 <= response.status < 300:
                return {}
            page.wait_for_timeout(500)
            _, final_host, _ = canonical_url(page.url)
            if any(final_host == h or final_host.endswith('.' + h) for h in exclusions):
                return {}
            html = page.content()
            if len(html.encode()) > 1_000_000:
                return {}
            screenshot = token + '.png'
            screenshot_file = Path(os.environ['CRAWLER_DATA_DIR']) / screenshot
            page.screenshot(path=str(screenshot_file), full_page=False, timeout=5000)
            screenshot_file.chmod(0o600)
            return {'html': html, 'url': page.url, 'screenshot': screenshot}
        finally:
            browser.close()


if __name__ == '__main__':
    try:
        print(json.dumps(capture(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]))))
    except Exception:
        print('{}')
