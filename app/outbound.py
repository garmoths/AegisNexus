"""Public-internet-only, DNS-pinned HTTP transport for untrusted destinations."""
import ipaddress
import json
import socket
import time
from urllib.parse import urlsplit, urlunsplit, urljoin

import requests
import urllib3


class UnsafeTarget(ValueError):
    pass


def validate_url(url, *, resolve=True):
    url = str(url).strip()
    if any(ord(c) < 33 for c in url) or '\\' in url:
        raise UnsafeTarget('URL geçersiz karakter içeriyor.')
    parsed = urlsplit(url if '://' in url else 'https://' + url)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTarget('Yalnızca kimlik bilgisi içermeyen HTTP(S) adresleri taranabilir.')
    try:
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        host = parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()
    except (ValueError, UnicodeError) as exc:
        raise UnsafeTarget('Geçersiz adres veya port.') from exc
    if port not in (80, 443):
        raise UnsafeTarget('Yalnızca 80 ve 443 portlarına izin verilir.')
    if host in ('localhost', 'metadata.google.internal') or host.endswith(('.localhost', '.local', '.internal')):
        raise UnsafeTarget('Yerel ve özel ağ adreslerine izin verilmez.')
    addresses = []
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        if resolve:
            try:
                addresses = [ipaddress.ip_address(r[4][0]) for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
            except socket.gaierror as exc:
                raise UnsafeTarget('Alan adı çözümlenemedi.') from exc
    if any(not address.is_global or (getattr(address, 'ipv4_mapped', None) and not address.ipv4_mapped.is_global) for address in addresses):
        raise UnsafeTarget('Yerel, ayrılmış ve özel ağ adreslerine izin verilmez.')
    if resolve and not addresses:
        raise UnsafeTarget('Adres çözümlenemedi.')
    authority = '[' + host + ']' if ':' in host else host
    if port != (443 if parsed.scheme == 'https' else 80):
        authority += ':' + str(port)
    normalized = urlunsplit((parsed.scheme.lower(), authority, parsed.path or '/', parsed.query, ''))
    return normalized, host, port, str(addresses[0]) if addresses else None


def safe_request(method, url, *, headers=None, data=None, json_body=None, timeout=8, allow_redirects=True, max_bytes=2_000_000):
    """Validate every redirect; connect to the validated IP while retaining TLS SNI."""
    started = time.monotonic()
    history = []
    body = json.dumps(json_body).encode() if json_body is not None else data
    for _ in range(6):
        normalized, host, port, address = validate_url(url)
        request_headers = {**(headers or {}), 'Host': urlsplit(normalized).netloc}
        if json_body is not None:
            request_headers.setdefault('Content-Type', 'application/json')
        pool_class = urllib3.HTTPSConnectionPool if normalized.startswith('https:') else urllib3.HTTPConnectionPool
        kwargs = {'server_hostname': host, 'assert_hostname': host, 'cert_reqs': 'CERT_REQUIRED'} if normalized.startswith('https:') else {}
        pool = pool_class(address, port=port, **kwargs)
        response = None
        try:
            parsed = urlsplit(normalized)
            response = pool.urlopen(method, urlunsplit(('', '', parsed.path, parsed.query, '')), body=body,
                                    headers=request_headers, redirect=False, retries=False, preload_content=False,
                                    timeout=urllib3.Timeout(connect=min(timeout, 4), read=timeout, total=timeout))
            chunks, size = [], 0
            for chunk in response.stream(65536, decode_content=True):
                size += len(chunk)
                if size > max_bytes or time.monotonic() - started > max(15, timeout * 2):
                    raise requests.RequestException('Yanıt boyutu veya süre sınırı aşıldı.')
                chunks.append(chunk)
            result = requests.Response()
            result.status_code = response.status
            result.headers.update(response.headers)
            result._content = b''.join(chunks)
            result.url = normalized
            result.encoding = requests.utils.get_encoding_from_headers(result.headers)
            result.history = history[:]
            if allow_redirects and result.is_redirect:
                destination = urljoin(normalized, result.headers['Location'])
                # Validate scheme and origin before the next request; DNS is pinned
                # again by validate_url at the start of the next iteration.
                target_url, target_host, target_port, _ = validate_url(destination, resolve=False)
                if parsed.scheme == 'https' and urlsplit(target_url).scheme != 'https':
                    raise UnsafeTarget('HTTPS bağlantısı şifresiz adrese yönlendirilemez.')
                cross_origin = (parsed.scheme, host, port) != (urlsplit(target_url).scheme, target_host, target_port)
                if cross_origin and (method.upper() not in ('GET', 'HEAD') or body is not None):
                    raise UnsafeTarget('İstek içeriği başka bir adrese yönlendirilemez.')
                history.append(result)
                url = target_url
                if cross_origin:
                    # Custom API keys, signatures and Referer can also contain secrets.
                    allowed = {'accept', 'accept-language', 'user-agent', 'accept-encoding'}
                    headers = {k: v for k, v in (headers or {}).items() if k.lower() in allowed}
                if result.status_code == 303 or (result.status_code == 302 and method.upper() != 'HEAD') or (result.status_code == 301 and method.upper() == 'POST'):
                    if method.upper() != 'HEAD':
                        method = 'GET'
                    body, json_body = None, None
                    headers = {k: v for k, v in (headers or {}).items()
                               if k.lower() not in ('content-type', 'content-length', 'transfer-encoding')}
                continue
            return result
        except urllib3.exceptions.HTTPError as exc:
            raise requests.RequestException('Dış adrese bağlantı kurulamadı.') from exc
        finally:
            if response is not None:
                response.close()
            pool.close()
    raise requests.TooManyRedirects('Çok fazla yönlendirme.')


def safe_get(url, **kwargs):
    return safe_request('GET', url, **kwargs)


def guard_browser_context(context):
    """Fetch browser resources through the pinned transport; never let Chromium dial a target."""
    def route_request(route):
        request = route.request
        try:
            if request.method not in ('GET', 'HEAD') or request.resource_type in ('media', 'websocket'):
                return route.abort()
            response = safe_request(request.method, request.url, headers={'User-Agent': request.headers.get('user-agent', 'AegisNexus')}, allow_redirects=False)
            response_headers = {k: v for k, v in response.headers.items() if k.lower() not in ('content-encoding', 'content-length', 'transfer-encoding', 'set-cookie')}
            route.fulfill(status=response.status_code, headers=response_headers, body=response.content)
        except (ValueError, requests.RequestException):
            route.abort()
    context.add_init_script("Object.defineProperty(window, 'RTCPeerConnection', {value: undefined}); Object.defineProperty(window, 'WebTransport', {value: undefined});")
    context.route('**/*', route_request)
    if hasattr(context, 'route_web_socket'):
        context.route_web_socket('**/*', lambda ws: ws.close())
