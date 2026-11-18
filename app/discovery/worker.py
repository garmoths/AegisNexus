"""Bounded crawl worker usable from CLI, the local supervisor or Celery."""
from datetime import timedelta
import hashlib
import json
import os
import subprocess
import sys
from urllib.parse import urlsplit, urljoin

import requests
from app.database import SessionLocal
from app import runtime_store as store
from app.models import CrawlCandidate, CrawlObservation, CrawlSource
from app.discovery import service
from app.discovery.analysis import canonical_url, extract, assess
from app.discovery.transport import fetch_page, CrawlBlocked
from app.outbound import UnsafeTarget, safe_get


def release(key, token):
    # Only the owner may release a lease, including after a process stall.
    with store.connection() as db:
        db.execute('DELETE FROM kv WHERE key=? AND value=?', (key, json.dumps(token)))


def run_one(sessions=SessionLocal):
    with sessions() as db:
        config = service.settings(db)
        if not config.enabled:
            return {'state': 'paused'}
        candidate, token = service.claim(db)
        if candidate is None:
            return {'state': 'idle'}
        candidate_id = candidate.id
        host_key = 'crawler:host:' + candidate.host
        if not store.claim(host_key, token, 600):
            service.failure(db, candidate_id, token, 'host_busy', defer=True)
            return {'state': 'deferred'}
        try:
            if service.excluded(candidate.host, config):
                raise CrawlBlocked('excluded_host')
            if not store.claim('crawler:gap:' + candidate.host, token, 2):
                service.failure(db, candidate_id, token, 'host_cooldown', defer=True)
                return {'state': 'deferred'}
            day = service.now().strftime('%Y-%m-%d')
            if not store.increment('crawler:daily:' + day, ttl=172800, limit=config.daily_limit)[1]:
                service.failure(db, candidate_id, token, 'daily_budget', defer=True)
                return {'state': 'budget'}
            result = fetch_page(candidate.url, allowed=lambda host: not service.excluded(host, config))
            extra = {'redirects': result['redirects']}
            features = extract(result['html'], result['url'])
            initial = assess(features, http_status=result['status'])
            rendered, screenshot = False, None
            if config.browser_enabled and (initial['risk'] or 0) >= 35:
                if store.increment('crawler:browser:' + day, ttl=172800, limit=config.browser_limit)[1]:
                    try:
                        browser = render(result['url'], token, config.excluded_hosts)
                        if browser.get('html'):
                            result['html'], result['url'] = browser['html'], browser['url']
                            rendered, screenshot = True, browser.get('screenshot')
                            extra['browser'] = 'complete'
                        else:
                            extra['browser'] = 'unavailable'
                    except (subprocess.SubprocessError, OSError, ValueError):
                        extra['browser'] = 'unavailable'
                else:
                    extra['browser'] = 'budget_exhausted'
            favicon = features.get('favicon_url')
            if favicon:
                # Image fingerprinting only; never execute or publicly serve fetched content.
                try:
                    host = urlsplit(favicon).hostname
                    if host == candidate.host and not service.excluded(host, config):
                        from app.discovery.transport import robots_allows
                        if robots_allows(favicon):
                            icon = safe_get(favicon, timeout=3, max_bytes=128_000, allow_redirects=False)
                            if icon.status_code == 200 and 'html' not in icon.headers.get('Content-Type', '').lower():
                                extra['favicon_sha256'] = hashlib.sha256(icon.content).hexdigest()
                except (requests.RequestException, ValueError):
                    pass
            observation = service.finish(db, candidate_id, token, url=result['url'], html=result['html'],
                                         status=result['status'], rendered=rendered, screenshot=screenshot, extra=extra)
            if observation is not None and 200 <= result['status'] < 300:
                discover_links(db, candidate, observation.features)
                return {'state': 'review', 'candidate_id': candidate_id}
            return {'state': 'stale' if observation is None else 'review', 'candidate_id': candidate_id}
        except (CrawlBlocked, UnsafeTarget) as exc:
            service.failure(db, candidate_id, token, str(exc)[:100], retry=False)
            return {'state': 'blocked', 'candidate_id': candidate_id}
        except Exception:
            # Store a bounded error code, never a URL query or private response body.
            db.rollback()
            service.failure(db, candidate_id, token, 'fetch_failed')
            return {'state': 'retry', 'candidate_id': candidate_id}
        finally:
            store.put('crawler:gap:' + candidate.host, token, 2)
            release(host_key, token)


def discover_links(db, candidate, features):
    if candidate.depth >= 2:
        return
    root_id = candidate.root_id or candidate.id
    total = db.query(CrawlCandidate).filter((CrawlCandidate.root_id == root_id) | (CrawlCandidate.id == root_id)).count()
    # Only same-host pages are followed automatically. No unbounded external fan-out.
    links = features.get('links', [])
    ranked = sorted(links, key=lambda url: not any(word in url.lower() for word in ('login', 'giris', 'verify', 'account', 'odeme')))
    for url in ranked:
        if total >= 5:
            break
        if urlsplit(url).hostname != candidate.host:
            continue
        try:
            _, added = service.enqueue(db, url, source='link', reason=f'Aday #{candidate.id} içindeki bağlantı',
                                       depth=candidate.depth + 1, root_id=root_id)
            total += int(added)
        except ValueError:
            continue


def render(url, token, excluded_hosts):
    # Browser process lifetime and CPU/memory isolation are independent of API requests.
    process = subprocess.run([sys.executable, '-m', 'app.discovery.render', url, token,
                              json.dumps(excluded_hosts)], capture_output=True, text=True, timeout=40,
                             env={**os.environ, 'CRAWLER_DATA_DIR': str(service.artifacts())})
    if process.returncode != 0:
        return {}
    return json.loads(process.stdout)


def source_urls(body, kind):
    """Public URL lists or CT-style JSON. Every item is only an unverified candidate."""
    if kind == 'url_list':
        return [line.strip() for line in body.splitlines() if line.strip() and not line.lstrip().startswith('#')][:100]
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError('Kaynak JSON listesi olmalı.')
    urls = []
    for row in data[:100]:
        if isinstance(row, dict):
            names = row.get('name_value', '')
            if not isinstance(names, str):
                continue
            for name in names.splitlines()[:20]:
                if not name.startswith('*.'):
                    urls.append('https://' + name)
    return list(dict.fromkeys(urls))[:100]


def poll_sources(sessions=SessionLocal):
    with sessions() as db:
        config = service.settings(db)
        if not config.enabled:
            return 0
        # CertStream kaynağı saatlik GET ile çekilmez; onu certstream dinleyicisi yönetir.
        sources = db.query(CrawlSource).filter_by(enabled=True).filter(CrawlSource.kind != 'certstream').filter(
            (CrawlSource.last_checked_at.is_(None)) | (CrawlSource.last_checked_at < service.now() - timedelta(hours=1))).limit(5).all()
        total = 0
        for source in sources:
            token = os.urandom(16).hex()
            lease = f'crawler:source:{source.id}'
            if not store.claim(lease, token, 120):
                continue
            try:
                source_url = source.url
                for _ in range(6):
                    _, host, _ = canonical_url(source_url)
                    if service.excluded(host, config):
                        raise CrawlBlocked('excluded_host')
                    response = safe_get(source_url, timeout=8, max_bytes=1_000_000, allow_redirects=False)
                    if not response.is_redirect:
                        break
                    destination = urljoin(source_url, response.headers['Location'])
                    if source_url.startswith('https:') and destination.startswith('http:'):
                        raise CrawlBlocked('https_downgrade')
                    source_url = destination
                else:
                    raise CrawlBlocked('redirect_limit')
                response.raise_for_status()
                added = 0
                for url in source_urls(response.text, source.kind):
                    try:
                        _, created = service.enqueue(db, url, source=source.name, reason='Kaynak aday kaydı; phishing olduğu doğrulanmadı')
                        added += int(created)
                    except ValueError:
                        continue
                source.added_count += added
                source.last_error = None
                total += added
            except Exception:
                db.rollback()
                source.last_error = 'source_unavailable'
            finally:
                source.last_checked_at = service.now()
                db.commit()
                release(lease, token)
        return total


def schedule_rechecks(sessions=SessionLocal):
    """Withdraw our aging verdicts and require a new observation and decision."""
    with sessions() as db:
        config = service.settings(db)
        if not config.enabled:
            return 0
        rows = db.query(CrawlCandidate).filter(
            CrawlCandidate.state == 'confirmed',
            CrawlCandidate.updated_at < service.now() - timedelta(hours=24)).limit(20).all()
        for row in rows:
            if service.excluded(row.host, config):
                service.withdraw_publication(db, row.id)
                row.state, row.last_error = 'blocked', 'excluded_host'
                row.updated_at = service.now()
                db.commit()
                service.invalidate_verdict(row.url)
            else:
                service.requeue(db, row, 'scheduled_recheck')
        return len(rows)
