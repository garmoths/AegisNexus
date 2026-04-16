# 🎨 Aegis Nexus Frontend

## 🧪 API Test Dashboard

**File:** `api-test.html`

### Features
- ✅ **Single URL Check** - Gerçek zamanlı URL kontrol
- ✅ **Bulk Scanning** - CSV dosyası yükle, toplu tarama yap
- ✅ **Whitelist Management** - Güvenilen domainleri görüntüle ve filtrele
- ✅ **Statistics** - Sistem istatistiklerini görüntüle

### How to Use

1. **Dosyayı açın:**
   - Local: `file:///path/to/api-test.html` (tarayıcıda aç)
   - Web: `http://104.248.45.198/api-test.html` (eğer web server'da hosting edilirse)

2. **Tek URL Kontrol Et:**
   - "Tek URL" tabına git
   - URL gir (örn: `google.com` veya `https://example.com`)
   - "Kontrol Et" tıkla
   - Sonuç görebilirsin

3. **Toplu Tarama:**
   - "Toplu Tarama" tabına git
   - CSV dosyası seç (format: bir URL per satır)
   - "Taramayı Başlat" tıkla
   - Tüm URL'lerin sonuçlarını görebilirsin

4. **Whitelist Yönetimi:**
   - "Whitelist" tabına git
   - (Opsiyonel) Kategori filtresi gir
   - "Yükle" tıkla
   - Güvenilen domainleri görebilirsin

5. **İstatistikler:**
   - "İstatistikler" tabına git
   - "İstatistikleri Yükle" tıkla
   - Sistem istatistiklerini görebilirsin

### API Endpoints Used

- `GET /api/v1/check-url?url=<domain>` - Tek URL kontrol
- `POST /api/v1/bulk-scan` - CSV toplu tarama
- `GET /api/v1/whitelist?category=<cat>&limit=50` - Whitelist listeleme
- `GET /api/v1/stats` - İstatistikler

### Screenshots & Examples

#### Example 1: Single URL Check
```
Input: google.com
Output:
  Score: 100/100
  Risk Level: ✅ Güvenli
```

#### Example 2: Bulk Scan Results
```
URLs Processed: 4
- safe: 2
- high_risk: 0
- critical: 2
```

### Integration with Your Project

You can embed the dashboard in your main web application:

```html
<iframe src="api-test.html" width="100%" height="800"></iframe>
```

Or use individual components:

```html
<!-- Just the URL checker -->
<input type="text" id="urlInput" placeholder="URL">
<button onclick="checkUrl()">Check</button>
<div id="result"></div>
```

### Troubleshooting

**API not responding?**
- Check if API server is running:
  ```bash
  curl http://104.248.45.198:5000/api/v1/health
  ```

**CORS errors?**
- API server has CORS enabled for all origins
- If issues persist, check browser console for details

**Rate limit exceeded?**
- Wait 1 minute and retry
- Use bulk-scan for multiple URLs

### Development

To modify the dashboard:

1. Edit `api-test.html` directly
2. Modify the `<style>` section for design
3. Modify the JavaScript functions for functionality
4. Reload in browser to see changes

### Deployment

To serve via web server:

```bash
# Copy to your web server directory
cp api-test.html /var/www/html/

# Access via: http://your-domain/api-test.html
```

---

**API Documentation:** See `docs/API_INTEGRATION_GUIDE.md`
