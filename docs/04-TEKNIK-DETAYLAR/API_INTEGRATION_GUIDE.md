# 🔐 Aegis Nexus API Integration Guide

## 📍 API Endpoints

**Base URL:** `http://104.248.45.198:5000/api/v1`

### 1. ✅ Health Check
```
GET /api/v1/health
```
**Yanıt:**
```json
{
  "status": "healthy",
  "timestamp": "2026-04-16T13:46:29.220912Z",
  "version": "1.0"
}
```

---

## 🔍 URL Güvenlik Kontrolü

### Single URL Check
```
GET /api/v1/check-url?url=<domain>
```

**Parametreler:**
- `url` (gerekli): Kontrol edilecek URL veya domain

**Yanıt:**
```json
{
  "url": "https://google.com",
  "score": 100,
  "risk_level": "✅ Güvenli",
  "timestamp": "2026-04-16T13:46:30.099399Z"
}
```

**Risk Seviyeleri:**
- `✅ Güvenli` - Score ≥ 80
- `⚠️ Şüpheli` - Score 60-79
- `🚨 Riskli` - Score 40-59
- `❌ Tehlikeli` - Score < 40

---

## 📋 Toplu Tarama (Bulk Scan)

### File Upload
```
POST /api/v1/bulk-scan
Content-Type: multipart/form-data
```

**CSV Format:**
```
https://google.com
https://paypal.com
https://suspicious-site.com
```

**Yanıt:**
```json
{
  "total": 4,
  "processed": 4,
  "safe": 2,
  "medium": 0,
  "high_risk": 0,
  "critical": 2,
  "timestamp": "2026-04-16T13:45:24.422199Z",
  "results": [
    {
      "url": "https://google.com",
      "score": 100,
      "risk_level": "✅ Güvenli"
    }
  ]
}
```

---

## 🛡️ Whitelist Yönetimi

### Get Whitelist
```
GET /api/v1/whitelist?category=<category>&limit=50
```

**Parametreler:**
- `category` (opsiyonel): Kategori filtresi
- `limit` (opsiyonel): Sonuç limiti (default: 50)

**Yanıt:**
```json
{
  "total": 232,
  "returned": 50,
  "domains": [
    {
      "domain": "google.com",
      "category": "Tech Companies",
      "company_name": "Google LLC",
      "trusted_level": "Verified",
      "verified": true
    }
  ]
}
```

### Add Domain to Whitelist
```
POST /api/v1/whitelist
Content-Type: application/json

{
  "domain": "example.com",
  "category": "Finance",
  "company_name": "Example Corp",
  "description": "Our trusted partner"
}
```

---

## 📊 İstatistikler

### Get Stats
```
GET /api/v1/stats
```

**Yanıt:**
```json
{
  "whitelist_domains": 232,
  "categories": {
    "Tech Companies": 12,
    "Finance": 14,
    "Education": 9
  },
  "last_update": "2026-04-16T13:46:29.220912Z"
}
```

---

## 🚀 Frontend Entegrasyonu

### JavaScript/Fetch Örneği

#### 1. Tek URL Kontrol
```javascript
async function checkUrl(url) {
  const response = await fetch(
    `http://104.248.45.198:5000/api/v1/check-url?url=${encodeURIComponent(url)}`
  );
  const data = await response.json();
  
  console.log(`Score: ${data.score}`);
  console.log(`Risk: ${data.risk_level}`);
  
  return data;
}
```

#### 2. Toplu Tarama
```javascript
async function bulkScan(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch(
    'http://104.248.45.198:5000/api/v1/bulk-scan',
    {
      method: 'POST',
      body: formData
    }
  );
  
  const data = await response.json();
  return data;
}
```

#### 3. Form Entegrasyonu
```html
<form id="urlForm">
  <input type="text" id="urlInput" placeholder="URL girin...">
  <button type="submit">Kontrol Et</button>
  <div id="result"></div>
</form>

<script>
document.getElementById('urlForm').onsubmit = async (e) => {
  e.preventDefault();
  const url = document.getElementById('urlInput').value;
  const data = await checkUrl(url);
  
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = `
    <p>Score: ${data.score}/100</p>
    <p>Risk Level: ${data.risk_level}</p>
  `;
};
</script>
```

---

## 📱 React Entegrasyonu

```javascript
import { useState } from 'react';

function URLChecker() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const checkUrl = async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `http://104.248.45.198:5000/api/v1/check-url?url=${encodeURIComponent(url)}`
      );
      const data = await res.json();
      setResult(data);
    } catch (error) {
      console.error('Error:', error);
    }
    setLoading(false);
  };

  return (
    <div>
      <input 
        value={url} 
        onChange={(e) => setUrl(e.target.value)} 
        placeholder="URL girin..."
      />
      <button onClick={checkUrl} disabled={loading}>
        {loading ? 'Taranıyor...' : 'Kontrol Et'}
      </button>
      
      {result && (
        <div>
          <h3>Score: {result.score}/100</h3>
          <p>Risk: {result.risk_level}</p>
        </div>
      )}
    </div>
  );
}

export default URLChecker;
```

---

## 🌐 Hata Yönetimi

### Error Response
```json
{
  "error": "URL formatting error",
  "message": "Invalid URL provided",
  "timestamp": "2026-04-16T13:46:29.220912Z"
}
```

### HTTP Status Codes
- `200` - Başarılı
- `400` - Bad Request (geçersiz parametre)
- `429` - Rate Limited (60 req/min limit aşıldı)
- `500` - Server Error

### Try-Catch Örneği
```javascript
async function checkUrl(url) {
  try {
    const response = await fetch(
      `http://104.248.45.198:5000/api/v1/check-url?url=${encodeURIComponent(url)}`
    );
    
    if (!response.ok) {
      if (response.status === 429) {
        throw new Error('Rate limit exceeded. Try again later.');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error:', error.message);
    // Fallback veya error handling
    return null;
  }
}
```

---

## ⏱️ Rate Limiting

- **Limit:** 60 requests/minute per IP
- **Header:** `X-RateLimit-Remaining` yanıt headerında
- **Status:** 429 (Too Many Requests) ise bekleyin

```javascript
async function checkUrlWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    const response = await fetch(
      `http://104.248.45.198:5000/api/v1/check-url?url=${encodeURIComponent(url)}`
    );
    
    if (response.status === 429) {
      // Rate limited, wait and retry
      await new Promise(r => setTimeout(r, 2000));
      continue;
    }
    
    return await response.json();
  }
  throw new Error('Max retries exceeded');
}
```

---

## 📧 WordPress Plugin Örneği

```php
<?php
/**
 * Plugin Name: Aegis Nexus URL Checker
 * Description: Gerçek zamanlı URL güvenlik kontrol
 */

function aegis_check_url($url) {
    $api_base = 'http://104.248.45.198:5000/api/v1';
    $response = wp_remote_get(
        $api_base . '/check-url?url=' . urlencode($url)
    );
    
    if (is_wp_error($response)) {
        return null;
    }
    
    return json_decode(wp_remote_retrieve_body($response));
}

add_shortcode('aegis_checker', function() {
    return '
    <form method="post">
        <input type="text" name="url" placeholder="URL girin...">
        <button type="submit">Kontrol Et</button>
    </form>
    ' . (isset($_POST['url']) ? '<p>Score: ' . aegis_check_url($_POST['url'])->score . '/100</p>' : '');
});
```

---

## 🔌 Browser Extension Örneği

```javascript
// manifest.json
{
  "manifest_version": 3,
  "name": "Aegis Nexus",
  "version": "1.0",
  "permissions": ["activeTab", "scripting"],
  "host_permissions": ["http://104.248.45.198/*"],
  "action": {
    "default_popup": "popup.html"
  }
}

// popup.html
<div id="result"></div>
<script>
  chrome.tabs.query({active: true}, async (tabs) => {
    const url = new URL(tabs[0].url).hostname;
    const res = await fetch(
      `http://104.248.45.198:5000/api/v1/check-url?url=${url}`
    );
    const data = await res.json();
    document.getElementById('result').innerHTML = `
      Score: ${data.score}/100<br>
      Status: ${data.risk_level}
    `;
  });
</script>
```

---

## 🧪 Interaktif Test Sayfası

**URL:** Frontend clasöründe `api-test.html` dosyasını açın

Özellikler:
- ✅ Tek URL kontrolü
- ✅ Toplu tarama (CSV upload)
- ✅ Whitelist yönetimi
- ✅ İstatistikler
- ✅ Gerçek zamanlı yanıtlar

---

## 📞 Destek & Troubleshooting

### Problem: "Connection refused"
- API sunucusunun çalışıp çalışmadığını kontrol edin:
```bash
curl http://104.248.45.198:5000/api/v1/health
```

### Problem: Rate limit exceeded
- 60 req/min limitini aşmayın
- Retry logic ekleyin
- Batch işlemler için `bulk-scan` kullanın

### Problem: Invalid URL error
- URL'yi düzelt (örn: `example.com` → `https://example.com`)
- URL encoding kullanın: `encodeURIComponent(url)`

---

## 📚 Daha Fazla Bilgi

- API Endpoints: `/api/v1/`
- Health Check: `/api/v1/health`
- Documentation: Bu dosya
- Test Dashboard: `frontend/api-test.html`
