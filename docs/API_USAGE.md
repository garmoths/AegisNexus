# 🔐 Aegis Nexus API Kullanım Kılavuzu

## 📍 Base URL
```
http://104.248.45.198:5000/api/v1
```

---

## 🔍 1. Tek URL Kontrol

**Endpoint:** `GET /check-url`

**Parametreler:**
- `url` (required): Kontrol edilecek URL
- `detailed` (optional): `true` = detaylı bilgi

### cURL Örneği
```bash
curl "http://104.248.45.198:5000/api/v1/check-url?url=google.com"
```

### JavaScript Örneği
```javascript
fetch('http://104.248.45.198:5000/api/v1/check-url?url=google.com')
  .then(res => res.json())
  .then(data => {
    console.log(`Score: ${data.score}`);
    console.log(`Risk: ${data.risk_level}`);
    console.log(`URL: ${data.url}`);
  });
```

### Response
```json
{
  "url": "https://google.com",
  "score": 100,
  "risk_level": "✅ Güvenli",
  "timestamp": "2026-04-16T13:46:30Z"
}
```

---

## 📋 2. Toplu URL Taraması (Bulk Scan)

**Endpoint:** `POST /bulk-scan`

**Input:** CSV dosyası (bir URL per satır)

### cURL Örneği
```bash
cat > urls.csv << 'EOF'
https://google.com
https://amazon.com
https://suspicious-site.com
EOF

curl -X POST -F "file=@urls.csv" \
  "http://104.248.45.198:5000/api/v1/bulk-scan"
```

### JavaScript Örneği (HTML Form)
```html
<form id="bulkForm">
  <input type="file" id="csvFile" accept=".csv" required>
  <button type="submit">Taramayı Başlat</button>
  <div id="results"></div>
</form>

<script>
document.getElementById('bulkForm').onsubmit = async (e) => {
  e.preventDefault();
  
  const file = document.getElementById('csvFile').files[0];
  const formData = new FormData();
  formData.append('file', file);
  
  const res = await fetch('http://104.248.45.198:5000/api/v1/bulk-scan', {
    method: 'POST',
    body: formData
  });
  
  const data = await res.json();
  
  document.getElementById('results').innerHTML = `
    <h3>Sonuçlar</h3>
    <p>Toplam: ${data.total}</p>
    <p>🚨 Kritik: ${data.critical}</p>
    <p>🟠 Yüksek Risk: ${data.high_risk}</p>
    <p>✅ Güvenli: ${data.safe}</p>
    
    <table border="1">
      <tr><th>URL</th><th>Score</th><th>Risk</th></tr>
      ${data.results.map(r => `
        <tr>
          <td>${r.url}</td>
          <td>${r.score}</td>
          <td>${r.risk_level}</td>
        </tr>
      `).join('')}
    </table>
  `;
};
</script>
```

### Response
```json
{
  "total": 3,
  "processed": 3,
  "critical": 1,
  "high_risk": 0,
  "medium": 0,
  "safe": 2,
  "results": [
    {
      "url": "https://suspicious-site.com",
      "score": 15,
      "risk_level": "🚨 Tehlikeli"
    },
    {
      "url": "https://amazon.com",
      "score": 100,
      "risk_level": "✅ Güvenli"
    },
    {
      "url": "https://google.com",
      "score": 100,
      "risk_level": "✅ Güvenli"
    }
  ],
  "timestamp": "2026-04-16T13:45:24Z"
}
```

---

## 🛡️ 3. Whitelist Yönetimi

### 3a. Whitelist'i Görüntüle
**Endpoint:** `GET /whitelist`

```javascript
fetch('http://104.248.45.198:5000/api/v1/whitelist?limit=50&category=Tech')
  .then(res => res.json())
  .then(data => {
    console.log(`Toplam: ${data.total}`);
    data.domains.forEach(d => {
      console.log(`${d.domain} (${d.category})`);
    });
  });
```

### 3b. Domain Ekle
**Endpoint:** `POST /whitelist/add`

```javascript
fetch('http://104.248.45.198:5000/api/v1/whitelist/add', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    domain: 'mycompany.com',
    category: 'Custom',
    company_name: 'My Company',
    trusted_level: 'high'
  })
})
.then(res => res.json())
.then(data => console.log(data));
```

### 3c. Domain Çıkar
**Endpoint:** `POST /whitelist/remove`

```javascript
fetch('http://104.248.45.198:5000/api/v1/whitelist/remove', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    domain: 'mycompany.com'
  })
})
.then(res => res.json())
.then(data => console.log(data));
```

---

## 📊 4. İstatistikler

**Endpoint:** `GET /stats`

```javascript
fetch('http://104.248.45.198:5000/api/v1/stats')
  .then(res => res.json())
  .then(stats => {
    console.log(`Whitelist Domains: ${stats.whitelist_domains}`);
    console.log(`Categories: ${Object.keys(stats.categories).length}`);
    Object.entries(stats.categories).forEach(([cat, count]) => {
      console.log(`  ${cat}: ${count}`);
    });
  });
```

### Response
```json
{
  "whitelist_domains": 232,
  "categories": {
    "Tech Companies": 12,
    "Banks & Financial": 17,
    "Gaming": 11,
    ...
  },
  "last_update": "2026-04-16T13:39:14Z"
}
```

---

## ❤️ 5. Health Check

**Endpoint:** `GET /health`

```javascript
fetch('http://104.248.45.198:5000/api/v1/health')
  .then(res => res.json())
  .then(data => {
    if (data.status === 'healthy') {
      console.log('✅ API is online');
    }
  });
```

---

## ⚡ Rate Limiting

- **Limit:** 60 requests/minute per IP
- **Response Code:** 429 (Too Many Requests)

```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 60 requests per minute"
}
```

---

## 🎯 Risk Levels

| Score | Level | Emoji |
|-------|-------|-------|
| 80-100 | Güvenli | ✅ |
| 60-79 | Şüpheli | ⚠️ |
| 40-59 | Riskli | 🟠 |
| 0-39 | Tehlikeli | 🚨 |

---

## 🔗 Frontend Entegrasyonu

### Örnek: WordPress Plugin
```php
<?php
function check_link_safety($url) {
    $response = wp_remote_get(
        'http://104.248.45.198:5000/api/v1/check-url',
        ['body' => ['url' => $url]]
    );
    
    $data = json_decode(wp_remote_retrieve_body($response), true);
    
    if ($data['score'] < 30) {
        echo '<span style="color:red">🚨 Dangerous</span>';
    } elseif ($data['score'] < 80) {
        echo '<span style="color:orange">⚠️ Suspicious</span>';
    } else {
        echo '<span style="color:green">✅ Safe</span>';
    }
}
?>
```

### Örnek: Browser Extension
```javascript
// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkUrl') {
    fetch(`http://104.248.45.198:5000/api/v1/check-url?url=${request.url}`)
      .then(res => res.json())
      .then(data => {
        chrome.tabs.query({active: true}, (tabs) => {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: 'showResult',
            score: data.score,
            level: data.risk_level
          });
        });
      });
  }
});
```

---

## 🆘 Error Handling

```javascript
fetch('http://104.248.45.198:5000/api/v1/check-url?url=invalid')
  .then(res => res.json())
  .catch(error => {
    console.error('API Error:', error);
    // Fallback: assume safe
    showSafeWarning();
  });
```

---

## 📧 Support

- API Issues: Check `/api/v1/health`
- Database: `/var/www/aegis_nexus/data/whitelist.db`
- Logs: `/var/www/aegis_nexus/logs/api.log`

---

**API Version:** 1.0  
**Last Updated:** 2026-04-16  
**Status:** ✅ Production Ready
