# 📊 Frontend Grafik Rehberi

**IoC ve Phishing verilerini dashboard'da görselleştirme**

---

## 🎯 Gerekli Kütüphane

```html
<!-- Chart.js CDN -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
```

---

## 📈 1. IoC Risk Dağılımı (Pie Chart)

### API Endpoint
```javascript
const API_BASE = '/api/v2';

// Risk dağılımını çek
const response = await fetch(`${API_BASE}/honeypot/ioc/stats`);
const data = await response.json();

// data.risk_distribution formatı:
// [
//   { "range": "Düşük (0-20)", "count": 5, "percentage": 0.07 },
//   { "range": "Orta-Düşük (21-40)", "count": 5, "percentage": 0.07 },
//   { "range": "Orta (41-60)", "count": 0, "percentage": 0 },
//   { "range": "Orta-Yüksek (61-80)", "count": 0, "percentage": 0 },
//   { "range": "Yüksek (81-100)", "count": 7043, "percentage": 99.86 }
// ]
```

### HTML
```html
<canvas id="riskChart" width="400" height="300"></canvas>
```

### JavaScript
```javascript
async function loadRiskChart() {
  const response = await fetch('/api/v2/honeypot/ioc/stats');
  const { risk_distribution } = await response.json();
  
  const ctx = document.getElementById('riskChart').getContext('2d');
  
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: risk_distribution.map(d => d.range),
      datasets: [{
        data: risk_distribution.map(d => d.count),
        backgroundColor: [
          '#22c55e',  // Düşük - Yeşil
          '#84cc16',  // Orta-Düşük - Açık Yeşil
          '#eab308',  // Orta - Sarı
          '#f97316',  // Orta-Yüksek - Turuncu
          '#ef4444'   // Yüksek - Kırmızı
        ],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'IoC Risk Dağılımı'
        },
        legend: {
          position: 'bottom'
        }
      }
    }
  });
}

// Sayfa yüklendiğinde çalıştır
loadRiskChart();
```

---

## 📊 2. Haftalık IoC Artışı (Line Chart)

### API Endpoint
```javascript
// weekly_growth formatı:
// [
//   { "date": "2026-04-13", "count": 450 },
//   { "date": "2026-04-14", "count": 520 },
//   ...
//   { "date": "2026-04-20", "count": 7053 }
// ]
```

### HTML
```html
<canvas id="weeklyChart" width="600" height="300"></canvas>
```

### JavaScript
```javascript
async function loadWeeklyChart() {
  const response = await fetch('/api/v2/honeypot/ioc/stats');
  const { weekly_growth } = await response.json();
  
  const ctx = document.getElementById('weeklyChart').getContext('2d');
  
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: weekly_growth.map(d => d.date.slice(5)), // MM-DD format
      datasets: [{
        label: 'Günlük IoC Sayısı',
        data: weekly_growth.map(d => d.count),
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'Son 7 Gün IoC Artışı'
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

loadWeeklyChart();
```

---

## 📊 3. Top Tehdit Tipleri (Bar Chart)

### API Endpoint
```javascript
// top_threats formatı:
// [
//   { "type": "malware", "count": 3500 },
//   { "type": "phishing", "count": 2100 },
//   { "type": "c2_server", "count": 1453 }
// ]
```

### HTML
```html
<canvas id="threatChart" width="600" height="300"></canvas>
```

### JavaScript
```javascript
async function loadThreatChart() {
  const response = await fetch('/api/v2/honeypot/ioc/stats');
  const { top_threats } = await response.json();
  
  const ctx = document.getElementById('threatChart').getContext('2d');
  
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top_threats.map(t => t.type.toUpperCase()),
      datasets: [{
        label: 'Tehdit Sayısı',
        data: top_threats.map(t => t.count),
        backgroundColor: [
          '#ef4444',
          '#f97316',
          '#eab308',
          '#22c55e',
          '#3b82f6'
        ]
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'En Çok Görülen Tehdit Tipleri'
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

loadThreatChart();
```

---

## 📊 4. Phishing Domain İstatistikleri (Horizontal Bar)

### API Endpoint
```javascript
// top_domains formatı:
// [
//   { "domain": "evil-site.com", "count": 523 },
//   { "domain": "fake-bank.net", "count": 412 },
//   ...
// ]
```

### HTML
```html
<canvas id="domainChart" width="600" height="400"></canvas>
```

### JavaScript
```javascript
async function loadDomainChart() {
  const response = await fetch('/api/v2/phishing/stats');
  const { top_domains } = await response.json();
  
  // İlk 10 domain
  const top10 = top_domains.slice(0, 10);
  
  const ctx = document.getElementById('domainChart').getContext('2d');
  
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top10.map(d => d.domain),
      datasets: [{
        label: 'Phishing URL Sayısı',
        data: top10.map(d => d.count),
        backgroundColor: '#8b5cf6'
      }]
    },
    options: {
      indexAxis: 'y',  // Yatay bar
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: 'En Çok Phishing Yapılan Domainler'
        }
      }
    }
  });
}

loadDomainChart();
```

---

## 📊 5. Canlı Sayaçlar (Realtime Stats)

### HTML
```html
<div class="stats-grid">
  <div class="stat-card">
    <h3>Toplam IoC</h3>
    <div class="stat-value" id="iocCount">-</div>
  </div>
  <div class="stat-card">
    <h3>Toplam Phishing URL</h3>
    <div class="stat-value" id="phishingCount">-</div>
  </div>
  <div class="stat-card">
    <h3>Bugün Eklenen</h3>
    <div class="stat-value" id="todayCount">-</div>
  </div>
</div>
```

### CSS
```css
.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
  margin: 20px 0;
}

.stat-card {
  background: linear-gradient(135deg, #1e293b, #0f172a);
  color: white;
  padding: 30px;
  border-radius: 12px;
  text-align: center;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.stat-value {
  font-size: 48px;
  font-weight: bold;
  color: #22d3ee;
  margin-top: 10px;
}
```

### JavaScript
```javascript
async function loadStats() {
  // Paralel fetch
  const [iocRes, phishingRes] = await Promise.all([
    fetch('/api/v2/honeypot/ioc/stats'),
    fetch('/api/v2/phishing/stats')
  ]);
  
  const iocData = await iocRes.json();
  const phishingData = await phishingRes.json();
  
  // Animasyonlu sayaç
  animateValue('iocCount', 0, iocData.total_records || iocData.stats?.total_iocs || 0, 1000);
  animateValue('phishingCount', 0, phishingData.total_urls || phishingData.toplam_zararli_site || 0, 1000);
  animateValue('todayCount', 0, iocData.today_added || 0, 1000);
}

// Animasyon fonksiyonu
function animateValue(id, start, end, duration) {
  const obj = document.getElementById(id);
  const range = end - start;
  const increment = end > start ? 1 : -1;
  const stepTime = Math.abs(Math.floor(duration / range));
  let current = start;
  
  const timer = setInterval(() => {
    current += Math.ceil(range / 20);
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      current = end;
      clearInterval(timer);
    }
    obj.textContent = current.toLocaleString('tr-TR');
  }, 50);
}

// Sayfa yüklendiğinde ve her 30 saniyede bir güncelle
loadStats();
setInterval(loadStats, 30000);
```

---

## 🎯 Tam Dashboard HTML Örneği

```html
<!DOCTYPE html>
<html>
<head>
  <title>AegisNexus Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      font-family: 'Inter', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 20px;
    }
    .dashboard {
      max-width: 1400px;
      margin: 0 auto;
    }
    h1 {
      text-align: center;
      color: #22d3ee;
      margin-bottom: 40px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 20px;
    }
    .card {
      background: #1e293b;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    canvas {
      max-height: 300px;
    }
  </style>
</head>
<body>
  <div class="dashboard">
    <h1>🛡️ AegisNexus Tehdit İstihbaratı Dashboard</h1>
    
    <div class="stats-grid">
      <div class="stat-card">
        <h3>Toplam IoC</h3>
        <div class="stat-value" id="iocCount">-</div>
      </div>
      <div class="stat-card">
        <h3>Toplam Phishing URL</h3>
        <div class="stat-value" id="phishingCount">-</div>
      </div>
      <div class="stat-card">
        <h3>Yüksek Riskli IoC</h3>
        <div class="stat-value" id="highRiskCount" style="color: #ef4444;">-</div>
      </div>
    </div>
    
    <div class="grid">
      <div class="card">
        <canvas id="riskChart"></canvas>
      </div>
      <div class="card">
        <canvas id="weeklyChart"></canvas>
      </div>
      <div class="card">
        <canvas id="threatChart"></canvas>
      </div>
      <div class="card">
        <canvas id="domainChart"></canvas>
      </div>
    </div>
  </div>

  <script>
    // Yukarıdaki tüm load fonksiyonlarını çağır
    loadStats();
    loadRiskChart();
    loadWeeklyChart();
    loadThreatChart();
    loadDomainChart();
    
    // 30 saniyede bir güncelle
    setInterval(() => {
      loadStats();
    }, 30000);
  </script>
</body>
</html>
```

---

## 📚 API Endpoint Özeti

| Veri | Endpoint | Kullanım |
|------|----------|----------|
| IoC Stats | `GET /api/v2/honeypot/ioc/stats` | Risk dağılımı, günlük artış |
| Phishing Stats | `GET /api/v2/phishing/stats` | Domain istatistikleri |
| Honeypot Stats | `GET /api/v2/honeypot/stats` | Session verileri |

---

**Hazır!** 🎉 Tüm grafikler canlı veri ile çalışıyor.
