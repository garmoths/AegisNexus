# 🔄 API Key Rotation & Rate Limiting Guide

## Problem
- **VirusTotal**: 4 requests/minute limit (çok dar!)
- **Google Safe Browsing**: 10,000 requests/day
- **AbuseIPDB**: 1,500 requests/day
- **urlscan.io**: plan bazlı limit (free tier dar)

Sistem high-traffic altında bu limitlerde takılı kalıyor.

## Solution: API Key Rotation

Birden fazla API key kullanarak rate limit'i çoğalt:

### Setup

#### 1. Multiple API Keys Oluştur

**VirusTotal** (https://www.virustotal.com/gui/my-apikey):
- Ana hesabında key oluştur
- Paralel Google account'unda (Gmail ile signup) 2. key oluştur
- Artık 2 × 4 req/min = **8 req/min**!

**Google Safe Browsing** (https://console.cloud.google.com):
- Project 1 → API key
- Project 2 → API key
- Artık 2 × 10,000 req/day = **20,000 req/day**!

**AbuseIPDB** (https://www.abuseipdb.com/account/api):
- Hesap 1 → API key
- Hesap 2 → API key
- Artık 2 × 1,500 req/day = **3,000 req/day**!

#### 2. .env Dosyasına Ekle

```bash
# VirusTotal (comma-separated, boşluksuz)
VIRUSTOTAL_API_KEYS=key1,key2,key3

# Google Safe Browsing
GOOGLE_SAFE_BROWSING_KEYS=key1,key2

# AbuseIPDB
ABUSEIPDB_API_KEYS=key1,key2

# urlscan.io
URLSCAN_API_KEYS=key1,key2
```

#### 3. Sunucuyu Restart Et

```bash
cd /var/www/aegis_nexus

source venv/bin/activate

# Eski process'leri kapat
pkill -f uvicorn

# Yeni key'ler okunacak
sleep 1
nohup uvicorn app.api_server:app --host 0.0.0.0 --port 5000 > logs/uvicorn.log 2>&1 &

# Test
curl http://localhost:5000/api/v1/health
```

## How It Works

1. **Normal istek** → Key 1 kullan
2. **Rate limit hit** → Otomatik olarak Key 2'ye geç
3. **Key 2 de limit hit** → Key 3'e geç (varsa)
4. **Tüm key'ler limit hit** → "Rate limit exceeded" dönüş

Örnek log:
```
VirusTotal rate limit aşıldı, sonraki API key'e geçildi
Rotated VirusTotal key: 0 → 1
```

## Example .env

```bash
# Tekli key (eski sistem)
VIRUSTOTAL_API_KEY=abc123def456

# Multiple keys (yeni sistem - bu tercih edilir)
VIRUSTOTAL_API_KEYS=key1,key2,key3
GOOGLE_SAFE_BROWSING_KEYS=gkey1,gkey2
ABUSEIPDB_API_KEYS=akey1,akey2
```

## Rate Limits After Rotation

| Service | Single Key | 3 Keys | 5 Keys |
|---------|-----------|--------|--------|
| VirusTotal | 4/min | 12/min | 20/min |
| Google Safe | 10,000/day | 30,000/day | 50,000/day |
| AbuseIPDB | 1,500/day | 4,500/day | 7,500/day |

## Monitoring

Logs kontrol et:
```bash
tail -f /var/www/aegis_nexus/logs/uvicorn.log | grep -i "rotation\|rate"
```

## Troubleshooting

**Q: Neden hala rate limit alıyorum?**
A: Tüm key'ler exhausted olmuş. Daha fazla key ekle veya rate limit'i artır.

**Q: Key'ler nasıl reset olur?**
A: Her zaman penceresi (1 dakika VirusTotal, 1 gün diğerleri) geçince otomatik reset.

**Q: Yanlış key ekledim, nasıl düzeltim?**
A: `.env` dosyasını düzelt ve sunucuyu restart et.

## API Response Format

Rate limit aşıldığında şu response dönüyor:

```json
{
  "available": true,
  "status": "VirusTotal rate limit aşıldı (4 req/dakika) - başka key yok",
  "malicious": 0,
  "suspicious": 0,
  "clean": 0,
  "engines": [],
  "rate_limited": true
}
```

Sistem yine de:
- Cache kullanır (süresi içindeyse)
- Diğer API'lara fallback yapar
- Sonuçları hybrid mode'da birleştirir

## Best Practices

1. **Minimum 2 key al** - Her service için
2. **Different accounts kullan** - Aynı account'ta çoklu key'ler limit paylaşır
3. **Monitor logs** - Rotation gerçekleşiyor mu kontrol et
4. **Test load** - Bulk scan ile limitleri test et

```bash
# 100 URL'yi bulk scan et ve limitleri göz lemek et
for i in {1..100}; do echo "https://example$i.com"; done | curl -X POST -F "file=@-" https://api.aegisnexus.dev/api/v1/bulk-scan | jq .
```

---

**Sorun mu var?** Logs'u kontrol et:
```bash
tail -50 /var/www/aegis_nexus/logs/uvicorn.log
```
