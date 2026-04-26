# Aegis Nexus — IOC Entegrasyon Rehberi
## abuse.ch Ekosistemi + Shodan InternetDB

---

## 1. abuse.ch Ekosistemi

abuse.ch tek bir API key ile 3 farklı servise erişim sağlar.
Key'i `https://abuse.ch` profilinden alabilirsin.

### 1.1 MalwareBazaar

**Ne işe yarar:** Hash (MD5, SHA1, SHA256) sorgulama. Malware ailesi, tehdit skoru, tag bilgisi döner.

**Endpoint:** `POST https://mb-api.abuse.ch/api/v1/`

**Kullanım:**
```python
import requests

ABUSE_API_KEY = "senin_key_buraya"

def check_hash(file_hash: str) -> dict:
    data = {
        "query": "get_info",
        "hash": file_hash
    }
    headers = {"API-KEY": ABUSE_API_KEY}
    
    r = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data=data,
        headers=headers,
        timeout=10
    )
    result = r.json()
    
    if result["query_status"] == "ok":
        entry = result["data"][0]
        return {
            "found": True,
            "malware_family": entry.get("signature"),
            "file_type": entry.get("file_type"),
            "threat_score": entry.get("intelligence", {}).get("clamav"),
            "tags": entry.get("tags", []),
            "first_seen": entry.get("first_seen"),
        }
    return {"found": False}
```

**Örnek Dönüş:**
```json
{
  "found": true,
  "malware_family": "Emotet",
  "file_type": "exe",
  "tags": ["trojan", "banker"],
  "first_seen": "2024-01-15"
}
```

---

### 1.2 ThreatFox

**Ne işe yarar:** IP, domain, URL ve hash cross-check. IOC tipi, malware ailesi, confidence skoru döner. Projenle en uyumlu servis.

**Endpoint:** `POST https://threatfox-api.abuse.ch/api/v1/`

**Kullanım:**
```python
def check_ioc_threatfox(ioc_value: str) -> dict:
    data = {
        "query": "search_ioc",
        "search_term": ioc_value
    }
    headers = {"API-KEY": ABUSE_API_KEY}
    
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json=data,
        headers=headers,
        timeout=10
    )
    result = r.json()
    
    if result["query_status"] == "ok":
        entry = result["data"][0]
        return {
            "found": True,
            "ioc_type": entry.get("ioc_type"),       # ip:port, domain, url, md5_hash
            "threat_type": entry.get("threat_type"), # botnet_cc, payload_delivery vb.
            "malware": entry.get("malware"),
            "confidence": entry.get("confidence_level"),
            "tags": entry.get("tags", []),
        }
    return {"found": False}
```

**Örnek Dönüş:**
```json
{
  "found": true,
  "ioc_type": "ip:port",
  "threat_type": "botnet_cc",
  "malware": "Cobalt Strike",
  "confidence": 75,
  "tags": ["c2", "botnet"]
}
```

---

### 1.3 URLhaus

**Ne işe yarar:** URL ve domain sorgulama. Malware dağıtım URL'leri için. Zaten entegrasyonun var, cross-check için kullanabilirsin.

**Endpoint:** `POST https://urlhaus-api.abuse.ch/v1/url/`

**Kullanım:**
```python
def check_url_urlhaus(url: str) -> dict:
    r = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url},
        timeout=10
    )
    result = r.json()
    
    if result["query_status"] == "is_available":
        return {
            "found": True,
            "url_status": result.get("url_status"),  # online / offline
            "threat": result.get("threat"),
            "tags": result.get("tags", []),
        }
    return {"found": False}
```

---

## 2. Shodan InternetDB

**Ne işe yarar:** IP hakkında açık portlar, servisler, CVE'ler ve hostnames bilgisi döner. **Tamamen ücretsiz, kayıt gerektirmez, limitsiz.**

**Endpoint:** `GET https://internetdb.shodan.io/{ip}`

**Kullanım:**
```python
def check_ip_shodan(ip: str) -> dict:
    r = requests.get(
        f"https://internetdb.shodan.io/{ip}",
        timeout=10
    )
    
    if r.status_code == 200:
        data = r.json()
        return {
            "found": True,
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),       # çalışan servisler
            "vulns": data.get("vulns", []),     # CVE listesi
            "tags": data.get("tags", []),       # "vpn", "tor", "scanner" vb.
        }
    return {"found": False}
```

**Örnek Dönüş:**
```json
{
  "found": true,
  "open_ports": [22, 80, 443, 8080],
  "hostnames": ["mail.example.com"],
  "vulns": ["CVE-2021-44228"],
  "tags": ["scanner", "honeypot"]
}
```

> 💡 **İpucu:** `tags` alanında `"scanner"` veya `"tor"` görürsen o IP zaten şüpheli demektir. Confidence skoruna direkt +20 ekleyebilirsin.

---

## 3. Birleşik IP Reputation Fonksiyonu

Tüm kaynakları birleştiren tek fonksiyon:

```python
def get_ip_reputation(ip: str) -> dict:
    confidence = 0
    sources = []
    threat_types = []
    is_c2 = False

    # 1. Kendi IOC DB'ne bak
    local = check_local_ioc_db(ip)
    if local["found"]:
        confidence += 50
        sources.append("local_db")
        threat_types.append(local["type"])
        if local["type"] == "BOTNET":
            is_c2 = True

    # 2. ThreatFox cross-check
    tf = check_ioc_threatfox(ip)
    if tf["found"]:
        confidence += tf.get("confidence", 30)
        sources.append("threatfox")
        threat_types.append(tf["threat_type"])
        if tf["threat_type"] == "botnet_cc":
            is_c2 = True

    # 3. Shodan InternetDB
    shodan = check_ip_shodan(ip)
    if shodan["found"]:
        sources.append("shodan")
        if "scanner" in shodan["tags"]:
            confidence += 20
        if "tor" in shodan["tags"]:
            confidence += 15
        if shodan["vulns"]:
            confidence += 10

    return {
        "ip": ip,
        "malicious": confidence >= 40,
        "confidence": min(confidence, 100),
        "is_c2_server": is_c2,
        "threat_types": list(set(threat_types)),
        "open_ports": shodan.get("open_ports", []),
        "cves": shodan.get("vulns", []),
        "sources": sources
    }
```

---

## 4. FastAPI Endpoint

```python
from fastapi import APIRouter, Query

router = APIRouter(prefix="/api/v2/ioc", tags=["IOC"])

@router.get("/check-ip")
async def check_ip_reputation(ip: str = Query(..., description="Sorgulanacak IP adresi")):
    result = get_ip_reputation(ip)
    return {
        "status": "success",
        "data": result,
        "module": "02_honeypot_ioc"
    }

@router.post("/check-hash")
async def check_hash_reputation(payload: dict):
    file_hash = payload.get("hash")
    
    mb_result = check_hash(file_hash)
    tf_result = check_ioc_threatfox(file_hash)
    
    return {
        "status": "success",
        "hash": file_hash,
        "malwarebazaar": mb_result,
        "threatfox": tf_result,
        "malicious": mb_result["found"] or tf_result["found"],
        "module": "02_honeypot_ioc"
    }
```

---

## 5. AI Prompt Şablonu

Aşağıdaki şablonu Claude'a veya başka bir LLM'e yapıştır:

```
Sen bir FastAPI backend geliştiricisisin.

## Proje Bağlamı
- Proje adı: Aegis Nexus (siber güvenlik platformu)
- Python 3.12, FastAPI, SQLAlchemy
- Mevcut router: [router dosyasını buraya yapıştır]
- Mevcut IOC modeli: [models/ioc.py içeriğini buraya yapıştır]
- abuse.ch API key zaten .env'de: ABUSE_API_KEY

## Görev
Aşağıdaki 3 endpoint'i yaz:

### 1. GET /api/v2/ioc/check-ip?ip=1.2.3.4
Sırasıyla şu kaynaklara bak:
1. Kendi IOC veritabanı (SQLAlchemy ile)
2. ThreatFox API (abuse.ch)
3. Shodan InternetDB (key gerektirmez)

Confidence skoru hesapla:
- Kendi DB'de varsa: +50
- ThreatFox'ta varsa: +ThreatFox confidence değeri
- Shodan'da "scanner" tag'i varsa: +20
- Shodan'da "tor" tag'i varsa: +15
- Shodan'da CVE varsa: +10

Dön:
{
  "ip": "...",
  "malicious": true/false,
  "confidence": 0-100,
  "is_c2_server": true/false,
  "threat_types": [...],
  "open_ports": [...],
  "cves": [...],
  "sources": [...]
}

### 2. POST /api/v2/ioc/check-hash
Body: {"hash": "md5_veya_sha256"}
- MalwareBazaar API'ye sor
- ThreatFox'a cross-check at
Dön: found, malware_family, tags, confidence

### 3. Phishing Detector entegrasyonu
check-url endpoint'i çağrıldığında URL'deki domain ve IP'yi
otomatik olarak IOC DB'nde ve ThreatFox'ta kontrol et.
Eşleşme varsa score'a -30 ekle ve details'e "IOC listesinde bulundu" ekle.

## Dikkat
- Her API çağrısını try/except içine al
- Timeout: 10 saniye
- Async/await kullan
- Mevcut kod yapısını bozmadan sadece yeni endpoint ekle
```

---

## 6. Özet Tablo

| Servis | Tip | Limit | Key Gerekli? | En İyi Kullanım |
|--------|-----|-------|--------------|-----------------|
| MalwareBazaar | Hash | Yüksek | Evet (abuse.ch) | Malware hash lookup |
| ThreatFox | IP/Domain/Hash | Yüksek | Evet (abuse.ch) | IOC cross-check |
| URLhaus | URL/Domain | Yüksek | Hayır | URL/domain kontrolü |
| Shodan InternetDB | IP | Limitsiz | Hayır | Port/CVE/tag bilgisi |

---

> ⚠️ **Güvenlik Notu:** API key'ini asla koda gömmeden `.env` dosyasında tut ve `.gitignore`'a ekle.
