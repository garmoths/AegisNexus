# 🚀 IOC FETCHER - FRANKFURT SUNUCUSUNA KURULUM

**Tarih:** 17 Nisan 2026  
**Server:** Ubuntu 20.04+ (Frankfurt)  
**Script:** `/var/www/aegis_nexus/scripts/ioc_fetcher.py`

---

## 📋 KURULUM ADIMLARI

### 1️⃣ Log Dizini Oluştur

```bash
sudo mkdir -p /var/log/aegis
sudo chmod 755 /var/log/aegis
sudo chown root:root /var/log/aegis
```

### 2️⃣ Script'i Çalıştırılabilir Yap

```bash
chmod +x /var/www/aegis_nexus/scripts/ioc_fetcher.py
```

### 3️⃣ Test Çalıştırma

```bash
cd /var/www/aegis_nexus
source venv/bin/activate
python scripts/ioc_fetcher.py
```

**Beklenen çıktı:**
```
2026-04-17 08:40:00 - INFO - ✅ Database connection successful
2026-04-17 08:40:01 - INFO - 🔄 Starting IOC collection from: abuse_urlhaus, abuse_phishtank, abuseipdb
2026-04-17 08:40:15 - INFO - ✅ Collected 523 IOCs
2026-04-17 08:40:20 - INFO - ✅ Persisted 450 new IOCs, 73 duplicates
...
🎯 IOC COLLECTION COMPLETE
========================
Collected: 523 IOCs
Persisted: 450 new IOCs
Errors: 0
Duration: 19.45s
```

### 4️⃣ Cron Job Kurulumu

**Option A: root crontab (Önerilir)**

```bash
sudo crontab -e
```

Ekle (her saat başında çalıştır):

```bash
# Run IOC Fetcher every hour at :00
0 * * * * cd /var/www/aegis_nexus && source venv/bin/activate && python scripts/ioc_fetcher.py >> /var/log/aegis/ioc_fetcher.log 2>&1

# Run daily backup at 3:00 AM
0 3 * * * pg_dump -U postgres phishing_db > /backups/ioc_$(date +\%Y\%m\%d).sql 2>&1
```

**Option B: Systemd Timer (Daha modern)**

Crontab yerine systemd timer'ı kullanmak istersen:

```bash
# File: /etc/systemd/system/aegis-ioc-fetcher.service
[Unit]
Description=AegisNexus IOC Fetcher
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/var/www/aegis_nexus
ExecStart=/bin/bash -c 'source venv/bin/activate && python scripts/ioc_fetcher.py'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# File: /etc/systemd/system/aegis-ioc-fetcher.timer
[Unit]
Description=Run AegisNexus IOC Fetcher hourly
Requires=aegis-ioc-fetcher.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable et:
```bash
sudo systemctl enable aegis-ioc-fetcher.timer
sudo systemctl start aegis-ioc-fetcher.timer
sudo systemctl status aegis-ioc-fetcher.timer
```

---

## 📊 MONITORING

### Logs'u İzle (Realtime)

```bash
# All logs
tail -f /var/log/aegis/ioc_collector.log

# Errors only
tail -f /var/log/aegis/ioc_collector_errors.log

# Last 100 lines
tail -100 /var/log/aegis/ioc_collector.log
```

### Cron Job'un Çalıştığını Kontrol Et

```bash
# Son çalıştırmalar
sudo journalctl -u aegis-ioc-fetcher.service -n 20

# Ya da crontab logs (Linux'ta)
sudo grep CRON /var/log/syslog | tail -20
```

### Database'de IOC Sayısını Kontrol Et

```bash
psql -U postgres -d phishing_db << EOF
SELECT 
    COUNT(*) as total_iocs,
    COUNT(CASE WHEN risk_score >= 95 THEN 1 END) as critical,
    COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as high_risk,
    MAX(created_at) as latest_fetch
FROM indicators_of_compromise;
EOF
```

---

## ⚙️ CONFIGURATION

### Veri Çekme Kaynakları Değiştir

`ioc_fetcher.py` içinde:

```python
iocs = self.fetch_iocs(sources=[
    "abuse_urlhaus",      # URLhaus
    "abuse_phishtank",    # PhishTank
    "abuseipdb",          # AbuseIPDB (hepsi mevcut)
])
```

### Çekme Frekansı Değiştir

**Crontab:**
```bash
# Her 30 dakika
*/30 * * * * ...

# Her 6 saatte bir
0 */6 * * * ...

# Haftada bir (Pazarları saat 2'de)
0 2 * * 0 ...
```

---

## 🔍 TROUBLESHOOTING

### Error: "Database connection failed"

```bash
# PostgreSQL çalışıyor mu?
systemctl status postgresql

# Credentials doğru mu?
psql -U postgres -d phishing_db -c "SELECT 1;"
```

### Error: "ModuleNotFoundError"

```bash
# venv aktif mı?
source /var/www/aegis_nexus/venv/bin/activate

# Dependencies yüklü mü?
pip list | grep requests sqlalchemy
```

### Error: "Permission denied on /var/log/aegis"

```bash
sudo chmod 777 /var/log/aegis
sudo chown root:root /var/log/aegis
```

---

## 📈 PERFORMANCE

**Tipik çalıştırma süreleri:**
- URLhaus: 5-10 saniye (~450 IOC)
- PhishTank: 3-5 saniye (~350 IOC)
- AbuseIPDB: 2-3 saniye (~170 IOC)
- Deduplication: 2-5 saniye
- DB persist: 5-10 saniye
- **TOTAL: ~20-30 saniye**

---

## 📋 CHECKLIST

Kurulum tamamlandı mı?

- [ ] Log dizini oluşturuldu (`/var/log/aegis`)
- [ ] Script çalıştırılabilir (`chmod +x`)
- [ ] Test çalıştırma başarılı
- [ ] Cron job ayarlandı (`crontab -e`)
- [ ] Logs görünüyor (`tail -f`)
- [ ] Database'de IOC'ler gözüküyor
- [ ] Hata log'u kontrol edildi (boş olmalı)

---

## 🚀 NEXT STEPS

1. ✅ IOC Fetcher script'i deploy et
2. ⏳ Cron job'u 2-3 gün çalıştır, verinin nasıl toplandığını gözlemle
3. ⏳ Threat Responder'da SMS entegrasyonunu yapılanaz
4. ⏳ Daily reports kurulacak

---

**Kurulum tamamlandı mı?** Sorun varsa yaz! 💪
