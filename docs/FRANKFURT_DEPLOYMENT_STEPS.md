# 🚀 FRANKFURT PRODUCTION - STEP BY STEP DEPLOYMENT

**Date:** April 17, 2026  
**Server:** Ubuntu 20.04+ (Frankfurt)  
**Status:** Ready for deployment

---

## 📋 DEPLOYMENT CHECKLIST

### STEP 1: SSH into Frankfurt Server

```bash
ssh root@<frankfurt-ip>
cd /var/www/aegis_nexus
source venv/bin/activate
```

### STEP 2: Update Repository

```bash
git pull origin main
```

### STEP 3: PostgreSQL Setup (AS ROOT/SUPERUSER)

This MUST run as `postgres` user or root with sudo:

```bash
# Option A: Run SQL script (recommended)
sudo psql -U postgres -f scripts/db_setup.sql

# Option B: Manual setup
sudo -u postgres psql << 'EOF'
-- Create database
CREATE DATABASE phishing_db OWNER postgres ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8';

-- Connect to database
\c phishing_db

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;

-- Verify
\dt
EOF
```

Expected output:
```
CREATE DATABASE
CREATE EXTENSION
```

### STEP 4: Initialize Database Tables (AS APP USER)

```bash
# Still in /var/www/aegis_nexus with venv activated
python scripts/init_db.py
```

Expected output:
```
✅ Database initialization complete!

Created tables:
  - phishing_urls
  - whitelist_domains
  - honeypot_events
  - breach_records
  - password_checks
  - indicators_of_compromise
  - operator_api_keys
  - ioc_operator_alerts
```

### STEP 5: Verify Database Tables

```bash
psql -U postgres -d phishing_db -c "\dt"
```

Expected output:
```
            List of relations
 Schema |           Name            | Type  | Owner
--------+---------------------------+-------+----------
 public | breach_records            | table | postgres
 public | honeypot_events           | table | postgres
 public | indicators_of_compromise  | table | postgres
 public | ioc_operator_alerts       | table | postgres
 public | operator_api_keys         | table | postgres
 public | password_checks           | table | postgres
 public | phishing_urls             | table | postgres
 public | whitelist_domains         | table | postgres
(8 rows)
```

### STEP 6: Test IOC Fetcher (Dry Run)

```bash
python scripts/ioc_fetcher.py
```

Expected output:
```
✅ Database connection successful
🔄 Starting IOC collection from: abuse_urlhaus, abuse_phishtank, abuseipdb
✅ Collected XXX IOCs
✅ Persisted XXX new IOCs, X duplicates
Duration: XX.XXs
```

### STEP 7: Setup Cron Job (Automated Hourly)

```bash
sudo crontab -e
```

Add this line:
```bash
0 * * * * cd /var/www/aegis_nexus && source venv/bin/activate && python scripts/ioc_fetcher.py >> /var/log/aegis/ioc_fetcher.log 2>&1
```

### STEP 8: Setup Log Rotation

```bash
sudo cp scripts/ioc_logrotate.conf /etc/logrotate.d/aegis-ioc
sudo chmod 644 /etc/logrotate.d/aegis-ioc

# Test it
sudo logrotate -d /etc/logrotate.d/aegis-ioc
```

### STEP 9: Verify Cron Job Running

```bash
# Check if next run is scheduled
sudo crontab -l | grep ioc_fetcher

# Wait for next hour and check logs
tail -f /var/log/aegis/ioc_fetcher.log

# Or check system log
sudo grep CRON /var/log/syslog | tail -5
```

---

## 🔧 TROUBLESHOOTING

### Error: "permission denied for schema public"

**Cause:** PostgreSQL user doesn't have CREATE TABLE privileges

**Fix:**
```bash
# Run as root/superuser
sudo -u postgres psql -d phishing_db << 'EOF'
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
EOF
```

### Error: "psycopg2.OperationalError: could not connect to server"

**Cause:** PostgreSQL not running or connection details wrong

**Fix:**
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Check connection
psql -U postgres -d phishing_db -c "SELECT 1;"
```

### Error: "ModuleNotFoundError" when running scripts

**Cause:** Virtual environment not activated

**Fix:**
```bash
source /var/www/aegis_nexus/venv/bin/activate
```

### Cron job not running

**Cause:** Path or environment issue

**Fix:**
```bash
# Use full path in crontab
0 * * * * /bin/bash -c 'cd /var/www/aegis_nexus && source venv/bin/activate && python scripts/ioc_fetcher.py' >> /var/log/aegis/ioc_fetcher.log 2>&1

# Or add to root crontab
sudo crontab -e
```

---

## 📊 MONITORING

### Check Database Growth

```bash
psql -U postgres -d phishing_db -c "
SELECT 
    COUNT(*) as total_iocs,
    COUNT(CASE WHEN risk_score >= 95 THEN 1 END) as critical,
    COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as high_risk,
    MAX(created_at) as last_update
FROM indicators_of_compromise;
"
```

### View Recent Logs

```bash
tail -100 /var/log/aegis/ioc_fetcher.log
```

### Check Cron Execution

```bash
# View all cron job outputs (may require sudo)
sudo journalctl -u cron -n 20

# Or check syslog
sudo grep CRON /var/log/syslog | grep ioc_fetcher
```

---

## ✅ SUCCESS CRITERIA

- [x] Repository updated to latest code
- [x] PostgreSQL database created and configured
- [x] All 8 tables created successfully
- [x] IOC Fetcher script runs without errors
- [x] Cron job configured for hourly runs
- [x] Logs being written to /var/log/aegis/
- [x] Data persisting in database

---

## 📞 SUPPORT

If something goes wrong:

1. **Check logs first:**
   ```bash
   tail -100 /var/log/aegis/ioc_fetcher.log
   tail -50 /var/log/aegis/ioc_collector_errors.log
   ```

2. **Test script manually:**
   ```bash
   cd /var/www/aegis_nexus
   source venv/bin/activate
   python scripts/ioc_fetcher.py -v
   ```

3. **Verify database connection:**
   ```bash
   psql -U postgres -d phishing_db -c "SELECT 1;"
   ```

---

**Deployment Status:** ✅ READY  
**Next Phase:** Monitor for 24 hours, then integrate with Threat Responder SMS gateway
