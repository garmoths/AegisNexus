# 🚀 FRANKFURT PRODUCTION DEPLOYMENT CHECKLIST

**Project:** AegisNexus IOC Collector  
**Environment:** Frankfurt Ubuntu Server (1vCPU, 1GB)  
**Date:** April 17, 2026

---

## ✅ PRE-DEPLOYMENT VERIFICATION

- [ ] **Git Repository** - Tüm değişiklikler commit ve push edildi
  ```bash
  git status  # Clean branch
  git log --oneline -5
  ```

- [ ] **Dependencies** - requirements.txt günceldir
  ```bash
  pip freeze > requirements.txt
  cat requirements.txt | grep -E "sqlalchemy|requests|psycopg2"
  ```

- [ ] **Database Schema** - Migration scripts hazır
  - [ ] `app/models.py` - IndicatorOfCompromise, OperatorAPIKey, IOCOperatorAlert
  - [ ] Indexes created for fast queries
  - [ ] Connection pooling configured

- [ ] **IOC Collector** - Code quality check
  ```bash
  python -m py_compile modules/honeypot/ioc_collector.py
  python -m py_compile scripts/ioc_fetcher.py
  ```

---

## 🔧 FRANKFURT SERVER SETUP

### Step 1: Prerequisite Packages

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3-venv python3-pip postgresql-client logrotate

# Check versions
python3 --version  # Should be 3.8+
pip3 --version
psql --version
```

### Step 2: Project Deployment

```bash
# Navigate to web directory
cd /var/www

# Clone repository (if not already there)
# git clone https://github.com/your-org/AegisNexus.git
# OR update existing
cd aegis_nexus
git pull origin main

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify imports work
python -c "from modules.honeypot.ioc_collector import IOCCollectorEngine; print('✅ IOC Collector imported successfully')"
```

### Step 3: Database Setup

```bash
# Connect to PostgreSQL (update credentials as needed)
export DB_USER="postgres"
export DB_PASSWORD="your_secure_password"
export DB_HOST="localhost"
export DB_NAME="phishing_db"

# Create database if not exists
createdb -U $DB_USER -h $DB_HOST $DB_NAME

# Run migrations (if using Alembic)
# alembic upgrade head

# Or manually create tables (from app/models.py)
psql -U $DB_USER -h $DB_HOST -d $DB_NAME << 'EOF'
-- Run your CREATE TABLE statements here
EOF

# Verify tables created
psql -U $DB_USER -d $DB_NAME -c "\dt"
```

### Step 4: Logging Setup

```bash
# Create log directory
sudo mkdir -p /var/log/aegis
sudo chmod 755 /var/log/aegis
sudo chown root:root /var/log/aegis

# Setup log rotation
sudo cp scripts/ioc_logrotate.conf /etc/logrotate.d/aegis-ioc
sudo chmod 644 /etc/logrotate.d/aegis-ioc

# Verify logrotate
sudo logrotate -d /etc/logrotate.d/aegis-ioc  # Dry run
```

### Step 5: Test Run

```bash
# Make script executable
chmod +x /var/www/aegis_nexus/scripts/ioc_fetcher.py

# Run in foreground (watch output)
cd /var/www/aegis_nexus
source venv/bin/activate
python scripts/ioc_fetcher.py

# Expected output:
# ✅ Database connection successful
# 🔄 Starting IOC collection...
# ✅ Collected XXX IOCs
# ✅ Persisted XXX new IOCs
# Duration: XX.XXs
```

---

## ⏰ CRON CONFIGURATION

### Option A: Traditional Crontab (Simple)

```bash
# Edit crontab
sudo crontab -e

# Add this line (runs every hour at :00)
0 * * * * cd /var/www/aegis_nexus && source venv/bin/activate && python scripts/ioc_fetcher.py >> /var/log/aegis/ioc_fetcher.log 2>&1
```

### Option B: Systemd Timer (Recommended)

Create service file:
```bash
sudo nano /etc/systemd/system/aegis-ioc-fetcher.service
```

Paste:
```ini
[Unit]
Description=AegisNexus IOC Fetcher
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/var/www/aegis_nexus
Environment="PATH=/var/www/aegis_nexus/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/bin/bash -c 'source venv/bin/activate && python scripts/ioc_fetcher.py'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create timer file:
```bash
sudo nano /etc/systemd/system/aegis-ioc-fetcher.timer
```

Paste:
```ini
[Unit]
Description=Run AegisNexus IOC Fetcher every hour
Requires=aegis-ioc-fetcher.service

[Timer]
# Start 5 minutes after boot
OnBootSec=5min

# Run every hour
OnUnitActiveSec=1h

# Keep track of last run
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable aegis-ioc-fetcher.timer
sudo systemctl start aegis-ioc-fetcher.timer
sudo systemctl status aegis-ioc-fetcher.timer

# Check timer status
sudo systemctl list-timers aegis-ioc-fetcher.timer
```

---

## 📊 VERIFICATION & MONITORING

### Check if Script Runs

```bash
# View recent runs (last 20 entries)
sudo journalctl -u aegis-ioc-fetcher.service -n 20

# View with timestamps
sudo journalctl -u aegis-ioc-fetcher.service --no-pager

# Follow in real-time
sudo journalctl -u aegis-ioc-fetcher.service -f
```

### Monitor Database Growth

```bash
# Check IOC count
psql -U postgres -d phishing_db -c "
SELECT 
    COUNT(*) as total_iocs,
    COUNT(CASE WHEN risk_score >= 95 THEN 1 END) as critical,
    COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as high_risk,
    MAX(created_at) as last_update
FROM indicators_of_compromise;
"

# Check by source
psql -U postgres -d phishing_db -c "
SELECT source, COUNT(*) as count, AVG(risk_score) as avg_risk
FROM indicators_of_compromise
GROUP BY source
ORDER BY count DESC;
"

# Check by threat type
psql -U postgres -d phishing_db -c "
SELECT threat_type, COUNT(*) as count, AVG(risk_score) as avg_risk
FROM indicators_of_compromise
GROUP BY threat_type
ORDER BY count DESC;
"
```

### View Logs

```bash
# All logs
tail -100 /var/log/aegis/ioc_collector.log

# Errors
tail -50 /var/log/aegis/ioc_collector_errors.log

# Follow in real-time
tail -f /var/log/aegis/ioc_collector.log

# Search for errors
grep "ERROR\|FAILED\|Failed" /var/log/aegis/ioc_collector.log
```

---

## 🆘 TROUBLESHOOTING

### Issue: "Permission denied" on /var/log/aegis

```bash
sudo chmod 777 /var/log/aegis
ls -la /var/log/aegis  # Should show drwxrwxrwx
```

### Issue: "Database connection failed"

```bash
# Check PostgreSQL
sudo systemctl status postgresql

# Test connection manually
psql -U postgres -h localhost -d phishing_db -c "SELECT 1;"

# Check credentials in .env or config
grep DB_ /var/www/aegis_nexus/.env || echo "No .env found"
```

### Issue: "ModuleNotFoundError: No module named 'modules'"

```bash
# Ensure venv is active
source /var/www/aegis_nexus/venv/bin/activate

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Should include: /var/www/aegis_nexus

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: Cron job not running

```bash
# Check crontab
sudo crontab -l

# Check syslog
sudo grep CRON /var/log/syslog | tail -20

# Enable debug
sudo service rsyslog restart

# For systemd timer
sudo systemctl status aegis-ioc-fetcher.timer
sudo journalctl -u aegis-ioc-fetcher.timer
```

---

## 📈 EXPECTED BEHAVIOR

**First Run:**
- Connects to all sources (URLhaus, PhishTank, AbuseIPDB)
- Collects ~1200-1500 IOCs
- Takes ~25-30 seconds
- Persists all IOCs to database

**Subsequent Runs:**
- Collects new IOCs (50-150 per hour)
- Detects duplicates via SHA256 hash
- Updates detection_count and last_seen
- Takes ~20-30 seconds (database faster with repeats)

**Logs grow:**
- ~2-3 KB per run
- 50+ KB per day
- Rotated daily via logrotate

---

## 🚨 ALERTS & NOTIFICATIONS

**Currently Manual:**
- [ ] Check `/var/log/aegis/ioc_collector_errors.log` daily
- [ ] Monitor database size: `du -sh /var/lib/postgresql`
- [ ] Alert if no runs in 24 hours

**Future (Phase 3):**
- [ ] Email alerts on errors
- [ ] Telegram bot notifications
- [ ] Slack integration
- [ ] Dashboard with real-time stats

---

## ✅ POST-DEPLOYMENT CHECKLIST

- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip list`)
- [ ] Database connection verified
- [ ] Log directory exists and writable
- [ ] Test run successful (script outputs metrics)
- [ ] Cron/timer configured and running
- [ ] Logs being written to `/var/log/aegis/`
- [ ] IOCs appearing in database
- [ ] Error log is clean (or only expected errors)
- [ ] Automated run happened (check crontab output or systemd journal)

---

## 📞 SUPPORT

**Quick Commands:**

```bash
# Start/stop timer
sudo systemctl start|stop|restart aegis-ioc-fetcher.timer

# Check timer next run
sudo systemctl list-timers --all

# View all logs
sudo journalctl -u aegis-ioc-fetcher.service -n 100 --no-pager

# Database backup
pg_dump -U postgres phishing_db > /backups/ioc_$(date +%Y%m%d_%H%M%S).sql

# Clear old logs (older than 30 days)
find /var/log/aegis -name "*.log.*" -mtime +30 -delete
```

---

**Status:** Ready for deployment ✅  
**Last Updated:** April 17, 2026
