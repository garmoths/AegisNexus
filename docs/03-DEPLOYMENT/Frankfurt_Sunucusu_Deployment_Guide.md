# 🌍 FRANKFURT SUNUCUSU - DEPLOYMENT & OPERATIONS GUIDE

**Sunucu Bilgileri:**
- **IP:** 104.248.45.198
- **Location:** Frankfurt, Germany (FRA1)
- **Spec:** 1 vCPU, 1GB RAM, 23GB SSD
- **OS:** Ubuntu 24.04.4 LTS
- **Status:** ✅ AKTIF (Canlı - Production)

---

## 📍 SUNUCU SETUP - TÜZEL TAKVİ

### Hardware Specs

```
┌─────────────────────────────────────────┐
│ DigitalOcean Droplet (Frankfurt)        │
├─────────────────────────────────────────┤
│ CPU:      1 vCPU (Intel Xeon)          │
│ RAM:      1 GB                          │
│ Storage:  23 GB SSD                     │
│ Uplink:   1 Gbps                        │
│ Backup:   Daily (automated)             │
│ IPv4:     104.248.45.198                │
│ Region:   Germany (FRA-1)               │
└─────────────────────────────────────────┘

Current Usage:
├── Disk:   24.1% used (5.6 GB / 23 GB)
├── Memory: 61% used (610 MB / 1 GB)
├── CPU:    ~15% (idle, spike to 80% during fetches)
└── Uptime: 89+ days (stable)
```

### Network Configuration

```bash
# IP Configuration
$ hostname
ubuntu-s-1vcpu-1gb-fra1-01

$ ip addr show
inet 104.248.45.198 (public IPv4)
inet 10.19.0.5 (internal VPC)

# DNS
$ cat /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4

# Firewall (ufw)
$ sudo ufw status
Status: active
To                         Action      From
--
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
8000/tcp                   ALLOW       Anywhere
5000/tcp                   ALLOW       Anywhere
5432/tcp                   DENY        Anywhere  (DB - local only)
```

---

## 📁 DIRECTORY STRUCTURE

```
/var/www/aegis_nexus/              ← Main application directory
│
├── 📜 app/
│   ├── main.py                    ← FastAPI entry point
│   ├── api_server.py              ← API routes
│   ├── models.py                  ← SQLAlchemy ORM models
│   ├── database.py                ← PostgreSQL connection
│   └── config.py                  ← Configuration
│
├── 📦 modules/
│   ├── phishing_detector/
│   │   ├── threat_intel.py        ← VirusTotal, Google Safe, AbuseIPDB
│   │   ├── scanner.py             ← URL scanning logic
│   │   ├── fetch_all_sources.py   ← Threat fetcher (2:00 AM daily)
│   │   └── fetch_data.py
│   │
│   ├── honeypot/
│   │   ├── ioc_collector.py       ← URLhaus, PhishTank fetcher (CRITICAL)
│   │   ├── ioc_validator.py
│   │   ├── ioc_scorer.py
│   │   └── router.py              ← API endpoints
│   │
│   ├── breach_intel/
│   ├── password_shield/
│   └── threat_responder/
│
├── 🔄 scripts/
│   ├── ioc_fetcher.py             ← **MAIN: Hourly IOC collection**
│   ├── deploy.sh
│   └── db_init.py
│
├── 📚 frontend/
│   ├── api-test.html              ← Web API tester
│   └── dashboard.js
│
├── 📖 docs/
│   ├── API_INTEGRATION_GUIDE.md
│   ├── IOC_COLLECTOR_GUIDE.md
│   └── OPERATOR_SMS_INTEGRATION.md
│
├── 📋 logs/                       ← Application logs
│   └── ioc_fetch.log
│
├── 🔐 .env                        ← API keys, DB credentials (SENSITIVE!)
├── requirements.txt               ← Python dependencies
├── venv/                          ← Virtual environment (Python 3.12)
│
└── .github/
    └── workflows/
        └── deploy.yml             ← GitHub Actions auto-deploy
```

### Kritik Dosyalar

| Dosya | Amaç | Ownership | Permissions |
|-------|------|-----------|------------|
| `.env` | API keys, DB creds | root | 600 (read-only) |
| `scripts/ioc_fetcher.py` | Hourly IOC fetch | root | 755 (executable) |
| `modules/honeypot/ioc_collector.py` | IOC collection engine | root | 644 |
| `/var/log/aegis/cron.log` | Cron execution log | root | 644 |
| `/var/log/postgresql/` | Database logs | postgres | 644 |

---

## 🗄️ DATABASE SETUP

### PostgreSQL Configuration

```bash
# Service Status
sudo systemctl status postgresql
sudo systemctl start postgresql        # If needed
sudo systemctl restart postgresql      # If hung

# Database Info
$ psql -U enes -d phishing_db -c "\du"
                   List of roles
 Role name |                         Attributes
-----------+------------------------------------------------------------
 enes      | Superuser, Create role, Create DB, ...
 postgres  | Superuser, Create role, Create DB, ...

# Database Connection
Database: phishing_db
User: enes
Host: 127.0.0.1 (localhost only)
Port: 5432
```

### Database Schema

```sql
-- Main table: Indicators of Compromise (IOCs)
CREATE TABLE indicators_of_compromise (
    id BIGSERIAL PRIMARY KEY,
    ioc_type VARCHAR(20),          -- 'url', 'domain', 'ip', 'hash'
    ioc_value VARCHAR(1000),       -- The actual indicator
    ioc_value_hash VARCHAR(64) UNIQUE,
    source VARCHAR(50),            -- 'abuse_urlhaus', 'abuseipdb'
    threat_type VARCHAR(100),      -- 'phishing', 'malware', 'botnet'
    risk_score INTEGER,            -- 1-100
    confidence FLOAT,              -- 0.0-1.0
    threat_tags JSON,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    detection_count INTEGER,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Other tables (phishing_detector, honeypot, etc.)
-- Will be created by SQLAlchemy on first run
```

### Database Backup

```bash
# Manual backup
pg_dump -U enes phishing_db > /var/backups/phishing_db.sql

# Restore from backup
psql -U enes phishing_db < /var/backups/phishing_db.sql

# DigitalOcean automated backups (enabled in control panel)
# - Daily snapshots
# - 7-day retention
# - Can restore to new droplet
```

### Database Monitoring

```bash
# Connect to database
psql -U enes -d phishing_db

# Check table sizes
\dt+

# Check total records
SELECT COUNT(*) FROM indicators_of_compromise;

# Check by source
SELECT source, COUNT(*) FROM indicators_of_compromise GROUP BY source;

# Check growth rate
SELECT DATE(created_at), COUNT(*) 
FROM indicators_of_compromise 
GROUP BY DATE(created_at)
ORDER BY DATE DESC LIMIT 7;
```

---

## 🔄 SERVICES & PROCESS MANAGEMENT

### PM2 Process Manager

```bash
# List all processes
pm2 list

# Current processes:
# 0: main        (FastAPI server, port 8000)
# 1: api         (Alternative API, port 5000)
# 3: ioc-fetch   (DELETED - now using cron)

# Start/stop services
pm2 start main
pm2 stop main
pm2 restart main
pm2 delete main

# Logs
pm2 logs main         # Real-time logs
pm2 logs api          # API server logs
pm2 logs --lines 100  # Last 100 lines

# Save & restore
pm2 save              # Save current processes
pm2 startup          # Auto-start on reboot
pm2 kill             # Stop all processes
```

### SystemD Services

```bash
# PostgreSQL
sudo systemctl status postgresql
sudo systemctl restart postgresql
sudo systemctl enable postgresql  # Auto-start on reboot

# SSH
sudo systemctl status ssh

# Cron (system scheduler)
sudo systemctl status cron
```

### Running Ports

```
Port 22:   SSH (administrative access)
Port 80:   HTTP (HTTP server, redirects to HTTPS)
Port 443:  HTTPS (web server, if configured)
Port 5000: API alternative endpoint
Port 8000: FastAPI main server (http://104.248.45.198:8000)
Port 5432: PostgreSQL (127.0.0.1 only, not exposed)
```

---

## ⏰ CRON JOBS

### Current Cron Configuration

```bash
# View current crontab
sudo crontab -l

# Output:
# m h  dom mon dow   command
* * * * * /bin/bash -c 'cd /var/www/aegis_nexus && source venv/bin/activate && git pull origin main && pip install -r requirements.txt >> /var/log/aegis_deploy.log 2>&1'
0 2 * * * cd /var/www/aegis_nexus && PYTHONPATH=/var/www/aegis_nexus /usr/bin/python3 -m modules.phishing_detector.fetch_all_sources >> logs/fetch_data.log 2>&1
0 * * * * cd /var/www/aegis_nexus && source venv/bin/activate && python3 scripts/ioc_fetcher.py >> /var/log/aegis/cron.log 2>&1
```

### Cron Job Details

#### 1. **Auto-Deploy (Every minute)**
```bash
* * * * * cd /var/www/aegis_nexus && source venv/bin/activate && \
    git pull origin main && pip install -r requirements.txt >> /var/log/aegis_deploy.log 2>&1
```
- **Frequency:** Every minute (for rapid testing)
- **Task:** Pull latest from GitHub + install dependencies
- **Log:** `/var/log/aegis_deploy.log`
- **Purpose:** Continuous deployment

#### 2. **Phishing Data Fetcher (2:00 AM daily)**
```bash
0 2 * * * cd /var/www/aegis_nexus && PYTHONPATH=/var/www/aegis_nexus \
    /usr/bin/python3 -m modules.phishing_detector.fetch_all_sources >> logs/fetch_data.log 2>&1
```
- **Frequency:** Daily at 02:00 UTC
- **Task:** Fetch phishing data from sources
- **Log:** `logs/fetch_data.log`

#### 3. **IOC Fetcher (Every hour) - CRITICAL ⭐**
```bash
0 * * * * cd /var/www/aegis_nexus && source venv/bin/activate && \
    python3 scripts/ioc_fetcher.py >> /var/log/aegis/cron.log 2>&1
```
- **Frequency:** Every hour at minute 0 (00:00, 01:00, 02:00, ..., 23:00)
- **Task:** Fetch 2000 malicious URLs from URLhaus, persist to DB
- **Log:** `/var/log/aegis/cron.log`
- **Duration:** ~6-8 seconds per run
- **Throughput:** 2000 IOCs/hour × 24 = 48,000 IOCs/day

### Monitoring Cron Jobs

```bash
# View cron log (last 20 lines)
tail -20 /var/log/aegis/cron.log

# Monitor real-time
tail -f /var/log/aegis/cron.log

# Check execution history (last 24 hours)
grep "2026-04-17" /var/log/aegis/cron.log | head -20

# Check for errors
grep ERROR /var/log/aegis/cron.log

# Parse log statistics
cat /var/log/aegis/cron.log | grep "✅" | wc -l  # Successful runs
cat /var/log/aegis/cron.log | grep "❌" | wc -l  # Failed runs
```

### Editing Cron Jobs

```bash
# Edit crontab (opens in nano/vim)
sudo crontab -e

# Add new job (example: run every 6 hours)
0 */6 * * * cd /var/www/aegis_nexus && source venv/bin/activate && python3 scripts/script.py

# Remove cron job
# Open with: sudo crontab -e
# Delete the line
# Save and exit

# Syntax reference:
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of week (0 - 7) (0 & 7 = Sunday)
# │ │ │ │ │
# │ │ │ │ │
# * * * * * command
```

---

## 🔐 ENVIRONMENT CONFIGURATION

### .env File (SENSITIVE - DO NOT COMMIT)

```bash
# Location: /var/www/aegis_nexus/.env
# Permissions: 600 (read-only)
# Owner: root

# Database
DATABASE_URL=postgresql://enes:password@127.0.0.1:5432/phishing_db

# Threat Intelligence API Keys (comma-separated for rotation)
VIRUSTOTAL_API_KEYS=key1,key2,key3,...,key10
GOOGLE_SAFE_BROWSING_KEYS=key1,key2
ABUSEIPDB_API_KEYS=key1,key2,...,key9

# URLhaus (currently unused - public endpoint)
URLHAUS_API_KEY=your_key_here

# Application Settings
LOG_LEVEL=INFO
DEBUG_MODE=false
API_PORT=8000
```

### View Environment (Redacted)

```bash
# Check if .env exists
cat /var/www/aegis_nexus/.env | head -10

# Check specific variable
grep DATABASE_URL /var/www/aegis_nexus/.env

# Check API keys (redacted for security)
grep "VIRUSTOTAL_API_KEYS" /var/www/aegis_nexus/.env | sed 's/=.*/=***REDACTED***/g'
```

---

## 📊 MONITORING & LOGGING

### Log Files

| Log File | Purpose | Location | Rotation |
|----------|---------|----------|----------|
| **cron.log** | IOC fetcher (hourly) | `/var/log/aegis/cron.log` | Manual |
| **ioc_collector.log** | IOC collection details | `/var/log/aegis/ioc_collector.log` | Manual |
| **ioc_collector_errors.log** | IOC errors only | `/var/log/aegis/ioc_collector_errors.log` | Manual |
| **postgresql.log** | Database operations | `/var/log/postgresql/` | Automatic (daily) |
| **fetch_data.log** | Phishing data fetch | `logs/fetch_data.log` | Manual |
| **aegis_deploy.log** | Auto-deploy script | `/var/log/aegis_deploy.log` | Manual |

### Viewing Logs

```bash
# Real-time monitoring (tail -f)
tail -f /var/log/aegis/cron.log

# Last N lines
tail -50 /var/log/aegis/cron.log
head -50 /var/log/aegis/cron.log

# Search for patterns
grep "ERROR\|CRITICAL" /var/log/aegis/cron.log
grep "2026-04-17 15:" /var/log/aegis/cron.log  # Specific hour

# Count successes/failures
grep "✅" /var/log/aegis/cron.log | wc -l
grep "❌" /var/log/aegis/cron.log | wc -l

# Follow specific pattern
tail -f /var/log/aegis/cron.log | grep "ERROR"
```

### Log Rotation (Maintenance)

```bash
# Manual rotation (if logs get large)
sudo logrotate -vf /etc/logrotate.d/aegis

# Or manually archive
gzip /var/log/aegis/cron.log
mv /var/log/aegis/cron.log.gz /var/log/aegis/cron.log.gz.old

# PostgreSQL automatic rotation
# Already configured in postgresql.conf
```

### Monitoring Commands

```bash
# System resource usage
top -b -n 1 | head -20
free -h                          # RAM
df -h                           # Disk
ps aux | grep python           # Python processes

# Network connections
ss -tlnp | grep 8000
netstat -an | grep ESTABLISHED

# Recent SSH logins
last -n 5

# System uptime & load
uptime

# CPU temperature (if available)
sensors

# Database connections
psql -U enes -d phishing_db -c "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

---

## 🚀 MANUAL OPERATIONS

### Starting Services

```bash
# SSH to server
ssh root@104.248.45.198

# Navigate to project
cd /var/www/aegis_nexus

# Activate virtual environment
source venv/bin/activate

# Start FastAPI server (if stopped)
pm2 start main

# Start alternative API
pm2 start api

# Verify services running
pm2 list
```

### Manual IOC Fetch (Testing)

```bash
# SSH to server
ssh root@104.248.45.198

# Run IOC fetcher manually
cd /var/www/aegis_nexus
source venv/bin/activate
python3 scripts/ioc_fetcher.py

# Expected output:
# 2026-04-17 16:30:45,123 - INFO - 🚀 IOC Fetcher started
# 2026-04-17 16:30:46,456 - INFO - ✅ Database connection successful
# 2026-04-17 16:30:47,789 - INFO - ✅ Collected 2000 IOCs
# 2026-04-17 16:30:52,012 - INFO - ✅ Persisted: 47 inserted, 1953 updated
# 2026-04-17 16:30:52,345 - INFO - ✅ IOC Fetcher completed in 7s
```

### Database Operations

```bash
# SSH to server
ssh root@104.248.45.198

# Connect to PostgreSQL
psql -U enes -d phishing_db

# Basic queries
SELECT COUNT(*) FROM indicators_of_compromise;
SELECT * FROM indicators_of_compromise LIMIT 5;
SELECT source, COUNT(*) FROM indicators_of_compromise GROUP BY source;
SELECT threat_type, COUNT(*) FROM indicators_of_compromise GROUP BY threat_type;

# Exit
\q
```

### Restarting PostgreSQL (If Hung)

```bash
# Check status
sudo systemctl status postgresql

# If hung/unresponsive:
sudo systemctl stop postgresql
sleep 5
sudo systemctl start postgresql
sleep 5

# Verify running
sudo systemctl status postgresql
ps aux | grep postgres
```

---

## 🔧 TROUBLESHOOTING

### Issue: IOC Fetcher Timeout or Hangs

**Symptom:** Script doesn't complete in time

```bash
# Kill hanging process
ps aux | grep ioc_fetcher.py
kill -9 <PID>

# Check PostgreSQL
sudo systemctl status postgresql
ps aux | grep postgres

# Check network connectivity
curl https://urlhaus.abuse.ch/downloads/csv/ -I

# Review logs
tail -50 /var/log/aegis/cron.log
```

### Issue: Database Connection Failed

```bash
# Check PostgreSQL running
sudo systemctl status postgresql

# Restart PostgreSQL
sudo systemctl restart postgresql
sleep 5

# Test connection
psql -U enes -d phishing_db -c "SELECT 1"

# Check network
netstat -tlnp | grep 5432
```

### Issue: Cron Job Not Running

```bash
# Verify crontab setup
sudo crontab -l

# Check if cron daemon is running
sudo systemctl status cron

# Test cron manually
0 * * * * /var/log/cron_test.log  # Add test job
# After 1 minute, check if /var/log/cron_test.log exists

# Check system logs for cron errors
grep CRON /var/log/syslog
```

### Issue: Low Memory (1GB)

```bash
# Check current usage
free -h

# Kill unnecessary processes
ps aux | grep python
kill -9 <PID>

# Clear cache
sync; echo 3 > /proc/sys/vm/drop_caches

# Limit Python memory (if needed)
# Edit cron job to add memory limit:
0 * * * * ulimit -v 500000; cd /var/www/aegis_nexus && python3 scripts/ioc_fetcher.py
```

### Issue: Disk Almost Full

```bash
# Check disk usage
df -h

# Find large files
du -sh /* | sort -rh | head -10

# Clean up old logs
rm /var/log/aegis/cron.log.old
gzip /var/log/aegis/cron.log  # Compress current log

# Check PostgreSQL backups
du -sh /var/lib/postgresql
```

---

## 🔐 SECURITY CHECKLIST

```
☐ SSH Key-Only Access (no password login)
  sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  sudo systemctl restart ssh

☐ Firewall Configured
  sudo ufw enable
  sudo ufw default deny incoming
  sudo ufw allow 22,80,443,8000/tcp

☐ .env File Protected
  chmod 600 /var/www/aegis_nexus/.env
  ls -la /var/www/aegis_nexus/.env  # Should show 600

☐ PostgreSQL Local-Only
  netstat -tlnp | grep 5432  # Should show 127.0.0.1 only

☐ Regular Backups
  sudo crontab -e
  0 3 * * * pg_dump -U enes phishing_db > /var/backups/phishing_db_$(date +\%Y\%m\%d).sql

☐ Monitor for Intrusions
  sudo tail -f /var/log/auth.log | grep "Failed password"

☐ Update System
  sudo apt update && sudo apt upgrade -y
  sudo unattended-upgrade  # Automatic security updates
```

---

## 📞 QUICK COMMANDS CHEATSHEET

```bash
# Connection
ssh root@104.248.45.198

# Navigation
cd /var/www/aegis_nexus
source venv/bin/activate

# Database
psql -U enes -d phishing_db -c "SELECT COUNT(*) FROM indicators_of_compromise;"

# Logs
tail -f /var/log/aegis/cron.log

# Process management
pm2 list
pm2 logs
pm2 restart main

# System info
uptime
free -h
df -h

# Manual IOC fetch
python3 scripts/ioc_fetcher.py

# Git operations
git status
git log --oneline -10
git pull origin main

# Service management
sudo systemctl status postgresql
sudo systemctl restart postgresql
```

---

## 📈 SCALING CONSIDERATIONS

### Current Limitations (1vCPU, 1GB RAM)

```
✅ Suitable for:
   - 2,000 IOCs/hour
   - 48,000 IOCs/day
   - Moderate API call traffic
   - Single database instance

❌ Not suitable for:
   - 10,000+ IOCs/hour (CPU bottleneck)
   - Multiple concurrent API clients (RAM limited)
   - Production with 99.99% SLA (single point of failure)
```

### Scaling Path

**Stage 1 (Current):** 1vCPU, 1GB RAM
- URLhaus only
- Hourly fetch
- Single DB

**Stage 2:** 2vCPU, 2GB RAM (within month)
- Add AbuseIPDB, PhishTank
- 4 hourly API sources
- Better caching

**Stage 3:** 4vCPU, 4GB RAM + load balancer (within quarter)
- Multiple API instances
- DB replication
- Redis cache layer

**Stage 4:** Kubernetes cluster (enterprise)
- Multi-region deployment
- Auto-scaling
- Managed DB (AWS RDS, etc.)

---

## 📖 REFERENCE LINKS

**External Resources:**
- [VirusTotal API Documentation](https://developers.virustotal.com/)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing/)
- [AbuseIPDB API](https://www.abuseipdb.com/api)
- [Abuse.ch URLhaus](https://urlhaus.abuse.ch/)
- [PostgreSQL Official Docs](https://www.postgresql.org/docs/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

**Internal Docs:**
- API Integration: `docs/API_INTEGRATION_GUIDE.md`
- IOC Collector: `docs/IOC_COLLECTOR_GUIDE.md`
- Operator Gateway: `docs/OPERATOR_SMS_INTEGRATION.md`

---

**Last Updated:** 17 Nisan 2026  
**Maintained By:** DevOps Team  
**Status:** Production Ready ✅
