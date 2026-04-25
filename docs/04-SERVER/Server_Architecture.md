# AegisNexus Server Architecture Documentation

## 🖥️ Server Specifications

### Hardware
- **Provider:** DigitalOcean
- **Location:** Frankfurt (fra1)
- **CPU:** 1 vCPU
- **RAM:** 1GB
- **Disk:** 48GB SSD
- **OS:** Ubuntu 24.04 LTS (Linux 6.8.0-110-generic)

### Network
- **IP:** 104.248.45.198
- **Domains:**
  - aegisnexus.dev (main)
  - www.aegisnexus.dev (redirects to main)
  - api.aegisnexus.dev (API subdomain)
  - modules.aegisnexus.dev (modules subdomain)

---

## 📁 Directory Structure

```
/var/www/aegis_nexus/
├── app/                    # FastAPI application
├── modules/                # Security modules
│   ├── phishing_detector/  # Phishing detection module
│   ├── ai_analyzer/        # AI analysis module
│   ├── honeypot/           # Honeypot/IOC module
│   └── breach_intel/      # Breach intelligence module
├── frontend-react/         # React SPA frontend
│   ├── dist/              # Built production files
│   ├── src/               # Source code
│   └── package.json       # Dependencies
├── shared/                # Shared utilities
├── scripts/               # Utility scripts
├── tests/                 # Test files
├── venv/                  # Python virtual environment
├── .env                   # Environment variables
├── requirements.txt       # Python dependencies
├── threat_intel_cache.db # SQLite cache database
└── main.py               # FastAPI entry point
```

---

## 🔧 System Services

### 1. AegisNexus API Service (SystemD)

**Service File:** `/etc/systemd/system/aegisnexus-api.service`

```ini
[Unit]
Description=AegisNexus FastAPI Backend
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/aegis_nexus
ExecStart=/var/www/aegis_nexus/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
Environment="PATH=/var/www/aegis_nexus/venv/bin"

[Install]
WantedBy=multi-user.target
```

**Management Commands:**
```bash
# Start service
sudo systemctl start aegisnexus-api.service

# Stop service
sudo systemctl stop aegisnexus-api.service

# Restart service
sudo systemctl restart aegisnexus-api.service

# Check status
sudo systemctl status aegisnexus-api.service

# View logs
sudo journalctl -u aegisnexus-api.service -f
```

### 2. Nginx Web Server

**Config Directory:** `/etc/nginx/`

**Active Configs:**
- `/etc/nginx/sites-available/default` - Main site (aegisnexus.dev, www.aegisnexus.dev)
- `/etc/nginx/sites-available/api.aegisnexus.dev` - API subdomain
- `/etc/nginx/sites-available/modules.aegisnexus.dev` - Modules subdomain

**Main Config Structure:**
```nginx
server {
    listen 80;
    server_name aegisnexus.dev www.aegisnexus.dev;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name aegisnexus.dev www.aegisnexus.dev;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/aegisnexus.dev/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/aegisnexus.dev/privkey.pem;
    
    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # React SPA
    location / {
        alias /var/www/aegis_nexus/frontend-react/dist/;
        try_files $uri $uri/ /index.html;
        add_header Cache-Control 'no-cache';
    }
}
```

**Management Commands:**
```bash
# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# Restart Nginx
sudo systemctl restart nginx

# Check status
sudo systemctl status nginx
```

### 3. PostgreSQL Database

**Version:** PostgreSQL 16

**Databases:**
- `aegisnexus` - Main application database
- `phishing_db` - Phishing detection database
- `postgres` - System database

**Users:**
- `postgres` - Superuser
- `enes` - Application user
- `aegisuser` - Additional application user

**Connection String:**
```
postgresql://enes:password@127.0.0.1:5432/phishing_db
```

**Management Commands:**
```bash
# Connect to database
sudo -u postgres psql -d phishing_db

# List databases
sudo -u postgres psql -c '\l'

# Backup database
sudo -u postgres pg_dump phishing_db > backup.sql

# Restore database
sudo -u postgres psql phishing_db < backup.sql
```

---

## 🔐 Environment Variables

**File:** `/var/www/aegis_nexus/.env`

```bash
# Database
DB_USER=enes
DB_PASSWORD=password
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=phishing_db
DATABASE_URL=postgresql://enes:password@127.0.0.1:5432/phishing_db

# VirusTotal API
VIRUSTOTAL_API_KEY=fe5254a6196c4f23a7d0f1a3164b7318818e1213c7c5c3e479fc999976f2a5d2
VIRUSTOTAL_API_KEYS=58177fb3550491ec6711145d5cadc097cde22c85079eec0be0e042285cddbf3c

# Google Safe Browsing
GOOGLE_SAFE_BROWSING_KEYS=AIzaSyAXbw-TjL73BWW59GT6byqrommVnlzWZBE,AIzaSyBeLMdzc20-DREvgh3ypcO_4-FmDr22qq0
GOOGLE_SAFE_BROWSING_KEY=AIzaSyAXbw-TjL73BWW59GT6byqrommVnlzWZBE

# AbuseIPDB
ABUSEIPDB_API_KEYS=055bc2de7cefa2db0bef577346ebc74386db8e74596e3b48bbabad16eda3b5978a678e6e797848b3
ABUSEIPDB_API_KEY=859f8b864877be82ebc790e367437ed092534cfbe28680a63be23300f8a37f6b876ef8ca38f86abc

# URLScan.io
URLSCAN_API_KEY=019da6d4-0ce0-773c-9e77-65a8b4118bee
URLSCAN_API_KEYS=019daba8-4266-774d-a251-dbc55d5a4a69

# Other APIs
ALIENVAULT_OTX_API_KEY=d8a7b78004e5deab2f36622aa64b6bbf262a5852850c5e74ea7c3cef11d200dd
KAGGLE_USERNAME=enestekdemir
KAGGLE_API_TOKEN=KGAT_8471cc4b8eaee3dd75a901ac102140b5
URLHAUS_API_KEY=804cd2869759b358df60916d83083f51be7a4e1893ec521e
GEMINI_API_KEY=AIzaSyDNCvR-xhKuWAP_5DJ_UqGKSFNlJ1lScgw
GROQ_API_KEY=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
TELEGRAM_API_ID=36167683
TELEGRAM_API_HASH=7d250a8acae18e12b3334dd8fd788fae
REDIS_URL=redis://localhost:6379/0
```

---

## 🚀 Deployment Process

### Initial Setup

1. **Clone Repository:**
```bash
cd /var/www
git clone https://github.com/garmoths/AegisNexus.git
cd AegisNexus
```

2. **Setup Python Environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Setup Database:**
```bash
sudo -u postgres psql
CREATE DATABASE phishing_db;
CREATE USER enes WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE phishing_db TO enes;
\q
```

4. **Setup SystemD Service:**
```bash
sudo cp /path/to/aegisnexus-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegisnexus-api.service
sudo systemctl start aegisnexus-api.service
```

5. **Setup Nginx:**
```bash
sudo cp /path/to/nginx-config /etc/nginx/sites-available/default
sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Update Deployment

```bash
# SSH to server
ssh root@104.248.45.198

# Navigate to project
cd /var/www/aegis_nexus

# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Build React frontend
cd frontend-react
npm run build
cd ..

# Restart services
sudo systemctl restart aegisnexus-api.service
sudo systemctl reload nginx
```

---

## 🔍 Monitoring & Troubleshooting

### Check Service Status
```bash
# All services
sudo systemctl status aegisnexus-api.service nginx postgresql@16-main.service

# Individual service
sudo systemctl status aegisnexus-api.service
```

### View Logs
```bash
# API logs
sudo journalctl -u aegisnexus-api.service -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-16-main.log
```

### Database Health
```bash
# Check connection
sudo -u postgres psql -c "SELECT version();"

# Check database size
sudo -u postgres psql -c "\l+"

# Check active connections
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity;"
```

### Disk Space
```bash
df -h
du -sh /var/www/aegis_nexus/*
```

### Memory Usage
```bash
free -h
ps aux --sort=-%mem | head
```

---

## 🔒 Security Checklist

- [ ] SSL certificates valid (Let's Encrypt)
- [ ] Firewall configured (UFW)
- [ ] Database passwords strong
- [ ] API keys not exposed in git
- [ ] SystemD services running as non-root where possible
- [ ] Regular backups configured
- [ ] Log rotation enabled
- [ ] Security updates applied

---

## 📞 Emergency Contacts

- **Server IP:** 104.248.45.198
- **SSH Access:** ssh root@104.248.45.198
- **Database User:** enes
- **Main Domain:** aegisnexus.dev

---

## 🔄 Backup Strategy

### Database Backup
```bash
# Automated daily backup (cron)
0 2 * * * sudo -u postgres pg_dump phishing_db > /backups/phishing_db_$(date +\%Y\%m\%d).sql
```

### Application Backup
```bash
# Backup entire application
tar -czf /backups/aegisnexus_$(date +%Y%m%d).tar.gz /var/www/aegis_nexus
```

---

## 📊 Performance Metrics

### Current Usage
- **CPU:** ~10-20% idle
- **RAM:** ~800MB used / 1.9GB total
- **Disk:** 6.4GB used / 48GB total
- **Network:** Standard DigitalOcean 1Gbps

### Optimization Tips
1. Enable PostgreSQL query caching
2. Configure Nginx gzip compression
3. Use Redis for session storage
4. Implement CDN for static assets
5. Monitor API response times

---

## 🚨 Common Issues & Solutions

### Service Won't Start
```bash
# Check logs
sudo journalctl -u aegisnexus-api.service -n 50

# Check port conflicts
sudo netstat -tlnp | grep 8000

# Restart service
sudo systemctl restart aegisnexus-api.service
```

### Database Connection Failed
```bash
# Check PostgreSQL status
sudo systemctl status postgresql@16-main.service

# Check connection string
echo $DATABASE_URL

# Test connection
psql -h 127.0.0.1 -U enes -d phishing_db
```

### Nginx 502 Bad Gateway
```bash
# Check if API is running
curl http://localhost:8000/health

# Check Nginx config
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

---

## 📝 Maintenance Schedule

### Daily
- Check service status
- Review error logs
- Monitor disk space

### Weekly
- Database backup verification
- Security updates check
- Performance metrics review

### Monthly
- Full system backup
- SSL certificate renewal check
- Dependency updates
- Security audit

---

**Last Updated:** April 25, 2026
**Maintained By:** enes
