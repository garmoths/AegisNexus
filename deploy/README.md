# AegisNexus Sunucu Kurulum Rehberi

## 1. Ön Koşullar
```bash
# PostgreSQL
sudo apt install postgresql postgresql-contrib

# RabbitMQ (Celery broker)
sudo apt install rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server

# Python 3.12+ & venv
sudo apt install python3 python3-venv python3-pip

# Node.js 20+ (frontend build)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs

# Nginx
sudo apt install nginx
```

## 2. Proje Kurulumu
```bash
# Klonla
cd /var/www
sudo git clone https://github.com/GARMOTHS/AegisNexus.git aegisnexus
cd aegisnexus

# Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# .env dosyası
cp deploy/.env.example .env
nano .env  # DATABASE_URL, GEMINI_API_KEY vb. doldur
```

## 3. PostgreSQL Kurulumu
```bash
sudo -u postgres createuser aegis -P
sudo -u postgres createdb aegisnexus -O aegis

# Test bağlantı
psql -U aegis -d aegisnexus -h localhost
```

## 4. Veritabanı Migration
```bash
cd /var/www/aegisnexus
source venv/bin/activate

# Alembic migration
alembic upgrade head

# SQLite'dan veri taşıma (varsa)
python scripts/migrate_sqlite_to_pg.py
```

## 5. Frontend Build
```bash
cd /var/www/aegisnexus/frontend-react
npm install
npm run build
# dist/ klasörü oluşur → nginx bunu serve eder
```

## 6. Nginx Yapılandırması
```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/aegisnexus
sudo ln -sf /etc/nginx/sites-available/aegisnexus /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 7. Systemd Servisleri
```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Admin API key oluştur
cd /var/www/aegisnexus && make create-admin

# Servisleri başlat
make up

# Otomatik başlatma
sudo systemctl enable aegis-api aegis-celery-worker aegis-celery-beat aegis-celery-honeypot
```

## 8. Doğrulama
```bash
# API sağlık kontrolü
curl http://localhost:8000/api/v2/victim-atlas/ingest/health

# Frontend
curl http://localhost/

# Loglar
make logs
```

## 9. SSL (Let's Encrypt)
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d aegisnexus.dev -d www.aegisnexus.dev
```

## 10. Güncelleme (Deploy)
```bash
cd /var/www/aegisnexus
make deploy
```
