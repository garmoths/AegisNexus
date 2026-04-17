# POSTGRESQL ŞIFRE SORUNU - ÇÖZÜMLER

## Çözüm 1: sudo -u postgres Kullan (EN KOLAY)

```bash
sudo -u postgres psql -f scripts/db_setup.sql
```

Bunu çalıştır, şifre soramayacak.

---

## Çözüm 2: Eğer hala şifre sorarsa - pg_hba.conf Düzenle

```bash
# pg_hba.conf'i bul ve düzenle
sudo nano /etc/postgresql/*/main/pg_hba.conf

# Bu satırını bul:
# local   all             postgres                                peer

# Eğer yoksa, dosya sonuna ekle:
local   all             postgres                                peer
local   all             all                                     peer

# Sonra PostgreSQL'i restart et:
sudo systemctl restart postgresql
```

Sonra tekrar dene:
```bash
sudo -u postgres psql -f scripts/db_setup.sql
```

---

## Çözüm 3: Inline Script (Şifre gerekmez)

```bash
sudo -u postgres psql << 'EOF'
CREATE DATABASE phishing_db OWNER postgres ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8';
\c phishing_db
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
\dt
EOF
```

---

## Çözüm 4: postgres Şifresini Sıfırla (Eğer hiçbiri işe yaramazsa)

```bash
# postgres user'ı sudo ile güncelle
sudo -u postgres psql << 'EOF'
ALTER USER postgres WITH PASSWORD 'aegis123456';
EOF

# Sonra psql'de kullan
sudo psql -U postgres -d phishing_db -c "SELECT 1;"
# Şifre gir: aegis123456
```

---

**EN İYİ: Çözüm 1'i Dene**
```bash
sudo -u postgres psql -f scripts/db_setup.sql
```

Bu çalışmazsa, Çözüm 2'yi yapıp tekrar dene!
