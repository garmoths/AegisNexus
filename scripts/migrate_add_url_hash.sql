-- Mevcut PostgreSQL tablosuna ölçek ve hızlı sorgu için sütunlar (bir kez çalıştırın).
ALTER TABLE phishing_urls ADD COLUMN IF NOT EXISTS url_hash VARCHAR(64);
ALTER TABLE phishing_urls ADD COLUMN IF NOT EXISTS domain_norm VARCHAR(512);

CREATE UNIQUE INDEX IF NOT EXISTS uq_phishing_urls_url_hash
  ON phishing_urls (url_hash) WHERE url_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_phishing_urls_domain_norm
  ON phishing_urls (domain_norm) WHERE domain_norm IS NOT NULL;
