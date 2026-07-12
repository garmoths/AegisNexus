-- Performance Optimization Indexes for Phishing Detector
-- Add these indexes to improve query performance on 1.1M records

-- PhishingURL table indexes
CREATE INDEX IF NOT EXISTS idx_phishing_url_id_desc ON phishing_urls(id DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_url_created_at_desc ON phishing_urls(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_url_domain_norm ON phishing_urls(domain_norm);
CREATE INDEX IF NOT EXISTS idx_phishing_url_status ON phishing_urls(status);
CREATE INDEX IF NOT EXISTS idx_phishing_url_target ON phishing_urls(target);
CREATE INDEX IF NOT EXISTS idx_phishing_url_online ON phishing_urls(online);

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_phishing_url_created_status ON phishing_urls(created_at DESC, status);

-- Full-text search index for URL searches (if supported)
-- CREATE INDEX IF NOT EXISTS idx_phishing_url_fulltext ON phishing_urls(url);

-- Cache table indexes
CREATE INDEX IF NOT EXISTS idx_cache_phishing_urls_checked_at ON phishing_urls(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_cache_phishing_urls_domain ON phishing_urls(domain);
CREATE INDEX IF NOT EXISTS idx_cache_phishing_urls_risk_score ON phishing_urls(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cache_phishing_urls_is_safe ON phishing_urls(is_safe);

-- IOC table indexes
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON indicators_of_compromise(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_threat_type ON indicators_of_compromise(threat_type);
CREATE INDEX IF NOT EXISTS idx_ioc_last_seen ON indicators_of_compromise(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_confidence ON indicators_of_compromise(confidence DESC);

-- Composite index for threat type queries
CREATE INDEX IF NOT EXISTS idx_ioc_type_last_seen ON indicators_of_compromise(threat_type, last_seen DESC);
