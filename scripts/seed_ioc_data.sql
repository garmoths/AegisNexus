-- IOC (Indicators of Compromise) Test Data
-- Frankfurt PostgreSQL - phishing_db

-- Temizle (opsiyonel - varsa sil)
-- TRUNCATE TABLE indicators_of_compromise CASCADE;

-- IOC Verileri Ekle
INSERT INTO indicators_of_compromise (
    ioc_type,
    ioc_value,
    source,
    risk_score,
    ioc_metadata,
    created_at
) VALUES

-- Yüksek Risk (CRITICAL) - 90+
('IP_ADDRESS', '195.154.32.108', 'AbuseIPDB', 94, 
 '{"reports": 250, "detection_rate": 0.85, "threat_type": "Botnet C&C"}', NOW()),

('IP_ADDRESS', '103.145.23.45', 'AbuseIPDB', 92,
 '{"reports": 187, "detection_rate": 0.92, "threat_type": "Malware Distribution"}', NOW() - INTERVAL '1 day'),

('DOMAIN', 'paypa1.secure-verify.tk', 'URLhaus', 91,
 '{"phishing_target": "PayPal", "last_seen": "2026-04-16", "urls_count": 12}', NOW() - INTERVAL '2 days'),

('URL', 'http://secure-amazon-login.ru/account/verify', 'PhishTank', 88,
 '{"phishing_type": "credential_harvesting", "screenshot": "suspicious"}', NOW() - INTERVAL '3 days'),

('EMAIL', 'attacker.botnet@evilhost.net', 'AbuseIPDB', 87,
 '{"campaigns": 15, "victims": 2450, "malware": "Emotet"}', NOW() - INTERVAL '4 days'),

-- Orta Risk (MEDIUM) - 50-79
('IP_ADDRESS', '92.118.160.55', 'AbuseIPDB', 68,
 '{"reports": 45, "detection_rate": 0.65, "threat_type": "Spam Source"}', NOW()),

('DOMAIN', 'mail.microsoftonline-check.com', 'URLhaus', 72,
 '{"phishing_target": "Microsoft", "last_seen": "2026-04-15"}', NOW() - INTERVAL '1 day'),

('HASH', 'a4fb3c2d7e8f1b9c6a2d5e8f1a3b6c9d', 'AbuseIPDB', 75,
 '{"file_type": "exe", "malware_family": "Trojan.Generic", "size": 245760}', NOW() - INTERVAL '2 days'),

('EMAIL', 'notification@paypal-verify.biz', 'URLhaus', 70,
 '{"spam_campaigns": 8, "targets": "Financial Services"}', NOW() - INTERVAL '5 days'),

('URL', 'https://verify-apple-account.xyz/login', 'PhishTank', 65,
 '{"phishing_type": "apple_impersonation", "detection_date": "2026-04-14"}', NOW() - INTERVAL '3 days'),

-- Düşük Risk (LOW) - <50
('IP_ADDRESS', '188.40.75.133', 'AbuseIPDB', 42,
 '{"reports": 8, "detection_rate": 0.15, "threat_type": "Proxy"}', NOW()),

('DOMAIN', 'example-test.ml', 'URLhaus', 38,
 '{"phishing_target": "Generic", "last_seen": "2026-04-16", "status": "inactive"}', NOW() - INTERVAL '1 day'),

('EMAIL', 'noreply@notification-service.net', 'AbuseIPDB', 35,
 '{"legitimate_concern": true, "false_positives": 5}', NOW() - INTERVAL '6 days'),

('HASH', 'b8c4d1e9f3a7c2b5d8e1f4a7b0c3d6e9', 'URLhaus', 28,
 '{"file_type": "dll", "detection_rate": 0.05, "sandbox": "clean"}', NOW() - INTERVAL '7 days'),

('URL', 'http://info-update.site/newsletter', 'PhishTank', 22,
 '{"phishing_type": "newsletter_impersonation", "low_confidence": true}', NOW() - INTERVAL '4 days');

-- Istatistik sorgusu
SELECT 
    COUNT(*) as total_iocs,
    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as high_risk,
    SUM(CASE WHEN risk_score >= 50 AND risk_score < 80 THEN 1 ELSE 0 END) as medium_risk,
    SUM(CASE WHEN risk_score < 50 THEN 1 ELSE 0 END) as low_risk,
    NOW() as last_update
FROM indicators_of_compromise;
