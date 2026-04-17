-- IOC (Indicators of Compromise) Test Data
-- Frankfurt PostgreSQL - phishing_db

-- Temizle (varsa)
DELETE FROM indicators_of_compromise;

-- IOC Verileri Ekle (threat_type column'ı fixlenmiş)
INSERT INTO indicators_of_compromise (
    ioc_type,
    ioc_value,
    threat_type,
    source,
    risk_score,
    ioc_metadata,
    created_at
) VALUES

-- Yüksek Risk (CRITICAL) - 90+
('IP_ADDRESS', '195.154.32.108', 'Botnet C&C', 'AbuseIPDB', 94, 
 '{"reports": 250, "detection_rate": 0.85}', NOW()),

('IP_ADDRESS', '103.145.23.45', 'Malware Distribution', 'AbuseIPDB', 92,
 '{"reports": 187, "detection_rate": 0.92}', NOW() - INTERVAL '1 day'),

('DOMAIN', 'paypa1.secure-verify.tk', 'Phishing', 'URLhaus', 91,
 '{"phishing_target": "PayPal", "urls_count": 12}', NOW() - INTERVAL '2 days'),

('URL', 'http://secure-amazon-login.ru/account/verify', 'Credential Harvesting', 'PhishTank', 88,
 '{"screenshot": "suspicious"}', NOW() - INTERVAL '3 days'),

('EMAIL', 'attacker.botnet@evilhost.net', 'Botnet', 'AbuseIPDB', 87,
 '{"campaigns": 15, "victims": 2450}', NOW() - INTERVAL '4 days'),

-- Orta Risk (MEDIUM) - 50-79
('IP_ADDRESS', '92.118.160.55', 'Spam Source', 'AbuseIPDB', 68,
 '{"reports": 45, "detection_rate": 0.65}', NOW()),

('DOMAIN', 'mail.microsoftonline-check.com', 'Phishing', 'URLhaus', 72,
 '{"phishing_target": "Microsoft"}', NOW() - INTERVAL '1 day'),

('HASH', 'a4fb3c2d7e8f1b9c6a2d5e8f1a3b6c9d', 'Trojan', 'AbuseIPDB', 75,
 '{"file_type": "exe", "malware_family": "Trojan.Generic"}', NOW() - INTERVAL '2 days'),

('EMAIL', 'notification@paypal-verify.biz', 'Spam', 'URLhaus', 70,
 '{"spam_campaigns": 8}', NOW() - INTERVAL '5 days'),

('URL', 'https://verify-apple-account.xyz/login', 'Phishing', 'PhishTank', 65,
 '{"detection_date": "2026-04-14"}', NOW() - INTERVAL '3 days'),

-- Düşük Risk (LOW) - <50
('IP_ADDRESS', '188.40.75.133', 'Proxy', 'AbuseIPDB', 42,
 '{"reports": 8, "detection_rate": 0.15}', NOW()),

('DOMAIN', 'example-test.ml', 'Phishing', 'URLhaus', 38,
 '{"status": "inactive"}', NOW() - INTERVAL '1 day'),

('EMAIL', 'noreply@notification-service.net', 'Suspicious', 'AbuseIPDB', 35,
 '{"false_positives": 5}', NOW() - INTERVAL '6 days'),

('HASH', 'b8c4d1e9f3a7c2b5d8e1f4a7b0c3d6e9', 'Malware', 'URLhaus', 28,
 '{"detection_rate": 0.05, "sandbox": "clean"}', NOW() - INTERVAL '7 days'),

('URL', 'http://info-update.site/newsletter', 'Spam', 'PhishTank', 22,
 '{"low_confidence": true}', NOW() - INTERVAL '4 days');

-- Istatistik sorgusu
SELECT 
    COUNT(*) as total_iocs,
    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as high_risk,
    SUM(CASE WHEN risk_score >= 50 AND risk_score < 80 THEN 1 ELSE 0 END) as medium_risk,
    SUM(CASE WHEN risk_score < 50 THEN 1 ELSE 0 END) as low_risk,
    NOW() as last_update
FROM indicators_of_compromise;
