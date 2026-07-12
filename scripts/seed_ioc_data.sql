-- IOC (Indicators of Compromise) Test Data
-- Frankfurt PostgreSQL - phishing_db

-- Temizle (varsa)
DELETE FROM indicators_of_compromise;

-- IOC Verileri Ekle (tüm NOT NULL columns eklendi)
INSERT INTO indicators_of_compromise (
    ioc_type,
    ioc_value,
    source,
    threat_type,
    risk_score,
    confidence,
    first_seen,
    last_seen,
    detection_count,
    ioc_metadata,
    created_at
) VALUES

-- Yüksek Risk (CRITICAL) - 90+
('IP_ADDRESS', '195.154.32.108', 'AbuseIPDB', 'Botnet C&C', 94, 0.95, NOW() - INTERVAL '5 days', NOW(), 250,
 '{"reports": 250, "detection_rate": 0.85}', NOW()),

('IP_ADDRESS', '103.145.23.45', 'AbuseIPDB', 'Malware Distribution', 92, 0.92, NOW() - INTERVAL '4 days', NOW(), 187,
 '{"reports": 187, "detection_rate": 0.92}', NOW() - INTERVAL '1 day'),

('DOMAIN', 'paypa1.secure-verify.tk', 'URLhaus', 'Phishing', 91, 0.88, NOW() - INTERVAL '10 days', NOW(), 12,
 '{"phishing_target": "PayPal", "urls_count": 12}', NOW() - INTERVAL '2 days'),

('URL', 'http://secure-amazon-login.ru/account/verify', 'PhishTank', 'Credential Harvesting', 88, 0.87, NOW() - INTERVAL '8 days', NOW(), 45,
 '{"screenshot": "suspicious"}', NOW() - INTERVAL '3 days'),

('EMAIL', 'attacker.botnet@evilhost.net', 'AbuseIPDB', 'Botnet', 87, 0.85, NOW() - INTERVAL '12 days', NOW(), 15,
 '{"campaigns": 15, "victims": 2450}', NOW() - INTERVAL '4 days'),

-- Orta Risk (MEDIUM) - 50-79
('IP_ADDRESS', '92.118.160.55', 'AbuseIPDB', 'Spam Source', 68, 0.68, NOW() - INTERVAL '3 days', NOW(), 45,
 '{"reports": 45, "detection_rate": 0.65}', NOW()),

('DOMAIN', 'mail.microsoftonline-check.com', 'URLhaus', 'Phishing', 72, 0.72, NOW() - INTERVAL '6 days', NOW(), 8,
 '{"phishing_target": "Microsoft"}', NOW() - INTERVAL '1 day'),

('HASH', 'a4fb3c2d7e8f1b9c6a2d5e8f1a3b6c9d', 'AbuseIPDB', 'Trojan', 75, 0.75, NOW() - INTERVAL '7 days', NOW(), 32,
 '{"file_type": "exe", "malware_family": "Trojan.Generic"}', NOW() - INTERVAL '2 days'),

('EMAIL', 'notification@paypal-verify.biz', 'URLhaus', 'Spam', 70, 0.70, NOW() - INTERVAL '15 days', NOW(), 8,
 '{"spam_campaigns": 8}', NOW() - INTERVAL '5 days'),

('URL', 'https://verify-apple-account.xyz/login', 'PhishTank', 'Phishing', 65, 0.65, NOW() - INTERVAL '9 days', NOW(), 12,
 '{"detection_date": "2026-04-14"}', NOW() - INTERVAL '3 days'),

-- Düşük Risk (LOW) - <50
('IP_ADDRESS', '188.40.75.133', 'AbuseIPDB', 'Proxy', 42, 0.42, NOW() - INTERVAL '14 days', NOW(), 8,
 '{"reports": 8, "detection_rate": 0.15}', NOW()),

('DOMAIN', 'example-test.ml', 'URLhaus', 'Phishing', 38, 0.38, NOW() - INTERVAL '20 days', NOW(), 2,
 '{"status": "inactive"}', NOW() - INTERVAL '1 day'),

('EMAIL', 'noreply@notification-service.net', 'AbuseIPDB', 'Suspicious', 35, 0.35, NOW() - INTERVAL '25 days', NOW(), 5,
 '{"false_positives": 5}', NOW() - INTERVAL '6 days'),

('HASH', 'b8c4d1e9f3a7c2b5d8e1f4a7b0c3d6e9', 'URLhaus', 'Malware', 28, 0.28, NOW() - INTERVAL '30 days', NOW(), 3,
 '{"detection_rate": 0.05, "sandbox": "clean"}', NOW() - INTERVAL '7 days'),

('URL', 'http://info-update.site/newsletter', 'PhishTank', 'Spam', 22, 0.22, NOW() - INTERVAL '18 days', NOW(), 1,
 '{"low_confidence": true}', NOW() - INTERVAL '4 days');

-- Istatistik sorgusu
SELECT 
    COUNT(*) as total_iocs,
    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as high_risk,
    SUM(CASE WHEN risk_score >= 50 AND risk_score < 80 THEN 1 ELSE 0 END) as medium_risk,
    SUM(CASE WHEN risk_score < 50 THEN 1 ELSE 0 END) as low_risk,
    NOW() as last_update
FROM indicators_of_compromise;
