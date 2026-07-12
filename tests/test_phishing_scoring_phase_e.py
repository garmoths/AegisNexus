def test_classify_with_confidence_safe_high_confidence():
    from modules.phishing_detector.scanner import classify_with_confidence

    result = classify_with_confidence(90, signal_count=10)
    assert result["verdict"] == "✅ Güvenli"
    assert result["confidence"] == "yüksek"
    assert result["range"]["min"] <= 90 <= result["range"]["max"]


def test_classify_with_confidence_boundary_uncertain():
    from modules.phishing_detector.scanner import classify_with_confidence

    result = classify_with_confidence(60, signal_count=1)
    assert result["verdict"].startswith("⚠️ Belirsiz")
    assert result["confidence"] == "düşük"


def test_classify_with_confidence_risky_threshold_35():
    from modules.phishing_detector.scanner import classify_with_confidence

    result = classify_with_confidence(35, signal_count=6)
    assert result["verdict"] == "🟠 Riskli"


def test_classify_with_confidence_danger_below_35():
    from modules.phishing_detector.scanner import classify_with_confidence

    result = classify_with_confidence(34, signal_count=6)
    assert result["verdict"] == "🚨 Tehlikeli"
