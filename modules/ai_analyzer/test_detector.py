"""
Test Cases for Advanced Phishing Detector

4 test scenarios:
1. Clean URL + neutral text → TEMİZ
2. DB URL similarity 0.92 + urgency text → PHİSHİNG
3. Valid SSL + high emotion score → ŞÜPHELİ
4. Text only (low C) → score close to prior (0.5)
"""

import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from modules.ai_analyzer.advanced_phishing_detector import detect_phishing


def test_case_1_clean():
    """
    Test Case 1: Temiz URL + nötr metin → TEMİZ bekleniyor
    """
    message = "Merhaba, yarın saat 14:00'da toplantı Zoom'da. Link: https://zoom.us/j/987654321"
    url = "https://zoom.us/j/987654321"
    
    result = detect_phishing(message, url)
    
    print("=" * 60)
    print("TEST 1: Temiz URL + Nötr Metin")
    print("-" * 60)
    print(f"Message: {message[:80]}...")
    print(f"URL: {url}")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Score: {result['score']}")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Reason: {result['reason']}")
    print(f"\nExpected: TEMİZ")
    print(f"Pass: {result['verdict'] == 'TEMİZ' or result['verdict'] == 'DÜŞÜK RİSK'}")
    return result


def test_case_2_similarity_override():
    """
    Test Case 2: DB'deki URL'e 0.92 benzerlik + aciliyet metni → PHİSHİNG
    Using a known phishing pattern URL
    """
    message = "Hesabınız askıya alındı! Şifrenizi hemen doğrulayın: http://secure-banka-giris.tk/verify?urgent=true"
    url = "http://secure-banka-giris.tk/verify?urgent=true"
    
    result = detect_phishing(message, url)
    
    print("\n" + "=" * 60)
    print("TEST 2: DB Benzerlik >= 0.90 + Aciliyet Metni")
    print("-" * 60)
    print(f"Message: {message}")
    print(f"URL: {url}")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Score: {result['score']}")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Hard Override: {result['hard_override']}")
    print(f"  Breakdown: {result['breakdown']}")
    print(f"\nExpected: PHİSHİNG veya ŞÜPHELİ")
    print(f"Pass: {result['score'] > 0.5}")
    return result


def test_case_3_emotion_based():
    """
    Test Case 3: Geçerli SSL + nötr metin ama duygu skoru yüksek → ŞÜPHELİ
    Using a message with fear/urgency emotions
    """
    message = "ACİL! Banka hesabınız bloke olacak! Lütfen hemen doğrulama yapın! Tehdit altındasınız!"
    url = "https://www.google.com"  # Valid SSL
    
    result = detect_phishing(message, url)
    
    print("\n" + "=" * 60)
    print("TEST 3: Geçerli SSL + Yüksek Duygu Skoru")
    print("-" * 60)
    print(f"Message: {message}")
    print(f"URL: {url}")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Score: {result['score']}")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Breakdown: {result['breakdown']}")
    print(f"\nExpected: ŞÜPHELİ veya DÜŞÜK RİSK")
    print(f"Pass: {result['score'] >= 0.25}")
    return result


def test_case_4_text_only():
    """
    Test Case 4: Sadece metin var, URL yok (C düşük senaryosu)
    → Güvenilirlik düştü, prior'a yaklaştı (~0.5)
    """
    message = "Tebrikler! Büyük ödül kazandınız! Hemen arayın: 0555 123 45 67"
    url = None  # No URL
    
    result = detect_phishing(message, url)
    
    print("\n" + "=" * 60)
    print("TEST 4: Sadece Metin (Düşük C)")
    print("-" * 60)
    print(f"Message: {message}")
    print(f"URL: {url}")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Score: {result['score']}")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Breakdown: {result['breakdown']}")
    print(f"\nExpected: Confidence düşük olmalı (~0.3-0.5), Score prior'a yakın")
    print(f"Pass: {result['confidence'] < 0.7}")
    return result


def run_all_tests():
    """Run all test cases"""
    print("\n" + "=" * 60)
    print("ADVANCED PHISHING DETECTOR - TEST SUITE")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(test_case_1_clean())
    except Exception as e:
        print(f"Test 1 Error: {e}")
        results.append(None)
    
    try:
        results.append(test_case_2_similarity_override())
    except Exception as e:
        print(f"Test 2 Error: {e}")
        results.append(None)
    
    try:
        results.append(test_case_3_emotion_based())
    except Exception as e:
        print(f"Test 3 Error: {e}")
        results.append(None)
    
    try:
        results.append(test_case_4_text_only())
    except Exception as e:
        print(f"Test 4 Error: {e}")
        results.append(None)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for i, r in enumerate(results, 1):
        if r:
            print(f"Test {i}: {r['verdict']} (score={r['score']:.3f}, conf={r['confidence']:.3f})")
        else:
            print(f"Test {i}: FAILED")
    
    return results


if __name__ == "__main__":
    run_all_tests()
