"""Gemini servis testleri — mock Gemini yanıtları ile.

Gerçek API çağrısı yapılmaz, _call_gemini mock'lanır.
"""
import json
import unittest
from unittest.mock import patch, MagicMock

from modules.victim_atlas.gemini_service import (
    _extract_json,
    _parse_analysis,
    analyze_user_report,
    classify_case,
    generate_protection_card,
    generate_weekly_digest,
)


MOCK_ANALYSIS_RESPONSE = """ANALİZ SONUCU:
- Saldırı Tipi: smishing
- Risk Skoru: 85
- Kayıp Türü: bank_account
- Hedef Platform: mobile
- Kritik Uyarı: SMS ile gelen linklere tıklamayın

KORUNMA PLANI:
1. Bankanızı arayın ve hesabınızı dondurun
2. SMS linkine tıkladıysanız tarayıcı geçmişini temizleyin
3. Mobil cihazınızı antivirüs ile tarayın
4. Banka uygulaması şifrenizi değiştirin
5. İleriye dönük SMS filtreleme aktif edin

BAŞVURU KURUMLARI:
- Bankanızın müşteri hizmetleri
- BDDK - 144
"""

MOCK_CLASSIFY_RESPONSE = """```json
{
  "attack_method": "smishing",
  "loss_type": "bank_account",
  "target_platform": "mobile",
  "severity": 80,
  "confidence": 75,
  "tags": ["sms", "banka", "link"],
  "region": "İstanbul",
  "critical_warning": "Sahte SMS ile banka bilgileri çalınıyor",
  "narrative_summary": "Kullanıcıya sahte banka SMS'i gönderilerek linkle yönlendirme yapılıyor."
}
```"""

MOCK_DIGEST_RESPONSE = """Son haftada siber dolandırıcılık vakalarında artış gözlemlendi. Toplam 47 yeni vaka kaydedildi, bunların %35'i smishing kategorisinde. Banka taklidi yapan dolandırıcılar özellikle mobil kullanıcıları hedef alıyor.

En dikkat çekici vaka, İstanbul'da faaliyet gösteren bir grubun sahte banka uygulaması ile 50'den fazla mağduru etkilemesi oldu. Mağdurlar Google Play'de yayınlanan sahte uygulamayı indirdikten sonra banka bilgilerini girdi ve hesapları boşaltıldı.

Bu hafta özellikle SMS ile gelen linklere dikkat edin. Bankanızın resmi uygulamasını sadece resmi web sitesinden indirin ve 2FA mutlaka aktif edin."""

MOCK_PROTECTION_CARD = """🛡️ KORUNMA KARTI

⚠️ Tehdit Seviyesi: KRİTİK
📌 Saldırı Türü: Smishing
💰 Kayıp Türü: bank_account

HIZLI KORUNMA ADIMLARI:
1. Bankanızı hemen arayın, hesabı dondurun
2. SMS linkine tıkladıysanız tarayıcı verilerini silin
3. Mobil cihazınızı güvenlik taramasından geçirin
4. Banka şifrenizi değiştirin
5. SMS filtreleme ve engelleme aktif edin

📞 ACİL İLETİŞİM:
- Banka müşteri hizmetleri: 444 0 444

🔒 TEKRAR KORUNMA:
- Bilinmeyen numaralardan gelen linklere tıklamayın"""


class TestExtractJson(unittest.TestCase):
    def test_json_in_code_block(self):
        text = '```json\n{"key": "value"}\n```'
        result = _extract_json(text)
        self.assertEqual(result, {"key": "value"})

    def test_json_in_plain_code_block(self):
        text = '```\n{"key": "value"}\n```'
        result = _extract_json(text)
        self.assertEqual(result, {"key": "value"})

    def test_direct_json(self):
        text = '{"key": "value"}'
        result = _extract_json(text)
        self.assertEqual(result, {"key": "value"})

    def test_invalid_json(self):
        text = "bu bir json değil"
        result = _extract_json(text)
        self.assertEqual(result, {})


class TestParseAnalysis(unittest.TestCase):
    def test_parse_mock_response(self):
        result = _parse_analysis(MOCK_ANALYSIS_RESPONSE)
        self.assertEqual(result["attack_type"], "smishing")
        self.assertEqual(result["risk_score"], 85)
        self.assertEqual(result["loss_type"], "bank_account")
        self.assertIn("Bankanızı arayın", result["protection_plan"])

    def test_parse_empty(self):
        result = _parse_analysis("")
        self.assertEqual(result["attack_type"], "unknown")
        self.assertEqual(result["risk_score"], 50)

    def test_parse_json_response(self):
        json_text = json.dumps({
            "attack_type": "phishing",
            "risk_score": 70,
            "loss_type": "identity",
        })
        result = _parse_analysis(json_text)
        self.assertEqual(result["attack_type"], "phishing")
        self.assertEqual(result["risk_score"], 70)


class TestAnalyzeUserReport(unittest.TestCase):
    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_analyze(self, mock_call):
        mock_call.return_value = MOCK_ANALYSIS_RESPONSE
        result = analyze_user_report("SMS ile dolandırıldım")
        self.assertEqual(result["attack_type"], "smishing")
        self.assertIn("protection_plan", result)
        mock_call.assert_called_once()


class TestClassifyCase(unittest.TestCase):
    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_classify_json(self, mock_call):
        mock_call.return_value = MOCK_CLASSIFY_RESPONSE
        result = classify_case("Sahte banka SMS'i ile dolandırıcılık")
        self.assertEqual(result["attack_method"], "smishing")
        self.assertEqual(result["severity"], 80)
        self.assertIn("tags", result)

    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_classify_fallback(self, mock_call):
        mock_call.return_value = "Bu bir JSON değil, sadece metin."
        result = classify_case("Herhangi bir metin")
        self.assertEqual(result["attack_method"], "other")
        self.assertEqual(result["severity"], 50)


class TestWeeklyDigest(unittest.TestCase):
    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_digest(self, mock_call):
        mock_call.return_value = MOCK_DIGEST_RESPONSE
        cases = [{"title": "Smishing vaka", "method": "smishing", "severity": 80}]
        result = generate_weekly_digest(cases)
        self.assertIn("siber dolandırıcılık", result)
        mock_call.assert_called_once()

    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_digest_empty_cases(self, mock_call):
        mock_call.return_value = "Bu hafta kayıtlı vaka yok."
        result = generate_weekly_digest([])
        self.assertIn("vaka", result)


class TestProtectionCard(unittest.TestCase):
    @patch("modules.victim_atlas.gemini_service._call_gemini")
    def test_card(self, mock_call):
        mock_call.return_value = MOCK_PROTECTION_CARD
        case = {
            "case_title": "Smishing ile banka dolandırıcılığı",
            "attack_method": "smishing",
            "loss_type": "bank_account",
            "target_platform": "mobile",
            "severity_score": 85,
            "confidence_score": 80,
            "narrative_summary": "Kullanıcıya sahte SMS gönderildi",
            "critical_warning": "SMS linklerine tıklamayın",
            "region": "İstanbul",
        }
        result = generate_protection_card(case)
        self.assertIn("card_text", result)
        self.assertIn("KORUNMA KARTI", result["card_text"])
        self.assertEqual(result["attack_method"], "smishing")


if __name__ == "__main__":
    unittest.main()
