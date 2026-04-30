"""Auth ve API endpoint testleri — FastAPI TestClient ile."""
import hashlib
import unittest

from fastapi.testclient import TestClient


class TestAuthAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_register_missing_email(self):
        r = self.client.post("/api/v2/auth/register", json={})
        self.assertEqual(r.status_code, 422)

    def test_register_invalid_email(self):
        r = self.client.post("/api/v2/auth/register", json={"email": "not-an-email"})
        self.assertEqual(r.status_code, 422)

    def test_register_and_login(self):
        try:
            r = self.client.post("/api/v2/auth/register", json={
                "email": "testuser@aegisnexus.dev",
                "full_name": "Test User",
            })
        except Exception:
            self.skipTest("Veritabanı bağlantısı yok")
        if r.status_code in (500, 503):
            self.skipTest("Veritabanı bağlantısı yok")
        self.assertIn(r.status_code, (200, 201, 409))
        if r.status_code in (200, 201):
            data = r.json()
            self.assertIn("api_key", data)
            api_key = data["api_key"]

            try:
                r2 = self.client.post("/api/v2/auth/login", json={
                    "email": "testuser@aegisnexus.dev",
                    "api_key": api_key,
                })
            except Exception:
                self.skipTest("Veritabanı bağlantısı yok")
            if r2.status_code in (500, 503):
                self.skipTest("Veritabanı bağlantısı yok")
            self.assertEqual(r2.status_code, 200)
            login_data = r2.json()
            self.assertEqual(login_data["role"], "free")

    def test_login_wrong_key(self):
        try:
            r = self.client.post("/api/v2/auth/login", json={
                "email": "nonexistent@aegisnexus.dev",
                "api_key": "aeg_invalidkey",
            })
        except Exception:
            self.skipTest("Veritabanı bağlantısı yok")
        if r.status_code in (500, 503):
            self.skipTest("Veritabanı bağlantısı yok")
        self.assertIn(r.status_code, (401,))

    def test_rotate_key_without_auth(self):
        r = self.client.post("/api/v2/auth/rotate-key")
        self.assertEqual(r.status_code, 401)

    def test_logout_without_auth(self):
        r = self.client.post("/api/v2/auth/logout")
        self.assertEqual(r.status_code, 401)


class TestReportsAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_analyze_without_key(self):
        r = self.client.post("/api/v2/reports/analyze", json={"description": "test"})
        self.assertEqual(r.status_code, 401)

    def test_list_without_key(self):
        r = self.client.get("/api/v2/reports/")
        self.assertEqual(r.status_code, 401)


class TestSubscriptionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_me_without_key(self):
        r = self.client.get("/api/v2/subscription/me")
        self.assertEqual(r.status_code, 401)

    def test_upgrade_without_key(self):
        r = self.client.post("/api/v2/subscription/upgrade", json={"plan": "premium"})
        self.assertEqual(r.status_code, 401)


class TestCorporateAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_cases_without_key(self):
        r = self.client.get("/api/v2/corporate/cases")
        self.assertEqual(r.status_code, 401)

    def test_stats_without_key(self):
        r = self.client.get("/api/v2/corporate/stats")
        self.assertEqual(r.status_code, 401)


class TestAdminAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_users_without_admin_key(self):
        r = self.client.get("/api/v2/admin/users")
        self.assertIn(r.status_code, (401, 403))


class TestAuthHelpers(unittest.TestCase):
    """Auth yardımcı fonksiyonların unit testleri — DB gerektirmez."""

    def test_hash_key_deterministic(self):
        from app.auth import _hash_key
        h1 = _hash_key("test-key-123")
        h2 = _hash_key("test-key-123")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA256 hex

    def test_hash_key_different_inputs(self):
        from app.auth import _hash_key
        h1 = _hash_key("key-a")
        h2 = _hash_key("key-b")
        self.assertNotEqual(h1, h2)

    def test_generate_api_key_format(self):
        from app.auth import generate_api_key
        raw, key_hash, prefix = generate_api_key()
        self.assertTrue(raw.startswith("aeg_"))
        self.assertEqual(len(key_hash), 64)
        self.assertEqual(prefix, raw[:8])


if __name__ == "__main__":
    unittest.main()
