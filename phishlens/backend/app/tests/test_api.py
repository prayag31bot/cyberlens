"""HTTP-layer tests. Skipped automatically when FastAPI/httpx are not installed
(they could not be installed in the build sandbox, so these have NOT been run yet --
run `pytest` after `pip install -r requirements.txt`)."""
import unittest

try:
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.core.config import Settings
    HAVE = True
except Exception:  # pragma: no cover
    HAVE = False


@unittest.skipUnless(HAVE, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def client(self, **kw):
        from app.services.scan_service import ScanService
        s = Settings(**kw)
        svc = ScanService(s, resolver=lambda h, p: ["93.184.216.34"])
        return TestClient(create_app(s, svc))

    def test_health(self):
        r = self.client().get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        self.assertIn("X-Request-ID", r.headers)

    def test_scan_url_ok_and_validation_error(self):
        c = self.client()
        r = c.post("/api/v1/scans/url", json={"url": "http://secure-login-paypal.tk/verify"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["verdict"], "SUSPICIOUS")
        bad = c.post("/api/v1/scans/url", json={"url": "javascript:alert(1)"})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(bad.json()["error"]["code"], "invalid_url")
        self.assertEqual(c.post("/api/v1/scans/url", json={}).status_code, 422)

    def test_rate_limit(self):
        c = self.client(rate_limit_per_minute=2)
        codes = [c.post("/api/v1/scans/url", json={"url": "https://example.com"}).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_private_scan_not_retrievable_but_saved_one_is(self):
        c = self.client()
        priv = c.post("/api/v1/scans/url", json={"url": "https://example.com"}).json()
        self.assertEqual(c.get(f"/api/v1/scans/{priv['scan_id']}").status_code, 404)
        kept = c.post("/api/v1/scans/url", json={"url": "https://example.com", "privacy_mode": False}).json()
        self.assertEqual(c.get(f"/api/v1/scans/{kept['scan_id']}").status_code, 200)

    def test_security_headers(self):
        h = self.client().get("/api/v1/health").headers
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
