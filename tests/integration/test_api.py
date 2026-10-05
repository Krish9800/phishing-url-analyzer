"""Integration tests for FastAPI REST API endpoints."""

from starlette.testclient import TestClient

from phish_analyzer.api.app import app

client = TestClient(app)


def test_health_check() -> None:
    """Verify health endpoint response and metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "Phishing URL Analyzer" in data["service"]


def test_security_headers_present() -> None:
    """Verify defensive HTTP security headers are injected."""
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "max-age=31536000" in response.headers["strict-transport-security"]


def test_api_analyze_benign() -> None:
    """Verify analyzing a benign URL."""
    payload = {"url": "https://www.google.com/search?q=infosec"}
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["raw_url"] == payload["url"]
    assert data["risk_level"] == "BENIGN"
    assert data["threat_score"] < 40
    assert "google[.]com" in data["defanged_url"]


def test_api_analyze_malicious() -> None:
    """Verify analyzing a malicious obfuscated IP URL."""
    payload = {"url": "http://0x7f000001/malware.exe"}
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["risk_level"] == "MALICIOUS"
    assert data["threat_score"] >= 70
    assert len(data["triggers"]) > 0


def test_api_analyze_validation_error() -> None:
    """Verify validation error on empty URL."""
    response = client.post("/api/v1/analyze", json={"url": ""})
    assert response.status_code == 422


def test_api_batch_analyze() -> None:
    """Verify bulk analysis endpoint."""
    payload = {
        "urls": [
            "https://google.com",
            "http://0x7f000001/status",
            "http://account-update.tk/login",
        ]
    }
    response = client.post("/api/v1/analyze/batch", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["total"] == 3
    assert "BENIGN" in data["summary"]
    assert "MALICIOUS" in data["summary"]
    assert len(data["reports"]) == 3


def test_api_batch_analyze_limit_exceeded() -> None:
    """Verify DoS limit guard rejecting batches > 200 items."""
    oversized = ["https://example.com"] * 201
    response = client.post("/api/v1/analyze/batch", json={"urls": oversized})
    assert response.status_code == 422


def test_api_defang_endpoint() -> None:
    """Verify URL defanging endpoint."""
    payload = {"url": "http://evil-tracker.com/click?id=123"}
    response = client.post("/api/v1/defang", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["raw_url"] == payload["url"]
    assert data["defanged_url"] == "hxxp://evil-tracker[.]com/click?id=123"
