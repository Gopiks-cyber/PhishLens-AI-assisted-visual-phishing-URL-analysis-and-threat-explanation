import pytest
import json
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestAnalyzeEndpoint:
    def test_valid_json_request(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["url"] == "https://example.com"
        assert "risk_score" in data
        assert "risk_level" in data
        assert "indicators" in data
        assert "recommendations" in data

    def test_missing_url_field(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({}),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["risk_level"] == "error"
        assert "error" in data

    def test_empty_url_string(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": ""}),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["risk_level"] == "error"

    def test_malformed_url(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "not-a-url"}),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["risk_level"] == "error"

    def test_missing_content_type(self, client):
        response = client.post(
            "/api/analyze",
            data='{"url": "https://example.com"}',
            content_type="text/plain"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["risk_level"] == "error"

    def test_invalid_json(self, client):
        response = client.post(
            "/api/analyze",
            data="not valid json",
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["risk_level"] == "error"

    def test_suspicious_url_returns_indicators(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://paypal.phisher.tk/login"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["indicators"]) > 0
        assert data["risk_score"] > 0

    def test_ip_address_url(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "http://192.168.1.1/admin"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        names = [i["name"] for i in data["indicators"]]
        assert "IP Address Host" in names

    def test_url_shortener(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://bit.ly/xyz"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        names = [i["name"] for i in data["indicators"]]
        assert "URL Shortener" in names

    def test_response_structure_complete(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        data = response.get_json()
        required_keys = {"url", "risk_score", "risk_level", "indicators", "recommendations"}
        assert required_keys.issubset(data.keys())
        assert isinstance(data["risk_score"], int)
        assert 0 <= data["risk_score"] <= 100
        assert data["risk_level"] in ("minimal", "low", "medium", "high", "error")
        assert isinstance(data["indicators"], list)
        assert isinstance(data["recommendations"], list)
        for ind in data["indicators"]:
            assert "name" in ind
            assert "detail" in ind
            assert "severity" in ind
            assert ind["severity"] in ("high", "medium", "low")


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"