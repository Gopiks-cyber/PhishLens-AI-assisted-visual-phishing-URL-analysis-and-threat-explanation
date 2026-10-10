import pytest
import json
import uuid
from app import app
import investigations


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure a clean database for each test."""
    investigations.init_db()
    conn = investigations.connect()
    try:
        conn.execute("DELETE FROM investigations")
        conn.commit()
    finally:
        conn.close()


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

    def test_response_includes_score_breakdown(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        data = response.get_json()
        assert "score_breakdown" in data
        breakdown = data["score_breakdown"]
        assert "raw_total" in breakdown
        assert "cap" in breakdown
        assert "final_score" in breakdown
        assert "capped" in breakdown
        assert "contributions" in breakdown
        assert isinstance(breakdown["contributions"], list)

    def test_score_breakdown_reconciles_with_risk_score(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://paypal.phisher.tk/login"}),
            content_type="application/json"
        )
        data = response.get_json()
        breakdown = data["score_breakdown"]
        contribution_sum = sum(c["points"] for c in breakdown["contributions"])
        assert contribution_sum == breakdown["raw_total"]
        assert breakdown["final_score"] == min(breakdown["raw_total"], breakdown["cap"])
        assert breakdown["final_score"] == data["risk_score"]

    def test_score_breakdown_bounds(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://paypal.phisher.tk/login"}),
            content_type="application/json"
        )
        data = response.get_json()
        breakdown = data["score_breakdown"]
        assert 0 <= breakdown["raw_total"]
        assert breakdown["cap"] == 100
        assert 0 <= breakdown["final_score"] <= 100
        assert 0 <= data["risk_score"] <= 100

    def test_score_breakdown_contributions_structure(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://paypal.phisher.tk/login"}),
            content_type="application/json"
        )
        data = response.get_json()
        breakdown = data["score_breakdown"]
        for contribution in breakdown["contributions"]:
            assert "name" in contribution
            assert "severity" in contribution
            assert "points" in contribution
            assert "explanation" in contribution
            assert contribution["severity"] in ("high", "medium", "low")
            assert isinstance(contribution["points"], int)
            assert contribution["points"] > 0

    def test_error_response_includes_score_breakdown(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "not-a-url"}),
            content_type="application/json"
        )
        data = response.get_json()
        assert "score_breakdown" in data
        assert data["score_breakdown"]["final_score"] == 0
        assert data["score_breakdown"]["contributions"] == []

    def test_clean_url_score_breakdown_empty(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://example.com/about"}),
            content_type="application/json"
        )
        data = response.get_json()
        breakdown = data["score_breakdown"]
        assert breakdown["raw_total"] == 0
        assert breakdown["final_score"] == 0
        assert breakdown["contributions"] == []
        assert breakdown["capped"] is False

    def test_xss_payload_url_returned_as_inert_data(self, client):
        """A URL containing an XSS payload must round-trip as inert string data.

        The backend never executes or strips user input; it returns it as a
        JSON string. The frontend is responsible for rendering it safely
        (via textContent), so the exact payload must be preserved.
        """
        payload = "http://example.com/<script>alert('xss')</script>?q=\"><img src=x>"
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": payload}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        # Payload preserved exactly as inert data (not executed, not sanitized).
        assert data["url"] == payload
        assert data["risk_level"] in ("minimal", "low", "medium", "high", "error")
        assert isinstance(data["risk_score"], int)
        assert 0 <= data["risk_score"] <= 100

    def test_xss_payload_in_indicator_evidence_is_inert(self, client):
        """Indicator evidence derived from a payload URL stays inert string data."""
        payload = "http://192.168.1.1/<script>alert(1)</script>"
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": payload}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        names = [i["name"] for i in data["indicators"]]
        assert "IP Address Host" in names
        for ind in data["indicators"]:
            # Every field is a plain string, safe to render via textContent.
            assert isinstance(ind.get("evidence", ""), str)
            assert isinstance(ind.get("detail", ""), str)
            assert isinstance(ind.get("explanation", ""), str)

    def test_successful_analysis_returns_investigation_id_header(self, client):
        """Successful analysis returns X-Investigation-ID header without changing JSON body."""
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "https://paypal.phisher.tk/login"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        # Header present
        investigation_id = response.headers.get("X-Investigation-ID")
        assert investigation_id is not None
        assert investigations.is_valid_id(investigation_id)
        # JSON body unchanged
        data = response.get_json()
        assert data["url"] == "https://paypal.phisher.tk/login"
        assert "risk_score" in data
        assert "investigation_id" not in data  # Not in JSON body

    def test_failed_analysis_no_investigation_id_header(self, client):
        """Failed analysis (400) does not return investigation ID header."""
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "not-a-url"}),
            content_type="application/json"
        )
        assert response.status_code == 400
        investigation_id = response.headers.get("X-Investigation-ID")
        assert investigation_id is None


class TestInvestigationsListEndpoint:
    def test_list_empty_initially(self, client):
        response = client.get("/api/investigations")
        assert response.status_code == 200
        data = response.get_json()
        assert data["investigations"] == []
        assert data["total"] == 0

    def test_list_after_analysis(self, client):
        # Create two investigations
        client.post("/api/analyze", data=json.dumps({"url": "https://paypal.phisher.tk/login"}), content_type="application/json")
        client.post("/api/analyze", data=json.dumps({"url": "https://example.com"}), content_type="application/json")

        response = client.get("/api/investigations")
        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 2
        assert len(data["investigations"]) == 2

    def test_list_pagination_limit(self, client):
        for i in range(5):
            client.post("/api/analyze", data=json.dumps({"url": f"https://example{i}.com"}), content_type="application/json")

        response = client.get("/api/investigations?limit=2")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["investigations"]) == 2
        assert data["total"] == 5

    def test_list_pagination_offset(self, client):
        for i in range(5):
            client.post("/api/analyze", data=json.dumps({"url": f"https://example{i}.com"}), content_type="application/json")

        response = client.get("/api/investigations?limit=2&offset=2")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["investigations"]) == 2
        assert data["total"] == 5

    def test_list_limit_validation_max(self, client):
        response = client.get("/api/investigations?limit=999")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_list_limit_validation_min(self, client):
        response = client.get("/api/investigations?limit=0")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_list_offset_validation_negative(self, client):
        response = client.get("/api/investigations?offset=-1")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_list_urls_redacted(self, client):
        url_with_creds = "https://user:pass@example.com/path"
        client.post("/api/analyze", data=json.dumps({"url": url_with_creds}), content_type="application/json")

        response = client.get("/api/investigations")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["investigations"]) == 1
        assert data["investigations"][0]["url"] == "https://[redacted]@example.com/path"

    def test_list_order_newest_first(self, client):
        client.post("/api/analyze", data=json.dumps({"url": "https://first.com"}), content_type="application/json")
        client.post("/api/analyze", data=json.dumps({"url": "https://second.com"}), content_type="application/json")

        response = client.get("/api/investigations")
        assert response.status_code == 200
        data = response.get_json()
        # Newest first
        assert data["investigations"][0]["url"] == "https://second.com"
        assert data["investigations"][1]["url"] == "https://first.com"


class TestInvestigationsDetailEndpoint:
    def test_get_existing_investigation(self, client):
        resp = client.post("/api/analyze", data=json.dumps({"url": "https://paypal.phisher.tk/login"}), content_type="application/json")
        investigation_id = resp.headers.get("X-Investigation-ID")

        response = client.get(f"/api/investigations/{investigation_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["investigation_id"] == investigation_id
        assert data["url"] == "https://paypal.phisher.tk/login"
        assert "risk_score" in data
        assert "indicators" in data
        assert "created_at" in data

    def test_get_nonexistent_investigation(self, client):
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/investigations/{fake_id}")
        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Investigation not found"

    def test_get_invalid_id_format(self, client):
        response = client.get("/api/investigations/not-a-uuid")
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "Invalid investigation ID format"

    def test_detail_url_redacted(self, client):
        url_with_creds = "https://user:pass@example.com/path"
        resp = client.post("/api/analyze", data=json.dumps({"url": url_with_creds}), content_type="application/json")
        investigation_id = resp.headers.get("X-Investigation-ID")

        response = client.get(f"/api/investigations/{investigation_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["url"] == "https://[redacted]@example.com/path"

    def test_detail_returns_stored_result_no_reanalysis(self, client):
        resp = client.post("/api/analyze", data=json.dumps({"url": "https://paypal.phisher.tk/login"}), content_type="application/json")
        investigation_id = resp.headers.get("X-Investigation-ID")

        response = client.get(f"/api/investigations/{investigation_id}")
        assert response.status_code == 200
        data = response.get_json()
        # Should have all original fields
        assert "indicators" in data
        assert "recommendations" in data
        assert "score_breakdown" in data


class TestInvestigationsPdfEndpoint:
    def test_pdf_generation_success(self, client):
        resp = client.post("/api/analyze", data=json.dumps({"url": "https://paypal.phisher.tk/login"}), content_type="application/json")
        investigation_id = resp.headers.get("X-Investigation-ID")

        response = client.get(f"/api/investigations/{investigation_id}/report.pdf")
        assert response.status_code == 200
        assert response.content_type == "application/pdf"
        assert "attachment" in response.headers.get("Content-Disposition", "")
        assert investigation_id[:8] in response.headers.get("Content-Disposition", "")

    def test_pdf_nonexistent_investigation(self, client):
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/investigations/{fake_id}/report.pdf")
        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Investigation not found"

    def test_pdf_invalid_id_format(self, client):
        response = client.get("/api/investigations/not-a-uuid/report.pdf")
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "Invalid investigation ID format"

    def test_pdf_content_not_empty(self, client):
        resp = client.post("/api/analyze", data=json.dumps({"url": "https://paypal.phisher.tk/login"}), content_type="application/json")
        investigation_id = resp.headers.get("X-Investigation-ID")

        response = client.get(f"/api/investigations/{investigation_id}/report.pdf")
        assert response.status_code == 200
        assert len(response.data) > 1000  # PDF should have substantial content


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"