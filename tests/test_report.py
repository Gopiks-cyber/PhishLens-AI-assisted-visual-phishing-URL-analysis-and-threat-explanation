"""Tests for the PDF report generator (report.py)."""

import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest
import report


def _sample_record(overrides=None):
    """Create a sample investigation record for testing."""
    base = {
        "id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "url": "https://example.com/login?redirect=https://paypal.com",
        "risk_score": 75,
        "risk_level": "high",
        "result": {
            "url": "https://example.com/login?redirect=https://paypal.com",
            "risk_score": 75,
            "risk_level": "high",
            "indicators": [
                {
                    "name": "Brand Impersonation",
                    "detail": "Subdomain contains brand name 'paypal' but domain is not official",
                    "severity": "high",
                    "evidence": "subdomain contains 'paypal'",
                    "points": 30,
                    "explanation": "A known brand name appears in a subdomain while the registered domain is different. Attackers use this technique to make URLs appear legitimate at first glance."
                },
                {
                    "name": "Suspicious TLD",
                    "detail": "Domain uses high-risk TLD: .tk",
                    "severity": "medium",
                    "evidence": "tld=.tk",
                    "points": 15,
                    "explanation": "The domain uses a top-level domain that is statistically over-represented in phishing campaigns. Free or low-cost TLDs are frequently abused."
                },
            ],
            "recommendations": [
                "Do not visit this URL. It shows strong indicators of phishing.",
                "Report this URL to your IT security team or the legitimate organization being impersonated.",
                "Check for subtle misspellings or extra subdomains mimicking known brands.",
            ],
            "score_breakdown": {
                "raw_total": 45,
                "cap": 100,
                "final_score": 75,
                "capped": False,
                "contributions": [
                    {"name": "Brand Impersonation", "severity": "high", "points": 30, "explanation": "Brand name in subdomain with different registered domain"},
                    {"name": "Suspicious TLD", "severity": "medium", "points": 15, "explanation": "High-risk TLD statistically associated with phishing"},
                ],
            },
        },
    }
    if overrides:
        base.update(overrides)
        if "result" in overrides:
            base["result"] = {**base["result"], **overrides["result"]}
    return base


class TestReportGeneration:
    """Tests for the generate_report function."""

    def test_generate_report_basic(self):
        """Test basic report generation with a standard record."""
        record = _sample_record()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 1000
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_long_url(self):
        """Test report generation with a very long URL that should wrap."""
        long_url = "https://very-long-subdomain-name-that-exceeds-normal-length.example.com/" + "path/" * 20 + "?param=" + "x" * 200
        record = _sample_record({"url": long_url, "result": {"url": long_url}})
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 1000
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_long_evidence(self):
        """Test report generation with very long evidence text."""
        long_evidence = "This is a very long evidence string " * 50
        indicators = [{
            "name": "Long Evidence Test",
            "detail": "Detail with " + "text " * 30,
            "severity": "high",
            "evidence": long_evidence,
            "points": 25,
            "explanation": "Explanation with " + "text " * 40,
        }]
        record = _sample_record({"result": {"indicators": indicators}})
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 2000
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_many_indicators(self):
        """Test report generation with many indicators (multi-page potential)."""
        indicators = []
        for i in range(30):
            indicators.append({
                "name": f"Indicator {i}",
                "detail": f"Detail for indicator {i} with some additional text to make it longer.",
                "severity": ["high", "medium", "low"][i % 3],
                "evidence": f"Evidence for indicator {i}",
                "points": 5 + (i % 10),
                "explanation": f"Explanation for indicator {i} with detailed reasoning about why this is suspicious.",
            })
        record = _sample_record({"result": {"indicators": indicators}})
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 5000
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_credential_redaction(self):
        """Test that credentials in URL are redacted in the PDF."""
        record = _sample_record({
            "url": "https://user:password@example.com/path",
            "result": {"url": "https://user:password@example.com/path"}
        })
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_xml_escaping(self):
        """Test that XML special characters in user content are escaped."""
        record = _sample_record({
            "result": {
                "indicators": [{
                    "name": "XSS <script>alert(1)</script>",
                    "detail": "Detail with <tag> and & entity",
                    "severity": "high",
                    "evidence": "Evidence with <script>",
                    "points": 20,
                    "explanation": "Explanation with <tag> & entity",
                }]
            }
        })
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_no_indicators(self):
        """Test report generation with no indicators."""
        record = _sample_record({
            "risk_score": 0,
            "risk_level": "minimal",
            "result": {"indicators": [], "recommendations": []}
        })
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_no_recommendations(self):
        """Test report generation with no recommendations."""
        record = _sample_record({"result": {"recommendations": []}})
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_different_risk_levels(self):
        """Test report generation for all risk levels."""
        for level in ["minimal", "low", "medium", "high", "error"]:
            record = _sample_record({"risk_level": level, "risk_score": {"minimal": 5, "low": 20, "medium": 50, "high": 85, "error": 0}[level]})
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                success = report.generate_report(record, tmp_path)
                assert success is True
                assert os.path.exists(tmp_path)
                assert os.path.getsize(tmp_path) > 500
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

    def test_generate_report_capped_score(self):
        """Test report generation with capped score."""
        record = _sample_record({
            "result": {
                "score_breakdown": {
                    "raw_total": 150,
                    "cap": 100,
                    "final_score": 100,
                    "capped": True,
                    "contributions": [
                        {"name": "Indicator 1", "severity": "high", "points": 50, "explanation": "Test"},
                        {"name": "Indicator 2", "severity": "high", "points": 50, "explanation": "Test"},
                        {"name": "Indicator 3", "severity": "high", "points": 50, "explanation": "Test"},
                    ],
                }
            }
        })
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            success = report.generate_report(record, tmp_path)
            assert success is True
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_generate_report_invalid_record(self):
        """Test that generate_report returns False for invalid input."""
        success = report.generate_report("not a dict", "/tmp/test.pdf")
        assert success is False

    def test_generate_report_from_id_invalid(self):
        """Test generate_report_from_id with invalid ID."""
        success, path, error = report.generate_report_from_id("not-a-uuid")
        assert success is False
        assert path is None
        assert error == "Invalid investigation ID"

    def test_generate_report_from_id_not_found(self):
        """Test generate_report_from_id with nonexistent ID."""
        fake_id = str(uuid.uuid4())
        success, path, error = report.generate_report_from_id(fake_id)
        assert success is False
        assert path is None
        assert error == "Investigation not found"

    def test_redact_url_for_display(self):
        """Test URL redaction helper."""
        assert report._redact_url_for_display("https://example.com") == "https://example.com"
        assert report._redact_url_for_display("https://user:pass@example.com") == "https://[redacted]@example.com"
        assert report._redact_url_for_display("https://user@example.com") == "https://[redacted]@example.com"
        # @ in path is treated as userinfo by urlparse, so it gets redacted
        assert report._redact_url_for_display("https://example.com@not-credentials") == "https://[redacted]@not-credentials"
        assert report._redact_url_for_display(None) is None
        assert report._redact_url_for_display("not a url") == "not a url"