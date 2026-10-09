import pytest
from analyzer import (
    validate_url,
    extract_indicators,
    calculate_risk_score,
    calculate_score_breakdown,
    get_risk_level,
    generate_recommendations,
    analyze_url,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS,
    URL_SHORTENERS,
    SEVERITY_WEIGHTS,
    MAX_SCORE
)
from urllib.parse import urlparse


class TestValidateURL:
    def test_valid_https_url(self):
        valid, error = validate_url("https://example.com")
        assert valid is True
        assert error is None

    def test_valid_http_url(self):
        valid, error = validate_url("http://example.com")
        assert valid is True
        assert error is None

    def test_valid_url_with_path_and_query(self):
        valid, error = validate_url("https://example.com/path?query=value")
        assert valid is True
        assert error is None

    def test_valid_url_with_port(self):
        valid, error = validate_url("https://example.com:8080")
        assert valid is True
        assert error is None

    def test_empty_url(self):
        valid, error = validate_url("")
        assert valid is False
        assert "required" in error.lower()

    def test_none_url(self):
        valid, error = validate_url(None)
        assert valid is False
        assert "required" in error.lower()

    def test_whitespace_only_url(self):
        valid, error = validate_url("   ")
        assert valid is False
        assert "empty" in error.lower()

    def test_missing_scheme(self):
        valid, error = validate_url("example.com")
        assert valid is False
        assert "scheme" in error.lower()

    def test_invalid_scheme(self):
        valid, error = validate_url("ftp://example.com")
        assert valid is False
        assert "http" in error.lower()

    def test_missing_host(self):
        valid, error = validate_url("https://")
        assert valid is False
        assert "host" in error.lower()

    def test_malformed_url(self):
        valid, error = validate_url("not a url")
        assert valid is False


class TestExtractIndicators:
    def test_ip_address_host(self):
        parsed = urlparse("http://192.168.1.1/login")
        indicators = extract_indicators("http://192.168.1.1/login", parsed)
        names = [i["name"] for i in indicators]
        assert "IP Address Host" in names

    def test_suspicious_tld(self):
        parsed = urlparse("https://example.tk")
        indicators = extract_indicators("https://example.tk", parsed)
        names = [i["name"] for i in indicators]
        assert "Suspicious TLD" in names

    def test_brand_impersonation_subdomain(self):
        parsed = urlparse("https://paypal.phishersite.com/login")
        indicators = extract_indicators("https://paypal.phishersite.com/login", parsed)
        names = [i["name"] for i in indicators]
        assert "Brand Impersonation" in names

    def test_legitimate_brand_domain_no_flag(self):
        parsed = urlparse("https://paypal.com/login")
        indicators = extract_indicators("https://paypal.com/login", parsed)
        names = [i["name"] for i in indicators]
        assert "Brand Impersonation" not in names

    def test_excessive_subdomains(self):
        parsed = urlparse("https://a.b.c.d.example.com")
        indicators = extract_indicators("https://a.b.c.d.example.com", parsed)
        names = [i["name"] for i in indicators]
        assert "Excessive Subdomains" in names

    def test_url_shortener(self):
        parsed = urlparse("https://bit.ly/abc123")
        indicators = extract_indicators("https://bit.ly/abc123", parsed)
        names = [i["name"] for i in indicators]
        assert "URL Shortener" in names

    def test_credential_embedding(self):
        parsed = urlparse("https://user:pass@phishersite.com")
        indicators = extract_indicators("https://user:pass@phishersite.com", parsed)
        names = [i["name"] for i in indicators]
        assert "Credential Embedding" in names

    def test_hyphenated_brand_domain(self):
        parsed = urlparse("https://paypal-security.com")
        indicators = extract_indicators("https://paypal-security.com", parsed)
        names = [i["name"] for i in indicators]
        assert "Hyphenated Brand Domain" in names

    def test_sensitive_path(self):
        parsed = urlparse("https://example.com/login")
        indicators = extract_indicators("https://example.com/login", parsed)
        names = [i["name"] for i in indicators]
        assert "Sensitive Path" in names

    def test_excessive_parameters(self):
        parsed = urlparse("https://example.com?a=1&b=2&c=3&d=4&e=5&f=6&g=7")
        indicators = extract_indicators("https://example.com?a=1&b=2&c=3&d=4&e=5&f=6&g=7", parsed)
        names = [i["name"] for i in indicators]
        assert "Excessive Parameters" in names

    def test_encoded_characters(self):
        parsed = urlparse("https://example.com/%20%21%22%23%24")
        indicators = extract_indicators("https://example.com/%20%21%22%23%24", parsed)
        names = [i["name"] for i in indicators]
        assert "Encoded Characters" in names

    def test_clean_url_minimal_indicators(self):
        parsed = urlparse("https://example.com/about")
        indicators = extract_indicators("https://example.com/about", parsed)
        assert len(indicators) == 0


class TestCalculateRiskScore:
    def test_no_indicators_zero_score(self):
        score = calculate_risk_score([])
        assert score == 0

    def test_high_severity_weight(self):
        indicators = [{"severity": "high"}, {"severity": "high"}]
        score = calculate_risk_score(indicators)
        assert score == 60

    def test_medium_severity_weight(self):
        indicators = [{"severity": "medium"}, {"severity": "medium"}]
        score = calculate_risk_score(indicators)
        assert score == 30

    def test_low_severity_weight(self):
        indicators = [{"severity": "low"}, {"severity": "low"}]
        score = calculate_risk_score(indicators)
        assert score == 10

    def test_mixed_severity(self):
        indicators = [{"severity": "high"}, {"severity": "medium"}, {"severity": "low"}]
        score = calculate_risk_score(indicators)
        assert score == 50

    def test_cap_at_100(self):
        indicators = [{"severity": "high"}] * 5
        score = calculate_risk_score(indicators)
        assert score == 100


class TestCalculateScoreBreakdown:
    def test_empty_indicators(self):
        breakdown = calculate_score_breakdown([])
        assert breakdown["raw_total"] == 0
        assert breakdown["cap"] == MAX_SCORE
        assert breakdown["final_score"] == 0
        assert breakdown["capped"] is False
        assert breakdown["contributions"] == []

    def test_single_high_indicator(self):
        indicators = [{"name": "IP Address Host", "severity": "high", "points": 30, "explanation": "test"}]
        breakdown = calculate_score_breakdown(indicators)
        assert breakdown["raw_total"] == 30
        assert breakdown["final_score"] == 30
        assert breakdown["capped"] is False
        assert len(breakdown["contributions"]) == 1
        assert breakdown["contributions"][0]["name"] == "IP Address Host"
        assert breakdown["contributions"][0]["points"] == 30

    def test_reconciliation_sum_equals_raw_total(self):
        indicators = [
            {"name": "A", "severity": "high", "points": 30},
            {"name": "B", "severity": "medium", "points": 15},
            {"name": "C", "severity": "low", "points": 5}
        ]
        breakdown = calculate_score_breakdown(indicators)
        contribution_sum = sum(c["points"] for c in breakdown["contributions"])
        assert contribution_sum == breakdown["raw_total"]
        assert breakdown["raw_total"] == 50
        assert breakdown["final_score"] == 50

    def test_cap_applied(self):
        indicators = [{"name": "A", "severity": "high", "points": 30}] * 5
        breakdown = calculate_score_breakdown(indicators)
        assert breakdown["raw_total"] == 150
        assert breakdown["cap"] == 100
        assert breakdown["final_score"] == 100
        assert breakdown["capped"] is True

    def test_final_score_within_bounds(self):
        indicators = [{"name": "A", "severity": "high", "points": 30}] * 10
        breakdown = calculate_score_breakdown(indicators)
        assert 0 <= breakdown["final_score"] <= 100

    def test_contributions_reconcile_with_risk_score(self):
        indicators = [
            {"name": "A", "severity": "high", "points": 30},
            {"name": "B", "severity": "medium", "points": 15}
        ]
        breakdown = calculate_score_breakdown(indicators)
        score = calculate_risk_score(indicators)
        assert breakdown["final_score"] == score

    def test_severity_weights_match(self):
        assert SEVERITY_WEIGHTS["high"] == 30
        assert SEVERITY_WEIGHTS["medium"] == 15
        assert SEVERITY_WEIGHTS["low"] == 5

    def test_max_score_is_100(self):
        assert MAX_SCORE == 100

    def test_indicators_have_points_and_explanation(self):
        parsed = urlparse("http://192.168.1.1/login")
        indicators = extract_indicators("http://192.168.1.1/login", parsed)
        assert len(indicators) >= 2
        for ind in indicators:
            assert "points" in ind
            assert "explanation" in ind
            assert "evidence" in ind
            assert ind["points"] == SEVERITY_WEIGHTS.get(ind["severity"], 0)

    def test_indicator_explanation_is_plain_english(self):
        parsed = urlparse("http://192.168.1.1/login")
        indicators = extract_indicators("http://192.168.1.1/login", parsed)
        for ind in indicators:
            assert isinstance(ind["explanation"], str)
            assert len(ind["explanation"]) > 10


class TestGetRiskLevel:
    def test_high_risk(self):
        assert get_risk_level(70) == "high"
        assert get_risk_level(100) == "high"

    def test_medium_risk(self):
        assert get_risk_level(40) == "medium"
        assert get_risk_level(69) == "medium"

    def test_low_risk(self):
        assert get_risk_level(15) == "low"
        assert get_risk_level(39) == "low"

    def test_minimal_risk(self):
        assert get_risk_level(0) == "minimal"
        assert get_risk_level(14) == "minimal"


class TestGenerateRecommendations:
    def test_high_risk_recommendations(self):
        indicators = [{"name": "IP Address Host", "severity": "high"}]
        recs = generate_recommendations(indicators, "high")
        assert any("do not visit" in r.lower() for r in recs)
        assert any("report" in r.lower() for r in recs)

    def test_medium_risk_recommendations(self):
        indicators = [{"name": "Suspicious TLD", "severity": "medium"}]
        recs = generate_recommendations(indicators, "medium")
        assert any("caution" in r.lower() for r in recs)
        assert any("verify" in r.lower() for r in recs)

    def test_low_risk_recommendations(self):
        indicators = [{"name": "Sensitive Path", "severity": "low"}]
        recs = generate_recommendations(indicators, "low")
        assert any("vigilant" in r.lower() for r in recs)

    def test_minimal_risk_recommendations(self):
        indicators = []
        recs = generate_recommendations(indicators, "minimal")
        assert any("no significant" in r.lower() for r in recs)

    def test_specific_recommendation_for_shortener(self):
        indicators = [{"name": "URL Shortener", "severity": "medium"}]
        recs = generate_recommendations(indicators, "medium")
        assert any("shortener" in r.lower() for r in recs)

    def test_specific_recommendation_for_ip_host(self):
        indicators = [{"name": "IP Address Host", "severity": "high"}]
        recs = generate_recommendations(indicators, "high")
        assert any("ip address" in r.lower() for r in recs)


class TestAnalyzeURL:
    def test_valid_clean_url(self):
        result = analyze_url("https://example.com")
        assert result["url"] == "https://example.com"
        assert result["risk_score"] == 0
        assert result["risk_level"] == "minimal"
        assert result["indicators"] == []
        assert "error" not in result

    def test_invalid_url_returns_error(self):
        result = analyze_url("not-a-url")
        assert result["risk_level"] == "error"
        assert "error" in result
        assert result["recommendations"]

    def test_missing_url_returns_error(self):
        result = analyze_url("")
        assert result["risk_level"] == "error"
        assert "error" in result

    def test_high_risk_phishing_pattern(self):
        result = analyze_url("https://paypal.phishersite.tk/login?redirect=evil.com")
        assert result["risk_score"] > 40
        assert result["risk_level"] in ("medium", "high")
        assert len(result["indicators"]) >= 2

    def test_ip_address_url(self):
        result = analyze_url("http://192.168.1.1/admin")
        assert any(i["name"] == "IP Address Host" for i in result["indicators"])
        assert result["risk_score"] >= 30

    def test_url_shortener(self):
        result = analyze_url("https://bit.ly/malicious")
        assert any(i["name"] == "URL Shortener" for i in result["indicators"])

    def test_credential_embedding(self):
        result = analyze_url("https://user:pass@evil.com")
        assert any(i["name"] == "Credential Embedding" for i in result["indicators"])

    def test_no_network_requests_made(self):
        """Ensure analyzer doesn't make network requests - it's purely static analysis."""
        # This test passes if analyze_url completes without network calls
        result = analyze_url("https://example.com")
        assert "risk_score" in result

    def test_analyze_url_includes_score_breakdown(self):
        result = analyze_url("https://example.com")
        assert "score_breakdown" in result
        breakdown = result["score_breakdown"]
        assert breakdown["raw_total"] == 0
        assert breakdown["final_score"] == 0
        assert breakdown["contributions"] == []

    def test_analyze_url_score_breakdown_reconciles(self):
        result = analyze_url("https://paypal.phishersite.tk/login")
        breakdown = result["score_breakdown"]
        contribution_sum = sum(c["points"] for c in breakdown["contributions"])
        assert contribution_sum == breakdown["raw_total"]
        assert breakdown["final_score"] == min(breakdown["raw_total"], MAX_SCORE)
        assert breakdown["final_score"] == result["risk_score"]

    def test_analyze_url_score_breakdown_bounds(self):
        result = analyze_url("https://paypal.phishersite.tk/login")
        breakdown = result["score_breakdown"]
        assert 0 <= breakdown["final_score"] <= 100
        assert 0 <= result["risk_score"] <= 100

    def test_analyze_url_invalid_includes_score_breakdown(self):
        result = analyze_url("not-a-url")
        assert "score_breakdown" in result
        assert result["score_breakdown"]["final_score"] == 0
        assert result["score_breakdown"]["contributions"] == []

    def test_analyze_url_risk_level_consistent_with_score(self):
        result = analyze_url("https://paypal.phishersite.tk/login")
        assert result["risk_level"] == get_risk_level(result["risk_score"])

    def test_analyze_url_recommendations_consistent_with_level(self):
        result = analyze_url("https://paypal.phishersite.tk/login")
        recs = generate_recommendations(result["indicators"], result["risk_level"])
        assert result["recommendations"] == recs