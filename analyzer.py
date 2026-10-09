from urllib.parse import urlparse
import re


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
    "work", "live", "stream", "racing", "party", "review", "trade", "download",
    "loan", "win", "bid", "accountant", "science", "cricket", "faith", "date"
}

BRAND_KEYWORDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "github", "dropbox", "linkedin", "twitter", "bank", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "santander"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "short.io", "v.gd"
]


def validate_url(url: str) -> tuple[bool, str | None]:
    """Validate URL format. Returns (is_valid, error_message)."""
    if not url or not isinstance(url, str):
        return False, "URL is required"
    
    url = url.strip()
    if not url:
        return False, "URL cannot be empty"
    
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    
    if not parsed.scheme:
        return False, "URL must include a scheme (http:// or https://)"
    
    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https schemes are supported"
    
    if not parsed.netloc:
        return False, "URL must include a host"
    
    return True, None


def extract_indicators(url: str, parsed) -> list[dict]:
    """Extract suspicious indicators from URL."""
    indicators = []
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()
    
    # Check for IP address as host
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, netloc.split(':')[0]):
        indicators.append({
            "name": "IP Address Host",
            "detail": "URL uses an IP address instead of a domain name",
            "severity": "high"
        })
    
    # Check for suspicious TLD
    tld = netloc.split('.')[-1] if '.' in netloc else ''
    if tld in SUSPICIOUS_TLDS:
        indicators.append({
            "name": "Suspicious TLD",
            "detail": f"Domain uses high-risk TLD: .{tld}",
            "severity": "medium"
        })
    
    # Check for brand impersonation in subdomain
    for brand in BRAND_KEYWORDS:
        if brand in netloc and not netloc.endswith(f".{brand}.com") and not netloc == f"{brand}.com":
            # Check if brand appears in subdomain (not main domain)
            parts = netloc.split('.')
            if len(parts) > 2 and any(brand in part for part in parts[:-2]):
                indicators.append({
                    "name": "Brand Impersonation",
                    "detail": f"Subdomain contains brand name '{brand}' but domain is not official",
                    "severity": "high"
                })
                break
    
    # Check for excessive subdomains
    subdomain_count = len(netloc.split('.')) - 2
    if subdomain_count >= 3:
        indicators.append({
            "name": "Excessive Subdomains",
            "detail": f"URL has {subdomain_count} subdomain levels",
            "severity": "medium"
        })
    
    # Check for URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in netloc:
            indicators.append({
                "name": "URL Shortener",
                "detail": f"URL uses known shortening service: {shortener}",
                "severity": "medium"
            })
            break
    
    # Check for @ symbol (credential embedding)
    if '@' in netloc:
        indicators.append({
            "name": "Credential Embedding",
            "detail": "URL contains @ symbol which may embed credentials",
            "severity": "high"
        })
    
    # Check for hyphenated brand-like domains
    for brand in BRAND_KEYWORDS:
        if f"{brand}-" in netloc or f"-{brand}" in netloc:
            indicators.append({
                "name": "Hyphenated Brand Domain",
                "detail": f"Domain contains hyphenated brand name '{brand}'",
                "severity": "medium"
            })
            break
    
    # Check for long random-looking subdomains
    subdomain_part = '.'.join(netloc.split('.')[:-2]) if len(netloc.split('.')) > 2 else ''
    if subdomain_part and len(subdomain_part) > 30 and re.search(r'[a-z0-9]{20,}', subdomain_part):
        indicators.append({
            "name": "Long Random Subdomain",
            "detail": "Subdomain appears to be randomly generated",
            "severity": "low"
        })
    
    # Check for suspicious path patterns
    suspicious_paths = ["login", "signin", "verify", "update", "secure", "account", "confirm"]
    for sus_path in suspicious_paths:
        if f"/{sus_path}" in path or path.startswith(f"/{sus_path}/"):
            indicators.append({
                "name": "Sensitive Path",
                "detail": f"URL path contains sensitive keyword: {sus_path}",
                "severity": "low"
            })
            break
    
    # Check for excessive query parameters
    if query.count('&') > 5:
        indicators.append({
            "name": "Excessive Parameters",
            "detail": "URL contains many query parameters",
            "severity": "low"
        })
    
    # Check for hex/encoded characters in path
    if re.search(r'%[0-9a-fA-F]{2}', path) and path.count('%') > 3:
        indicators.append({
            "name": "Encoded Characters",
            "detail": "URL path contains excessive percent-encoded characters",
            "severity": "low"
        })
    
    # Check for data URIs or javascript
    if parsed.scheme in ("data", "javascript", "vbscript"):
        indicators.append({
            "name": "Dangerous Scheme",
            "detail": f"URL uses potentially dangerous scheme: {parsed.scheme}",
            "severity": "high"
        })
    
    return indicators


def calculate_risk_score(indicators: list[dict]) -> int:
    """Calculate risk score 0-100 based on indicators."""
    severity_weights = {"high": 30, "medium": 15, "low": 5}
    score = sum(severity_weights.get(ind["severity"], 0) for ind in indicators)
    return min(score, 100)


def get_risk_level(score: int) -> str:
    """Convert risk score to risk level."""
    if score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 15:
        return "low"
    return "minimal"


def generate_recommendations(indicators: list[dict], risk_level: str) -> list[str]:
    """Generate actionable recommendations based on findings."""
    recommendations = []
    
    if risk_level == "high":
        recommendations.append("Do not visit this URL. It shows strong indicators of phishing.")
        recommendations.append("Report this URL to your IT security team or the legitimate organization being impersonated.")
    elif risk_level == "medium":
        recommendations.append("Exercise caution. Verify the URL independently before entering any credentials.")
        recommendations.append("Check the official website directly by typing the address manually.")
    elif risk_level == "low":
        recommendations.append("Remain vigilant. Some suspicious patterns were detected.")
        recommendations.append("Ensure the domain matches the expected official website exactly.")
    else:
        recommendations.append("No significant phishing indicators detected.")
        recommendations.append("Always verify the URL in your browser address bar before entering sensitive information.")
    
    # Specific recommendations based on indicators
    indicator_names = {ind["name"] for ind in indicators}
    
    if "IP Address Host" in indicator_names:
        recommendations.append("Legitimate organizations rarely use IP addresses in public links.")
    
    if "URL Shortener" in indicator_names:
        recommendations.append("URL shorteners hide the true destination. Expand the link before clicking.")
    
    if "Brand Impersonation" in indicator_names or "Hyphenated Brand Domain" in indicator_names:
        recommendations.append("Check for subtle misspellings or extra subdomains mimicking known brands.")
    
    if "Credential Embedding" in indicator_names:
        recommendations.append("URLs with @ symbols may attempt to redirect you while showing a familiar domain.")
    
    return recommendations


def analyze_url(url: str) -> dict:
    """Main analysis function. Returns structured analysis result."""
    is_valid, error = validate_url(url)
    if not is_valid:
        return {
            "url": url,
            "risk_score": 0,
            "risk_level": "error",
            "indicators": [],
            "recommendations": [f"Invalid input: {error}"],
            "error": error
        }
    
    parsed = urlparse(url)
    indicators = extract_indicators(url, parsed)
    risk_score = calculate_risk_score(indicators)
    risk_level = get_risk_level(risk_score)
    recommendations = generate_recommendations(indicators, risk_level)
    
    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendations": recommendations
    }