from flask import Flask, request, jsonify, render_template
from analyzer import analyze_url

app = Flask(__name__)
@app.route("/")
def index():
    """Serve the PhishLens frontend."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Analyze a URL for phishing indicators."""
    if not request.is_json:
        return jsonify({
            "url": "",
            "risk_score": 0,
            "risk_level": "error",
            "indicators": [],
            "recommendations": ["Request must be JSON with Content-Type: application/json"],
            "error": "Invalid content type"
        }), 400
    
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "url": "",
            "risk_score": 0,
            "risk_level": "error",
            "indicators": [],
            "recommendations": ["Request body must be valid JSON"],
            "error": "Invalid JSON"
        }), 400
    
    url = data.get("url", "")
    result = analyze_url(url)
    
    status_code = 400 if "error" in result else 200
    return jsonify(result), status_code


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)