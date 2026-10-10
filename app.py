import logging
import tempfile
import os
from flask import Flask, request, jsonify, render_template, send_file
from analyzer import analyze_url
import investigations
import report

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

investigations.init_db()

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
    response = jsonify(result)

    if status_code == 200:
        try:
            investigation_id = investigations.save_investigation(result)
            response.headers["X-Investigation-ID"] = investigation_id
        except Exception as e:
            logger.exception("Failed to persist investigation: %s", e)

    return response, status_code


@app.route("/api/investigations", methods=["GET"])
def list_investigations():
    """List saved investigations with pagination."""
    try:
        limit = request.args.get("limit", investigations.DEFAULT_LIST_LIMIT)
        offset = request.args.get("offset", 0)

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = investigations.DEFAULT_LIST_LIMIT
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            offset = 0

        if limit < 1 or limit > investigations.MAX_LIST_LIMIT:
            return jsonify({
                "error": f"Invalid limit. Must be between 1 and {investigations.MAX_LIST_LIMIT}"
            }), 400
        if offset < 0:
            return jsonify({"error": "Invalid offset. Must be non-negative"}), 400

        result = investigations.list_investigations(limit=limit, offset=offset)
        return jsonify(result), 200
    except Exception as e:
        logger.exception("Failed to list investigations: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/investigations/<investigation_id>", methods=["GET"])
def get_investigation(investigation_id):
    """Get a single investigation by ID."""
    if not investigations.is_valid_id(investigation_id):
        return jsonify({"error": "Invalid investigation ID format"}), 400

    try:
        record = investigations.get_investigation(investigation_id)
        if record is None:
            return jsonify({"error": "Investigation not found"}), 404

        result = record.get("result", {})
        result["investigation_id"] = record["id"]
        result["created_at"] = record["created_at"]

        return jsonify(result), 200
    except Exception as e:
        logger.exception("Failed to get investigation: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/investigations/<investigation_id>/report.pdf", methods=["GET"])
def get_investigation_report(investigation_id):
    """Generate and return a PDF evidence report for an investigation."""
    if not investigations.is_valid_id(investigation_id):
        return jsonify({"error": "Invalid investigation ID format"}), 400

    try:
        record = investigations.get_investigation(investigation_id)
        if record is None:
            return jsonify({"error": "Investigation not found"}), 404

        tmp_path = os.path.join(tempfile.gettempdir(), f"phishlens_{investigation_id[:8]}.pdf")

        success = report.generate_report(record, tmp_path)
        if not success:
            logger.error("PDF generation failed for investigation %s", investigation_id)
            return jsonify({"error": "Failed to generate report"}), 500

        safe_filename = f"phishlens-investigation-{investigation_id[:8]}.pdf"
        return send_file(
            tmp_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=safe_filename
        )
    except Exception as e:
        logger.exception("Failed to generate PDF report: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)