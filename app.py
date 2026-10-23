"""
SecurePass — Flask Application Server
=====================================
Provides REST API endpoints for password security analysis and breach checking:
- GET  /api/health       -> System status and health check
- POST /api/analyze      -> Heuristic password strength analysis
- GET  /api/breach-check -> HIBP range API proxy for k-Anonymity checks
- GET  /                 -> Serves the SecurePass dashboard UI
"""

import logging
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from breach_checker import (
    BreachCheckerError,
    InvalidPrefixError,
    check_breach_prefix,
    validate_prefix,
)
from strength_engine import analyze_password

# Configure logging: deliberately omit passwords, prefixes, and sensitive payloads
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecurePass")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False


@app.after_request
def set_security_headers(response):
    """Set security, anti-caching, and CORS headers on all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Allow local development and standalone previewers to communicate with backend
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    
    # Modern Content Security Policy allowing Google Fonts and local assets
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' http://127.0.0.1:5000 http://localhost:5000;"
    )
    response.headers["Content-Security-Policy"] = csp

    # Disable caching on API routes to avoid exposing user queries in browser cache
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


@app.errorhandler(BreachCheckerError)
def handle_breach_checker_error(error: BreachCheckerError):
    """Handle domain-specific breach checking exceptions."""
    return jsonify({
        "error": {
            "code": error.code,
            "message": error.message
        }
    }), error.status_code


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException):
    """Handle standard HTTP exceptions with consistent JSON response."""
    return jsonify({
        "error": {
            "code": error.name.upper().replace(" ", "_"),
            "message": error.description
        }
    }), error.code


@app.errorhandler(Exception)
def handle_generic_exception(error: Exception):
    """Catch-all error handler that prevents leaking server stack traces."""
    logger.error("Unhandled internal server exception: %s", type(error).__name__)
    return jsonify({
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected server error occurred."
        }
    }), 500


@app.route("/")
@app.route("/index.html")
def index():
    """Serve the primary SecurePass single-page dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET", "OPTIONS"])
def health_check():
    """Health check endpoint to verify backend availability."""
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "status": "ok",
        "service": "SecurePass API",
        "version": "1.0.0"
    }), 200


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    """
    Analyze password strength and return score, rating, checklist, and suggestions.
    Body JSON: {"password": "<string>"}
    """
    if request.method == "OPTIONS":
        return "", 204

    if not request.is_json:
        return jsonify({
            "error": {
                "code": "INVALID_CONTENT_TYPE",
                "message": "Request body must be valid application/json."
            }
        }), 400

    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify({
            "error": {
                "code": "INVALID_JSON",
                "message": "Malformed or invalid JSON payload."
            }
        }), 400

    if "password" not in data:
        return jsonify({
            "error": {
                "code": "MISSING_FIELD",
                "message": "The 'password' field is required."
            }
        }), 400

    password = data["password"]
    if not isinstance(password, str):
        return jsonify({
            "error": {
                "code": "INVALID_PASSWORD_TYPE",
                "message": "The 'password' field must be a string."
            }
        }), 400

    # Execute analysis — never logs or stores password
    analysis = analyze_password(password)
    return jsonify(analysis), 200


@app.route("/api/breach-check", methods=["GET", "OPTIONS"])
def breach_check():
    """
    Proxy the 5-character SHA-1 prefix to the HIBP range API.
    Query param: ?prefix=ABCDE
    """
    if request.method == "OPTIONS":
        return "", 204
    prefix = request.args.get("prefix", "").strip()

    if not prefix:
        return jsonify({
            "error": {
                "code": "MISSING_PREFIX",
                "message": "Query parameter 'prefix' is required."
            }
        }), 400

    try:
        validated_prefix = validate_prefix(prefix)
    except InvalidPrefixError as e:
        return jsonify({
            "error": {
                "code": e.code,
                "message": e.message
            }
        }), e.status_code

    demo = request.args.get("demo", "").strip().lower() in ("1", "true", "yes")
    result = check_breach_prefix(validated_prefix, demo_mode=demo)
    return jsonify(result), 200


if __name__ == "__main__":
    logger.info("Starting SecurePass server on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
