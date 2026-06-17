"""
Phishing Analyzer Pro - Vercel Compatible Entry Point
"""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

# ----------------------------
# Safe environment loading
# ----------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_analyzer")

# ----------------------------
# Flask App
# ----------------------------
app = Flask(__name__)
CORS(app)

# ----------------------------
# Import Blueprint (SAFE)
# IMPORTANT: no "api." prefix on Vercel
# ----------------------------
try:
    from routes.analyze import analyze_bp
    app.register_blueprint(analyze_bp, url_prefix="/api")
except Exception as e:
    logger.error(f"Failed to load blueprint: {e}")

# ----------------------------
# Health Check Route
# ----------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "Phishing Analyzer Pro is running",
        "version": "1.0.0"
    })

# ----------------------------
# Error Handlers
# ----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ----------------------------
# Vercel Entry Point (IMPORTANT)
# ----------------------------
def handler(environ, start_response):
    return app(environ, start_response)