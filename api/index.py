"""
Phishing Analyzer Pro - Vercel Stable Production Entry Point
"""

import os
import sys
import logging
from flask import Flask, jsonify
from flask_cors import CORS

# -----------------------------
# SAFE ENV LOADING (Vercel-safe)
# -----------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_analyzer")

# -----------------------------
# Flask App
# -----------------------------
app = Flask(__name__)
CORS(app)

# -----------------------------
# FIX: ensure correct import path
# -----------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from routes.analyze import analyze_bp
    app.register_blueprint(analyze_bp, url_prefix="/api")
except Exception as e:
    logger.error(f"Blueprint load failed: {e}")

# -----------------------------
# HEALTH CHECK (IMPORTANT)
# -----------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "Phishing Analyzer Pro is running",
        "version": "1.0.0"
    })

# -----------------------------
# ERROR HANDLERS
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# -----------------------------
# VERCEL ENTRY POINT (CRITICAL)
# -----------------------------
def handler(environ, start_response):
    return app(environ, start_response)