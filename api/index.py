"""
Phishing Analyzer Pro — Flask Backend Entry Point
Vercel serverless-compatible via WSGI adapter
"""
import os
import sys
import logging
from flask import Flask
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("phishing_analyzer")

app = Flask(__name__)

# CORS handled manually — no flask-cors needed
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-in-prod"),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    AI_TIMEOUT=int(os.getenv("AI_TIMEOUT", "10")),
    AI_API_KEY=os.getenv("OPENAI_API_KEY", ""),
    AI_BASE_URL=os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
    AI_MODEL=os.getenv("AI_MODEL", "gpt-4o-mini"),
    USE_AI=os.getenv("USE_AI", "false").lower() == "true",
)

from routes.analyze import analyze_bp
app.register_blueprint(analyze_bp, url_prefix="/api")

@app.route("/api/health", methods=["GET"])
def health():
    return {"status": "ok", "version": "1.0.0"}

@app.errorhandler(413)
def too_large(e):
    return {"error": "Request too large. Maximum 1MB."}, 413

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Unhandled server error: {e}")
    return {"error": "Internal server error. Please try again."}, 500

@app.errorhandler(404)
def not_found(e):
    return {"error": "Endpoint not found."}, 404

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    logger.info(f"Starting Phishing Analyzer Pro on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)