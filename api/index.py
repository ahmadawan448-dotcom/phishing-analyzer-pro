import os
import sys
import logging
from flask import Flask
from flask_cors import CORS

# local env only
if os.getenv("VERCEL") is None:
    from dotenv import load_dotenv
    load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("phishing_analyzer")

app = Flask(__name__)
CORS(app, origins=os.getenv("ALLOWED_ORIGINS", "*"))

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-in-prod"),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    AI_TIMEOUT=int(os.getenv("AI_TIMEOUT") or 10),
    AI_API_KEY=os.getenv("OPENAI_API_KEY", ""),
    AI_BASE_URL=os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
    AI_MODEL=os.getenv("AI_MODEL", "gpt-4o-mini"),
    USE_AI=os.getenv("USE_AI", "false").lower() == "true",
)

from api.routes.analyze import analyze_bp
app.register_blueprint(analyze_bp, url_prefix="/api")


@app.route("/api/health", methods=["GET"])
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Unhandled error: {e}")
    return {"error": "Internal server error"}, 500


# Vercel entry point
def handler(environ, start_response):
    return app(environ, start_response)