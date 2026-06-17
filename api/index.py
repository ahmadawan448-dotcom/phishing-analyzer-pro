import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "Phishing Analyzer Pro running",
        "version": "1.0.0"
    })

# -------------------------
# TEST ROUTE
# -------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "API is live"})

# IMPORTANT: NO app.run()