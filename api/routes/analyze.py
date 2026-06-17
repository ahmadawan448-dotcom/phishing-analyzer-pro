"""
API Routes — /api/analyze endpoint with full input validation.
"""
import logging
import re
from flask import Blueprint, request, jsonify
from api.services.analyzer import run_email_analysis, run_url_analysis, run_header_analysis

logger = logging.getLogger("phishing_analyzer.routes")
analyze_bp = Blueprint("analyze", __name__)

MAX_EMAIL_LEN = 50_000
MAX_URL_LEN = 2_083
MAX_HEADER_LEN = 20_000


def _error(msg: str, code: int = 400):
    return jsonify({"error": msg, "success": False}), code


def _validate_str(value, name: str, max_len: int, required: bool = True):
    if required and not value:
        return f"'{name}' is required and cannot be empty."
    if value and len(value) > max_len:
        return f"'{name}' exceeds maximum length of {max_len:,} characters."
    return None


@analyze_bp.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return "", 204

    if not request.is_json:
        return _error("Request must be JSON with Content-Type: application/json")

    try:
        data = request.get_json(force=False, silent=True)
    except Exception:
        return _error("Invalid JSON body.")

    if not data or not isinstance(data, dict):
        return _error("Request body must be a JSON object.")

    analysis_type = data.get("type", "").strip().lower()
    if analysis_type not in ("email", "url", "headers"):
        return _error("'type' must be one of: email, url, headers")

    try:
        if analysis_type == "email":
            body = (data.get("body") or data.get("content") or "").strip()
            sender = (data.get("sender") or data.get("from") or "").strip()[:500]
            subject = (data.get("subject") or "").strip()[:500]
            err = _validate_str(body, "body", MAX_EMAIL_LEN, required=True)
            if err:
                return _error(err)
            result = run_email_analysis(body=body, sender=sender, subject=subject)

        elif analysis_type == "url":
            url = (data.get("url") or data.get("content") or "").strip()
            err = _validate_str(url, "url", MAX_URL_LEN, required=True)
            if err:
                return _error(err)
            if not re.match(r"^(https?://|ftp://|www\.)\S+", url, re.IGNORECASE):
                if "." not in url:
                    return _error("'url' does not appear to be a valid URL.")
            result = run_url_analysis(url=url)

        else:
            headers = (data.get("headers") or data.get("content") or "").strip()
            err = _validate_str(headers, "headers", MAX_HEADER_LEN, required=True)
            if err:
                return _error(err)
            if "\n" not in headers or ":" not in headers:
                return _error("'headers' must contain raw email headers (key: value format).")
            result = run_header_analysis(raw_headers=headers)

        return jsonify({"success": True, "data": result})

    except Exception as e:
        logger.error(f"Analysis error ({analysis_type}): {e}", exc_info=True)
        return _error("Analysis failed due to an internal error. Please try again.", 500)


@analyze_bp.route("/examples", methods=["GET"])
def get_examples():
    return jsonify({
        "email": {
            "type": "email",
            "subject": "⚠️ Urgent: Your Account Will Be Suspended",
            "sender": "security-noreply@paypa1-accounts.xyz",
            "body": (
                "Dear Valued Customer,\n\n"
                "We detected suspicious activity on your PayPal account. "
                "Your account will be permanently suspended within 24 hours unless you verify your information immediately.\n\n"
                "Click here to verify your account now: http://paypal-secure-verify.xyz/login\n\n"
                "Please provide your full name, password, and credit card number to restore access.\n\n"
                "Act NOW — this is your last warning!\n\nPayPal Security Team"
            ),
        },
        "url": {
            "type": "url",
            "url": "http://paypa1-secure-login.xyz/verify?user=account&action=restore",
        },
        "headers": {
            "type": "headers",
            "headers": (
                "Received: from mail.paypa1-spoof.xyz (unknown [185.220.101.42])\n"
                "Received-SPF: fail (domain of paypal.com does not designate 185.220.101.42 as permitted sender)\n"
                "Authentication-Results: mx.google.com;\n"
                "   dkim=fail header.i=@paypal.com;\n"
                "   dmarc=fail (p=REJECT sp=REJECT) header.from=paypal.com;\n"
                "From: PayPal Security <security@paypal.com>\n"
                "Reply-To: support-noreply@paypa1-accounts.xyz\n"
                "Subject: URGENT: Account Suspended\n"
                "X-Mailer: PHPMailer 6.0.0\n"
                "Date: Mon, 10 Jun 2024 03:44:00 +0000"
            ),
        },
    })
