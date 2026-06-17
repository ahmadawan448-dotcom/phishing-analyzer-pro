"""
Phishing Analyzer Pro — Single File Vercel Deployment
All code in one file to avoid import path issues on Vercel serverless.
"""
import os
import sys
import re
import json
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("phishing_analyzer")

app = Flask(__name__)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret"),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    AI_TIMEOUT=int(os.getenv("AI_TIMEOUT", "10")),
    AI_API_KEY=os.getenv("OPENAI_API_KEY", ""),
    AI_BASE_URL=os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
    AI_MODEL=os.getenv("AI_MODEL", "gpt-4o-mini"),
    USE_AI=os.getenv("USE_AI", "false").lower() == "true",
)

# ============================================================
# RULES ENGINE
# ============================================================

@dataclass
class RuleMatch:
    rule_id: str
    label: str
    severity: int
    detail: str
    category: str

@dataclass
class RuleEngineResult:
    rule_score: int
    matches: List[RuleMatch] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)

PHISHING_KEYWORDS = {
    "critical": [
        r"\bverify\s+your\s+account\b",
        r"\bconfirm\s+your\s+password\b",
        r"\benter\s+your\s+(credit\s+card|bank\s+details|ssn|social\s+security)\b",
        r"\bwe\s+detected\s+suspicious\s+activity\b",
        r"\baccount\s+(suspended|locked|compromised|hacked)\b",
        r"\byour\s+account\s+will\s+be\s+(closed|deleted|terminated)\b",
        r"\bpayment\s+(declined|failed|rejected)\b",
        r"\bunauthorized\s+(login|access|transaction)\b",
    ],
    "high": [
        r"\bclick\s+(here|now|below|the\s+link)\s+to\s+(verify|confirm|update|reset)\b",
        r"\bupdate\s+your\s+(billing|payment|account)\s+information\b",
        r"\byou\s+(have\s+won|are\s+selected|are\s+a\s+winner)\b",
        r"\bclaim\s+your\s+(prize|reward|winnings)\b",
        r"\bOTP\b|\bone.time\s+password\b",
        r"\bfree\s+(gift|offer|prize|money|cash)\b",
        r"\blimited\s+time\s+offer\b",
        r"\bact\s+(now|immediately|fast|quickly)\b",
        r"\b(urgent|immediate)\s+(action\s+required|response\s+needed)\b",
    ],
    "medium": [
        r"\bpassword\s+expired\b",
        r"\bverification\s+(required|needed|pending)\b",
        r"\bsecurity\s+alert\b",
        r"\bunusual\s+(activity|sign.?in)\b",
        r"\bconfirm\s+(your\s+)?(identity|email|account)\b",
        r"\bplease\s+(verify|confirm|update)\b",
        r"\bsuspicious\s+(activity|login|transaction)\b",
    ],
    "low": [
        r"\bclick\s+here\b",
        r"\bspecial\s+offer\b",
        r"\bcongratulations\b",
        r"\bguaranteed\b",
    ],
}

URGENCY_PATTERNS = [
    (r"\b(within|in)\s+\d+\s+(hours?|minutes?|days?)\b", 3, "time-pressure deadline"),
    (r"\bexpires?\s+(today|tomorrow|soon|shortly)\b", 3, "expiry urgency"),
    (r"\blast\s+(chance|opportunity|warning|notice)\b", 3, "last-chance pressure"),
    (r"\bimmediate(ly)?\b", 2, "immediate demand"),
    (r"\burgent(ly)?\b", 2, "urgency marker"),
    (r"\bdeadline\b", 1, "deadline mention"),
]

CREDENTIAL_PATTERNS = [
    (r"\benter\s+(your\s+)?(password|pin|passcode)\b", 4, "Direct password request"),
    (r"\bsend\s+(your\s+)?(password|credentials|login)\b", 4, "Credential exfiltration attempt"),
    (r"\bfull\s+(card\s+)?(number|cvv|cvc|expiry)\b", 4, "Payment credential request"),
    (r"\bbank\s+(account|routing)\s+number\b", 4, "Banking credential request"),
    (r"\busername\s+and\s+password\b", 3, "Combined credential request"),
]

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

COMPILED_KW = {
    sev: [re.compile(p, re.IGNORECASE) for p in pats]
    for sev, pats in PHISHING_KEYWORDS.items()
}
COMPILED_URG = [(re.compile(p, re.IGNORECASE), s, l) for p, s, l in URGENCY_PATTERNS]
COMPILED_CRED = [(re.compile(p, re.IGNORECASE), s, l) for p, s, l in CREDENTIAL_PATTERNS]


def analyze_email(email_body: str, sender: str = "", subject: str = "") -> RuleEngineResult:
    full_text = f"{subject}\n{sender}\n{email_body}"
    matches, raw_score = [], 0

    for sev, patterns in COMPILED_KW.items():
        for pat in patterns:
            m = pat.search(full_text)
            if m:
                raw_score += SEVERITY_WEIGHTS[sev]
                matches.append(RuleMatch(
                    rule_id=f"KW_{sev.upper()}_{len(matches)}",
                    label=f"Phishing keyword ({sev})",
                    severity={"critical":4,"high":3,"medium":2,"low":1}[sev],
                    detail=f'Matched: "{m.group()[:60]}"',
                    category="keyword"))

    for pat, sev, label in COMPILED_URG:
        m = pat.search(full_text)
        if m:
            raw_score += sev * 5
            matches.append(RuleMatch(f"URG_{len(matches)}", f"Urgency: {label}", sev,
                                     f'"{m.group()[:60]}"', "urgency"))

    urls = re.findall(r'https?://[^\s<>"\']+', email_body, re.IGNORECASE)
    for url in urls:
        if url.startswith("http://"):
            raw_score += 24
            matches.append(RuleMatch("URL_HTTP", "Insecure HTTP link", 4, f"URL: {url[:80]}", "url"))
        if re.search(r"\.(xyz|tk|ml|ga|cf|gq|top|club|work|click)(/|$)", url, re.IGNORECASE):
            raw_score += 18
            matches.append(RuleMatch("URL_TLD", "High-risk TLD in link", 3, f"URL: {url[:80]}", "url"))

    for pat, sev, label in COMPILED_CRED:
        if pat.search(full_text):
            raw_score += sev * 7
            matches.append(RuleMatch(f"CRED_{len(matches)}", label, sev,
                                     "Credential collection attempt", "credential"))

    if sender:
        if re.search(r"@.*\.(xyz|tk|ml|ga|cf|gq|top|club|work)", sender, re.IGNORECASE):
            raw_score += 24
            matches.append(RuleMatch("SPOOF_TLD", "Sender uses suspicious TLD", 3,
                                     f"Sender: {sender[:100]}", "spoofing"))
        brands = ["paypal","amazon","apple","microsoft","google","facebook","netflix","irs"]
        for brand in brands:
            if brand in sender.lower() and f"@{brand}.com" not in sender.lower():
                raw_score += 32
                matches.append(RuleMatch("SPOOF_BRAND", f"Brand spoofing: {brand}", 4,
                                         f"Sender: {sender[:100]}", "spoofing"))
                break

    seen, unique = set(), []
    for m in matches:
        key = (m.category, m.severity)
        if key not in seen:
            seen.add(key)
            unique.append(m)

    return RuleEngineResult(rule_score=min(100, raw_score), matches=unique,
                            signals=list({m.label for m in unique}))


def analyze_url(url: str) -> RuleEngineResult:
    matches, raw_score = [], 0
    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    except Exception:
        return RuleEngineResult(rule_score=50, signals=["URL could not be parsed"])

    netloc = parsed.netloc or ""

    if parsed.scheme == "http":
        raw_score += 30
        matches.append(RuleMatch("URL_HTTP", "Insecure HTTP protocol", 4,
                                 "No TLS encryption", "security"))
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc):
        raw_score += 35
        matches.append(RuleMatch("URL_IP", "Raw IP address as domain", 4,
                                 "Legitimate services use domain names", "structure"))
    tld = re.search(r"\.(xyz|tk|ml|ga|cf|gq|top|club|work|click|download|stream)$",
                    netloc, re.IGNORECASE)
    if tld:
        raw_score += 25
        matches.append(RuleMatch("URL_TLD", f"High-risk TLD: .{tld.group(1)}", 3,
                                 "Free TLDs abused by phishing campaigns", "tld"))
    brands = ["paypal","amazon","apple","microsoft","google","facebook","netflix","bank","chase"]
    for brand in brands:
        if brand in netloc.lower():
            parts = netloc.lower().split(".")
            if not any(p == f"{brand}.com" for p in [".".join(parts[-2:])]):
                raw_score += 30
                matches.append(RuleMatch("URL_BRAND", f"Brand spoofing: {brand}", 3,
                                         f"'{brand}' in domain but not official site", "spoofing"))
                break
    if any(s in netloc.lower() for s in ["bit.ly","tinyurl.com","t.co","goo.gl"]):
        raw_score += 15
        matches.append(RuleMatch("URL_SHORT", "URL shortener detected", 2,
                                 "True destination is hidden", "obfuscation"))
    if "@" in url:
        raw_score += 25
        matches.append(RuleMatch("URL_AT", "@ character in URL", 4,
                                 "Classic phishing redirect trick", "deception"))
    if len(netloc) > 40:
        raw_score += 10
        matches.append(RuleMatch("URL_LONG", "Unusually long domain", 2,
                                 f"Domain length: {len(netloc)} chars", "structure"))

    return RuleEngineResult(rule_score=min(100, raw_score), matches=matches,
                            signals=[m.label for m in matches])


def analyze_headers(raw_headers: str) -> RuleEngineResult:
    matches, raw_score = [], 0
    header_map = {}
    for line in raw_headers.strip().split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            header_map[k.strip().lower()] = v.strip()

    spf = header_map.get("received-spf", "")
    auth = header_map.get("authentication-results", "")

    if "fail" in spf.lower():
        raw_score += 35
        matches.append(RuleMatch("SPF_FAIL", "SPF authentication failed", 4,
                                 "Server not authorized for this domain", "authentication"))
    elif "softfail" in spf.lower():
        raw_score += 20
        matches.append(RuleMatch("SPF_SOFT", "SPF soft fail", 3,
                                 "Possible spoofing", "authentication"))
    elif "pass" not in spf.lower() and "pass" not in auth.lower():
        raw_score += 10
        matches.append(RuleMatch("SPF_NONE", "No SPF result", 2,
                                 "Authentication unconfirmed", "authentication"))

    if "dkim=fail" in auth.lower():
        raw_score += 30
        matches.append(RuleMatch("DKIM_FAIL", "DKIM signature failed", 4,
                                 "Email may have been tampered with", "authentication"))
    if "dmarc=fail" in auth.lower():
        raw_score += 35
        matches.append(RuleMatch("DMARC_FAIL", "DMARC policy failed", 4,
                                 "Domain policy explicitly rejects this email", "authentication"))

    from_h = header_map.get("from", "")
    reply = header_map.get("reply-to", "")
    if reply and from_h:
        fd = re.search(r"@([\w\.-]+)", from_h)
        rd = re.search(r"@([\w\.-]+)", reply)
        if fd and rd and fd.group(1) != rd.group(1):
            raw_score += 25
            matches.append(RuleMatch("REPLYTO", "Reply-To differs from From domain", 3,
                                     f"From: {fd.group(1)} → Reply-To: {rd.group(1)}", "deception"))

    xm = header_map.get("x-mailer", "")
    if re.search(r"(phpmailer|bulk|mass|blast)", xm, re.IGNORECASE):
        raw_score += 15
        matches.append(RuleMatch("MAILER", "Suspicious mail client", 2,
                                 f"X-Mailer: {xm[:60]}", "infrastructure"))

    return RuleEngineResult(rule_score=min(100, raw_score), matches=matches,
                            signals=[m.label for m in matches])


# ============================================================
# SCORING
# ============================================================

def compute_final_score(rule_score: int, ai_score: Optional[int]) -> int:
    if ai_score is None:
        return rule_score
    blended = int(rule_score * 0.55 + ai_score * 0.45)
    if rule_score >= 70 and ai_score >= 70:
        blended = max(blended, max(rule_score, ai_score) - 5)
    return min(100, blended)


def score_to_verdict(score: int):
    if score < 15:  return "SAFE", "high"
    if score < 30:  return "LOW", "high"
    if score < 55:  return "MEDIUM", "medium"
    if score < 75:  return "HIGH", "medium"
    return "CRITICAL", "high"


def build_indicators(matches) -> List[dict]:
    icons = {"keyword":"🔤","urgency":"⏰","url":"🔗","credential":"🔑",
             "spoofing":"🎭","deception":"🎭","authentication":"🛡️",
             "infrastructure":"🏗️","security":"🔒","structure":"🏗️",
             "tld":"🌐","obfuscation":"👁️"}
    sevlabels = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW"}
    result = []
    for m in matches:
        result.append({
            "icon": icons.get(m.category, "⚠️"),
            "severity": sevlabels.get(m.severity, "LOW"),
            "severity_num": m.severity,
            "label": m.label,
            "detail": m.detail,
            "category": m.category,
        })
    result.sort(key=lambda x: x["severity_num"], reverse=True)
    return result


def generate_explanation(verdict, score, signals, analysis_type):
    labels = {"email":"email","url":"URL","headers":"email headers"}
    lbl = labels.get(analysis_type, "content")
    sigs = ", ".join(signals[:4]) if signals else "suspicious patterns"
    if verdict == "SAFE":
        return f"This {lbl} appears legitimate. No significant phishing indicators detected. Risk score: {score}/100."
    elif verdict == "LOW":
        return f"This {lbl} has minor concerns (score: {score}/100). Detected: {sigs}. Proceed with caution."
    elif verdict == "MEDIUM":
        return f"This {lbl} exhibits moderate phishing indicators (score: {score}/100). Detected: {sigs}. Do not click links without verifying the sender."
    elif verdict == "HIGH":
        return f"HIGH RISK — This {lbl} shows strong phishing characteristics (score: {score}/100). Detected: {sigs}. Do NOT interact with this content."
    else:
        return f"⚠️ CRITICAL THREAT — This {lbl} is almost certainly malicious (score: {score}/100). Detected: {sigs}. Quarantine immediately and report to your security team."


# ============================================================
# AI MOCK
# ============================================================

def mock_ai(rule_score: int, analysis_type: str):
    time.sleep(0.2)
    if rule_score < 20:
        return {"score": 12, "signals": ["No suspicious patterns detected", "Sender appears legitimate"]}
    elif rule_score < 55:
        return {"score": 48, "signals": ["Moderate urgency language", "Verify sender independently"]}
    else:
        return {"score": 82, "signals": ["Classic phishing pattern", "Social engineering detected", "Credential harvesting attempt"]}


# ============================================================
# ROUTES
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/examples", methods=["GET"])
def examples():
    return jsonify({
        "email": {
            "type": "email",
            "subject": "⚠️ Urgent: Your Account Will Be Suspended",
            "sender": "security-noreply@paypa1-accounts.xyz",
            "body": "Dear Valued Customer,\n\nWe detected suspicious activity on your PayPal account. Your account will be permanently suspended within 24 hours unless you verify your information immediately.\n\nClick here to verify your account now: http://paypal-secure-verify.xyz/login\n\nPlease provide your full name, password, and credit card number to restore access.\n\nAct NOW — this is your last warning!\n\nPayPal Security Team",
        },
        "url": {
            "type": "url",
            "url": "http://paypa1-secure-login.xyz/verify?user=account&action=restore",
        },
        "headers": {
            "type": "headers",
            "headers": "Received: from mail.paypa1-spoof.xyz (unknown [185.220.101.42])\nReceived-SPF: fail (domain of paypal.com does not designate 185.220.101.42 as permitted sender)\nAuthentication-Results: mx.google.com;\n   dkim=fail header.i=@paypal.com;\n   dmarc=fail (p=REJECT sp=REJECT) header.from=paypal.com;\nFrom: PayPal Security <security@paypal.com>\nReply-To: support-noreply@paypa1-accounts.xyz\nSubject: URGENT: Account Suspended\nX-Mailer: PHPMailer 6.0.0",
        },
    })


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return "", 204

    if not request.is_json:
        return jsonify({"error": "Request must be JSON", "success": False}), 400

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body", "success": False}), 400

    analysis_type = data.get("type", "").strip().lower()
    if analysis_type not in ("email", "url", "headers"):
        return jsonify({"error": "'type' must be: email, url, or headers", "success": False}), 400

    try:
        start = time.time()

        if analysis_type == "email":
            body = (data.get("body") or "").strip()
            if not body:
                return jsonify({"error": "'body' is required", "success": False}), 400
            sender = (data.get("sender") or "").strip()[:500]
            subject = (data.get("subject") or "").strip()[:500]
            rule_result = analyze_email(body, sender, subject)

        elif analysis_type == "url":
            url = (data.get("url") or "").strip()
            if not url:
                return jsonify({"error": "'url' is required", "success": False}), 400
            rule_result = analyze_url(url)

        else:
            headers = (data.get("headers") or "").strip()
            if not headers:
                return jsonify({"error": "'headers' is required", "success": False}), 400
            rule_result = analyze_headers(headers)

        ai = mock_ai(rule_result.rule_score, analysis_type)
        ai_score = ai["score"]
        final_score = compute_final_score(rule_result.rule_score, ai_score)
        verdict, confidence = score_to_verdict(final_score)
        all_signals = list(set(rule_result.signals + ai["signals"]))
        explanation = generate_explanation(verdict, final_score, all_signals, analysis_type)
        indicators = build_indicators(rule_result.matches)
        elapsed = round((time.time() - start) * 1000)

        return jsonify({
            "success": True,
            "data": {
                "score": final_score,
                "verdict": verdict,
                "confidence": confidence,
                "rule_score": rule_result.rule_score,
                "ai_score": ai_score,
                "signals": all_signals[:10],
                "explanation": explanation,
                "indicators": indicators[:12],
                "analysis_type": analysis_type,
                "elapsed_ms": elapsed,
            }
        })

    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        return jsonify({"error": "Analysis failed. Please try again.", "success": False}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port,
            debug=os.getenv("FLASK_ENV") == "development")