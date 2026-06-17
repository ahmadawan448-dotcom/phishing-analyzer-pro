"""
Core Rule-Based Phishing Detection Engine
Detects patterns, keywords, and structural red flags.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("phishing_analyzer.rules")


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

    def to_dict(self):
        return {
            "rule_score": self.rule_score,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "label": m.label,
                    "severity": m.severity,
                    "detail": m.detail,
                    "category": m.category,
                }
                for m in self.matches
            ],
            "signals": self.signals,
        }


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
        r"\bdo\s+not\s+share\s+this\s+(code|password|pin)\b",
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
        r"\bkyc\s+verification\b",
    ],
    "low": [
        r"\bclick\s+here\b",
        r"\blearn\s+more\b",
        r"\bspecial\s+offer\b",
        r"\bcongratulations\b",
        r"\bexclusive\s+(deal|offer)\b",
        r"\bno\s+cost\b",
        r"\bguaranteed\b",
    ],
}

URGENCY_PATTERNS = [
    (r"\b(within|in)\s+\d+\s+(hours?|minutes?|days?)\b", 3, "time-pressure deadline"),
    (r"\bexpires?\s+(today|tomorrow|soon|shortly)\b", 3, "expiry urgency"),
    (r"\blast\s+(chance|opportunity|warning|notice)\b", 3, "last-chance pressure"),
    (r"\bdo\s+not\s+(ignore|delay|wait)\b", 2, "urgency command"),
    (r"\bimmediate(ly)?\b", 2, "immediate demand"),
    (r"\burgent(ly)?\b", 2, "urgency marker"),
    (r"\bASAP\b", 2, "urgency slang"),
    (r"\bdeadline\b", 1, "deadline mention"),
]

SUSPICIOUS_URL_PATTERNS = [
    (r"http://(?!localhost)", 4, "Insecure HTTP link detected"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 4, "Raw IP address used as domain"),
    (r"(paypal|amazon|apple|microsoft|google|facebook|netflix|bank)\w*\.\w+\.\w+", 3,
     "Subdomain spoofing of major brand"),
    (r"(secure|login|verify|update|account|banking|signin)\d*\.", 3, "Suspicious security-themed subdomain"),
    (r"\.(xyz|tk|ml|ga|cf|gq|top|club|work|click|download|stream)(/|$)", 3,
     "High-risk free TLD associated with phishing"),
    (r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.\w+", 2, "URL shortener hides destination"),
    (r"[a-z0-9\-]{30,}\.", 2, "Unusually long subdomain"),
    (r"@", 2, "URL contains @ character — classic phishing trick"),
    (r"%[0-9a-fA-F]{2}", 1, "URL-encoded characters may hide true destination"),
]

CREDENTIAL_PATTERNS = [
    (r"\benter\s+(your\s+)?(password|pin|passcode)\b", 4, "Direct password request"),
    (r"\bprovide\s+(your\s+)?(ssn|social\s+security|dob|date\s+of\s+birth)\b", 4,
     "Sensitive PII requested"),
    (r"\bsend\s+(your\s+)?(password|credentials|login)\b", 4, "Credential exfiltration attempt"),
    (r"\btype\s+(your\s+)?(pin|password|code)\b", 3, "Inline credential request"),
    (r"\bfull\s+(card\s+)?(number|cvv|cvc|expiry)\b", 4, "Payment credential request"),
    (r"\bbank\s+(account|routing)\s+number\b", 4, "Banking credential request"),
    (r"\busername\s+and\s+password\b", 3, "Combined credential request"),
]

SENDER_SPOOFING_PATTERNS = [
    (r"(paypal|amazon|apple|microsoft|google|facebook|netflix|irs|fbi|interpol)"
     r"[^@]*@(?!paypal\.com|amazon\.com|apple\.com|microsoft\.com|google\.com|"
     r"facebook\.com|netflix\.com|irs\.gov)[\w\.-]+\.\w+", 4,
     "Brand name in sender but domain doesn't match"),
    (r"no.?reply@\w+\.\w+\.\w+", 2, "No-reply from uncommon subdomain"),
    (r"@.*\.(xyz|tk|ml|ga|cf|gq|top|club|work)", 3, "Sender uses suspicious TLD"),
    (r"<[^>]+@[^>]+>[^<]*<[^>]+>", 2, "Display name and actual email may differ"),
]


def _compile_patterns(patterns):
    return [(re.compile(p, re.IGNORECASE), *rest) for p, *rest in patterns]


COMPILED = {
    "keywords": {
        sev: [re.compile(p, re.IGNORECASE) for p in pats]
        for sev, pats in PHISHING_KEYWORDS.items()
    },
    "urgency": _compile_patterns(URGENCY_PATTERNS),
    "urls": _compile_patterns(SUSPICIOUS_URL_PATTERNS),
    "credentials": _compile_patterns(CREDENTIAL_PATTERNS),
    "spoofing": _compile_patterns(SENDER_SPOOFING_PATTERNS),
}

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_NUMS = {4: "critical", 3: "high", 2: "medium", 1: "low"}


def analyze_email(email_body: str, sender: str = "", subject: str = "") -> RuleEngineResult:
    full_text = f"{subject}\n{sender}\n{email_body}"
    matches: List[RuleMatch] = []
    raw_score = 0

    for sev, patterns in COMPILED["keywords"].items():
        for pat in patterns:
            m = pat.search(full_text)
            if m:
                weight = SEVERITY_WEIGHTS[sev]
                raw_score += weight
                matches.append(RuleMatch(
                    rule_id=f"KW_{sev.upper()}_{len(matches)}",
                    label=f"Phishing keyword ({sev})",
                    severity={"critical": 4, "high": 3, "medium": 2, "low": 1}[sev],
                    detail=f'Matched: "{m.group()[:60]}"',
                    category="keyword",
                ))

    for pat, sev, label in COMPILED["urgency"]:
        m = pat.search(full_text)
        if m:
            raw_score += sev * 5
            matches.append(RuleMatch(
                rule_id=f"URG_{len(matches)}",
                label=f"Urgency tactic: {label}",
                severity=sev,
                detail=f'Pattern: "{m.group()[:60]}"',
                category="urgency",
            ))

    urls = re.findall(r'https?://[^\s<>"\']+', email_body, re.IGNORECASE)
    for pat, sev, label in COMPILED["urls"]:
        for url in urls:
            if pat.search(url):
                raw_score += sev * 6
                matches.append(RuleMatch(
                    rule_id=f"URL_{len(matches)}",
                    label=label,
                    severity=sev,
                    detail=f"URL: {url[:80]}",
                    category="url",
                ))
                break

    href_mismatch = re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]+)<', email_body, re.IGNORECASE)
    for href, text in href_mismatch:
        text_urls = re.findall(r'https?://[\w\.]+', text)
        for tu in text_urls:
            tu_domain = urlparse(tu).netloc
            href_domain = urlparse(href).netloc
            if tu_domain and href_domain and tu_domain != href_domain:
                raw_score += 20
                matches.append(RuleMatch(
                    rule_id=f"MISMATCH_{len(matches)}",
                    label="Link text vs href domain mismatch",
                    severity=4,
                    detail=f"Displayed: {tu_domain} → Actual: {href_domain}",
                    category="deception",
                ))

    for pat, sev, label in COMPILED["credentials"]:
        if pat.search(full_text):
            raw_score += sev * 7
            matches.append(RuleMatch(
                rule_id=f"CRED_{len(matches)}",
                label=label,
                severity=sev,
                detail="Credential collection attempt detected",
                category="credential",
            ))

    if sender:
        for pat, sev, label in COMPILED["spoofing"]:
            if pat.search(sender):
                raw_score += sev * 8
                matches.append(RuleMatch(
                    rule_id=f"SPOOF_{len(matches)}",
                    label=label,
                    severity=sev,
                    detail=f"Sender: {sender[:100]}",
                    category="spoofing",
                ))

    seen = set()
    unique_matches = []
    for m in matches:
        key = (m.category, m.severity)
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    rule_score = min(100, raw_score)
    signals = list({m.label for m in unique_matches})
    return RuleEngineResult(rule_score=rule_score, matches=unique_matches, signals=signals)


def analyze_url(url: str) -> RuleEngineResult:
    matches: List[RuleMatch] = []
    raw_score = 0

    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    except Exception:
        return RuleEngineResult(rule_score=50, signals=["URL could not be parsed"])

    if parsed.scheme == "http":
        raw_score += 30
        matches.append(RuleMatch("URL_HTTP", "Insecure HTTP protocol", 4,
                                 "No TLS encryption — credentials sent in plaintext", "security"))

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc or ""):
        raw_score += 35
        matches.append(RuleMatch("URL_IP", "Raw IP address as domain", 4,
                                 "Legitimate services use domain names, not raw IPs", "structure"))

    tld_match = re.search(r"\.(xyz|tk|ml|ga|cf|gq|top|club|work|click|download|stream)$",
                          parsed.netloc or "", re.IGNORECASE)
    if tld_match:
        raw_score += 25
        matches.append(RuleMatch("URL_TLD", f"High-risk TLD: .{tld_match.group(1)}", 3,
                                 "Free TLDs frequently abused by phishing campaigns", "tld"))

    brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook",
              "netflix", "bank", "chase", "wellsfargo", "citibank"]
    netloc = parsed.netloc or ""
    for brand in brands:
        if brand in netloc.lower():
            domain_parts = netloc.lower().split(".")
            if not any(p == brand + ".com" or p == brand + ".co" for p in
                       [".".join(domain_parts[-2:]), ".".join(domain_parts[-3:])]):
                raw_score += 30
                matches.append(RuleMatch(
                    "URL_BRAND", f"Brand spoofing: {brand}", 3,
                    f"'{brand}' appears in domain but is not the official site", "spoofing"
                ))
                break

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "short.io"]
    if any(s in netloc.lower() for s in shorteners):
        raw_score += 15
        matches.append(RuleMatch("URL_SHORT", "URL shortener detected", 2,
                                 "True destination is hidden behind shortener", "obfuscation"))

    subdomain_count = len(netloc.split(".")) - 2
    if subdomain_count > 2:
        raw_score += 10 * (subdomain_count - 2)
        matches.append(RuleMatch("URL_SUBDOMAIN", f"Excessive subdomains ({subdomain_count})", 2,
                                 "Phishers use deep subdomains to look legitimate", "structure"))

    if len(netloc) > 40:
        raw_score += 10
        matches.append(RuleMatch("URL_LONG", "Unusually long domain name", 2,
                                 f"Domain length: {len(netloc)} chars", "structure"))

    if "@" in url:
        raw_score += 25
        matches.append(RuleMatch("URL_AT", "@ character in URL", 4,
                                 "Browser ignores everything before @ — classic redirect trick", "deception"))

    if re.search(r"%[0-9a-fA-F]{2}", url):
        raw_score += 8
        matches.append(RuleMatch("URL_ENCODE", "URL-encoded characters", 1,
                                 "Encoding can be used to hide true URL destination", "obfuscation"))

    rule_score = min(100, raw_score)
    signals = [m.label for m in matches]
    return RuleEngineResult(rule_score=rule_score, matches=matches, signals=signals)


def analyze_headers(raw_headers: str) -> RuleEngineResult:
    matches: List[RuleMatch] = []
    raw_score = 0
    lines = raw_headers.strip().split("\n")
    header_map = {}

    for line in lines:
        if ":" in line:
            key, _, val = line.partition(":")
            header_map[key.strip().lower()] = val.strip()

    received_spf = header_map.get("received-spf", "")
    auth_results = header_map.get("authentication-results", "")

    if "fail" in received_spf.lower():
        raw_score += 35
        matches.append(RuleMatch("HDR_SPF_FAIL", "SPF authentication failed", 4,
                                 "Server is not authorized to send email for this domain", "authentication"))
    elif "softfail" in received_spf.lower():
        raw_score += 20
        matches.append(RuleMatch("HDR_SPF_SOFT", "SPF soft fail", 3,
                                 "Sender marginally fails SPF — possible spoofing", "authentication"))
    elif "pass" not in received_spf.lower() and "pass" not in auth_results.lower():
        raw_score += 10
        matches.append(RuleMatch("HDR_SPF_NONE", "No SPF result found", 2,
                                 "Missing SPF verification — authentication unconfirmed", "authentication"))

    if "dkim=fail" in auth_results.lower():
        raw_score += 30
        matches.append(RuleMatch("HDR_DKIM_FAIL", "DKIM signature failed", 4,
                                 "Email content may have been tampered with in transit", "authentication"))
    elif "dkim=" not in auth_results.lower():
        raw_score += 8
        matches.append(RuleMatch("HDR_DKIM_NONE", "No DKIM signature", 2,
                                 "Email was not cryptographically signed", "authentication"))

    if "dmarc=fail" in auth_results.lower():
        raw_score += 35
        matches.append(RuleMatch("HDR_DMARC_FAIL", "DMARC policy failed", 4,
                                 "Domain's DMARC policy explicitly rejects this email", "authentication"))
    elif "dmarc=" not in auth_results.lower():
        raw_score += 5
        matches.append(RuleMatch("HDR_DMARC_NONE", "No DMARC result", 1,
                                 "DMARC was not evaluated", "authentication"))

    from_header = header_map.get("from", "")
    reply_to = header_map.get("reply-to", "")
    if reply_to and from_header:
        from_domain = re.search(r"@([\w\.-]+)", from_header)
        reply_domain = re.search(r"@([\w\.-]+)", reply_to)
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            raw_score += 25
            matches.append(RuleMatch("HDR_REPLYTO", "Reply-To domain differs from From domain", 3,
                                     f"From: {from_domain.group(1)} → Reply-To: {reply_domain.group(1)}",
                                     "deception"))

    x_mailer = header_map.get("x-mailer", header_map.get("x-php-originating-script", ""))
    if re.search(r"(bulk|mass|blast|phpmailer|sendblaster|gambler)", x_mailer, re.IGNORECASE):
        raw_score += 15
        matches.append(RuleMatch("HDR_MAILER", "Suspicious mail client detected", 2,
                                 f"X-Mailer: {x_mailer[:60]}", "infrastructure"))

    received_count = sum(1 for l in lines if l.lower().startswith("received:"))
    if received_count > 7:
        raw_score += 10
        matches.append(RuleMatch("HDR_HOPS", f"High mail hop count ({received_count})", 2,
                                 "Email routed through many servers — possible relay abuse", "infrastructure"))

    rule_score = min(100, raw_score)
    signals = [m.label for m in matches]
    return RuleEngineResult(rule_score=rule_score, matches=matches, signals=signals)