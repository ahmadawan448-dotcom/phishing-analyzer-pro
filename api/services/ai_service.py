"""
AI Service Layer — OpenAI-compatible API integration with mock fallback.
"""
import json
import logging
import re
import time
from typing import Optional
import urllib.request
import urllib.error

logger = logging.getLogger("phishing_analyzer.ai")


class AIAnalysisResult:
    def __init__(self, score: int, explanation: str, signals: list, raw: str = ""):
        self.score = max(0, min(100, score))
        self.explanation = explanation
        self.signals = signals
        self.raw = raw


MOCK_RESPONSES = {
    "email": {
        "low": (15, ["No suspicious links detected", "Sender domain appears legitimate",
                     "Language is professional and non-urgent"],
                "AI analysis found no significant phishing indicators."),
        "medium": (55, ["Slightly elevated urgency language", "Generic greeting instead of personalized",
                        "Contains external links worth verifying"],
                   "AI detected moderate risk signals. The email uses common social engineering language patterns."),
        "high": (80, ["Classic credential harvesting language", "Urgency tactics detected",
                      "Impersonation of trusted institution", "Suspicious link destination"],
                 "AI analysis indicates HIGH probability of phishing. Multiple social engineering techniques detected."),
    },
    "url": {
        "low": (10, ["Domain appears to match legitimate service"], "URL structure analysis shows no major red flags."),
        "medium": (45, ["Unusual subdomain structure", "Domain registered recently"],
                   "URL shows moderate risk indicators. Verify before clicking."),
        "high": (85, ["Known phishing URL pattern", "Spoofing legitimate brand"],
                 "URL exhibits strong phishing characteristics. Do not visit this URL."),
    },
    "headers": {
        "low": (10, ["Authentication headers appear valid"], "Email headers show standard legitimate delivery pattern."),
        "medium": (40, ["Minor SPF inconsistency"], "Headers show some anomalies but not conclusively malicious."),
        "high": (85, ["Authentication failures across SPF/DKIM/DMARC"],
                 "Header analysis strongly suggests spoofed/forged email origin."),
    },
}


def _mock_analyze(content: str, analysis_type: str, rule_score: int) -> AIAnalysisResult:
    time.sleep(0.3)
    responses = MOCK_RESPONSES.get(analysis_type, MOCK_RESPONSES["email"])
    if rule_score < 20:
        tier = "low"
        variation = 0
    elif rule_score < 55:
        tier = "medium"
        variation = (rule_score % 10) - 5
    else:
        tier = "high"
        variation = (rule_score % 8) - 4
    score, signals, explanation = responses[tier]
    score = max(0, min(100, score + variation))
    return AIAnalysisResult(score=score, explanation=explanation, signals=signals, raw="[mock]")


def _build_prompt(content: str, analysis_type: str) -> str:
    type_instructions = {
        "email": "Analyze this email for phishing indicators. Consider: urgency tactics, credential requests, spoofed branding, suspicious links, and social engineering patterns.",
        "url": "Analyze this URL for phishing/malicious indicators. Consider: domain spoofing, suspicious TLD, obfuscation, and brand impersonation.",
        "headers": "Analyze these email headers for phishing/spoofing indicators. Consider: SPF/DKIM/DMARC results, sender authentication, and relay path anomalies.",
    }
    return f"""You are a cybersecurity expert specializing in phishing detection.

{type_instructions.get(analysis_type, type_instructions['email'])}

Content to analyze:
---
{content[:3000]}
---

Respond ONLY with a JSON object (no markdown, no preamble):
{{
  "risk_score": <integer 0-100>,
  "signals": [<up to 5 short signal strings>],
  "explanation": "<2-3 sentence professional security assessment>"
}}"""


def analyze_with_ai(content: str, analysis_type: str, rule_score: int,
                    api_key: str, base_url: str = "https://api.openai.com/v1",
                    model: str = "gpt-4o-mini", timeout: int = 10,
                    use_ai: bool = False) -> Optional[AIAnalysisResult]:
    if not use_ai or not api_key:
        logger.info("AI analysis: using mock (USE_AI=false or no API key)")
        return _mock_analyze(content, analysis_type, rule_score)

    prompt = _build_prompt(content, analysis_type)
    payload = json.dumps({
        "model": model,
        "max_tokens": 400,
        "temperature": 0.1,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    url = f"{base_url.rstrip('/')}/chat/completions"
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_text = data["choices"][0]["message"]["content"]
            clean = re.sub(r"```(?:json)?|```", "", raw_text).strip()
            parsed = json.loads(clean)
            return AIAnalysisResult(
                score=int(parsed.get("risk_score", rule_score)),
                explanation=parsed.get("explanation", ""),
                signals=parsed.get("signals", []),
                raw=raw_text,
            )
    except Exception as e:
        logger.warning(f"AI API error: {e} — falling back to mock")
        return _mock_analyze(content, analysis_type, rule_score)