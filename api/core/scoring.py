"""
Scoring Engine — combines rule-based and AI scores into final verdict.
"""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FinalVerdict:
    score: int
    verdict: str
    confidence: str
    rule_score: int
    ai_score: Optional[int]
    signals: List[str]
    explanation: str
    indicators: List[dict]

    def to_dict(self):
        return {
            "score": self.score,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rule_score": self.rule_score,
            "ai_score": self.ai_score,
            "signals": self.signals,
            "explanation": self.explanation,
            "indicators": self.indicators,
        }


VERDICT_THRESHOLDS = [
    (0, 15, "SAFE", "confidence-high"),
    (15, 30, "LOW", "confidence-high"),
    (30, 55, "MEDIUM", "confidence-medium"),
    (55, 75, "HIGH", "confidence-medium"),
    (75, 101, "CRITICAL", "confidence-high"),
]


def compute_final_score(rule_score: int, ai_score: Optional[int]) -> int:
    if ai_score is None:
        return rule_score
    blended = int(rule_score * 0.55 + ai_score * 0.45)
    if rule_score >= 70 and ai_score >= 70:
        blended = max(blended, max(rule_score, ai_score) - 5)
    return min(100, blended)


def score_to_verdict(score: int):
    for low, high, verdict, conf in VERDICT_THRESHOLDS:
        if low <= score < high:
            return verdict, conf
    return "CRITICAL", "confidence-high"


def build_indicators(matches: list, analysis_type: str) -> List[dict]:
    category_icons = {
        "keyword": "🔤",
        "urgency": "⏰",
        "url": "🔗",
        "credential": "🔑",
        "spoofing": "🎭",
        "deception": "🎭",
        "authentication": "🛡️",
        "infrastructure": "🏗️",
        "security": "🔒",
        "structure": "🏗️",
        "tld": "🌐",
        "obfuscation": "👁️",
    }
    severity_labels = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
    indicators = []

    for m in matches:
        if isinstance(m, dict):
            sev = m.get("severity", 1)
            cat = m.get("category", "other")
            label = m.get("label", "Unknown signal")
            detail = m.get("detail", "")
        else:
            sev = m.severity
            cat = m.category
            label = m.label
            detail = m.detail

        indicators.append({
            "icon": category_icons.get(cat, "⚠️"),
            "severity": severity_labels.get(sev, "LOW"),
            "severity_num": sev,
            "label": label,
            "detail": detail,
            "category": cat,
        })

    indicators.sort(key=lambda x: x["severity_num"], reverse=True)
    return indicators


def generate_explanation(verdict: str, score: int, signals: List[str],
                         analysis_type: str, ai_explanation: Optional[str] = None) -> str:
    if ai_explanation:
        return ai_explanation

    type_labels = {"email": "email", "url": "URL", "headers": "email headers"}
    label = type_labels.get(analysis_type, "content")

    if verdict == "SAFE":
        return (
            f"This {label} appears legitimate. No significant phishing indicators were detected. "
            f"The risk score of {score}/100 is within normal bounds. "
            f"Standard caution is still advised."
        )
    elif verdict == "LOW":
        top = signals[0] if signals else "minor anomalies"
        return (
            f"This {label} has a low risk score of {score}/100 with minor concerns detected, "
            f"including: {top}. Proceed with caution and verify any requests through official channels."
        )
    elif verdict == "MEDIUM":
        sig_list = ", ".join(signals[:3]) if signals else "multiple suspicious patterns"
        return (
            f"This {label} exhibits moderate phishing indicators (score: {score}/100). "
            f"Detected signals include: {sig_list}. "
            f"Do not click links or provide information without verifying the sender's identity."
        )
    elif verdict == "HIGH":
        sig_list = ", ".join(signals[:4]) if signals else "multiple high-severity patterns"
        return (
            f"HIGH RISK — This {label} demonstrates strong phishing characteristics (score: {score}/100). "
            f"Key indicators: {sig_list}. "
            f"Do NOT interact with this content. Report to your security team."
        )
    else:
        sig_list = ", ".join(signals[:5]) if signals else "critical threat patterns"
        return (
            f"⚠️ CRITICAL THREAT — This {label} is almost certainly malicious (score: {score}/100). "
            f"Detected: {sig_list}. "
            f"Immediately quarantine this message, do NOT click any links, "
            f"and report this to your IT security team."
        )