"""
Analyzer Service — orchestrates rule engine + AI into a unified pipeline.
"""
import logging
import time
from typing import Optional
from flask import current_app

from core.rules_engine import analyze_email, analyze_url, analyze_headers
from core.scoring import (
    compute_final_score, score_to_verdict, build_indicators,
    generate_explanation, FinalVerdict
)
from services.ai_service import analyze_with_ai

logger = logging.getLogger("phishing_analyzer.analyzer")


def _get_ai_config():
    return {
        "api_key": current_app.config.get("AI_API_KEY", ""),
        "base_url": current_app.config.get("AI_BASE_URL", "https://api.openai.com/v1"),
        "model": current_app.config.get("AI_MODEL", "gpt-4o-mini"),
        "timeout": current_app.config.get("AI_TIMEOUT", 10),
        "use_ai": current_app.config.get("USE_AI", False),
    }


def run_email_analysis(body: str, sender: str = "", subject: str = "") -> dict:
    start = time.time()
    rule_result = analyze_email(body, sender, subject)
    ai_config = _get_ai_config()
    content = f"Subject: {subject}\nFrom: {sender}\n\n{body}"
    ai_result = analyze_with_ai(content=content, analysis_type="email",
                                rule_score=rule_result.rule_score, **ai_config)
    ai_score = ai_result.score if ai_result else None
    final_score = compute_final_score(rule_result.rule_score, ai_score)
    verdict, confidence = score_to_verdict(final_score)
    all_signals = list(set(rule_result.signals + (ai_result.signals if ai_result else [])))
    explanation = generate_explanation(verdict, final_score, all_signals, "email",
                                       ai_result.explanation if ai_result else None)
    indicators = build_indicators(rule_result.matches, "email")
    elapsed = round((time.time() - start) * 1000)
    return FinalVerdict(score=final_score, verdict=verdict, confidence=confidence,
                        rule_score=rule_result.rule_score, ai_score=ai_score,
                        signals=all_signals[:10], explanation=explanation,
                        indicators=indicators[:12]).to_dict() | {"analysis_type": "email", "elapsed_ms": elapsed}


def run_url_analysis(url: str) -> dict:
    start = time.time()
    rule_result = analyze_url(url)
    ai_config = _get_ai_config()
    ai_result = analyze_with_ai(content=url, analysis_type="url",
                                rule_score=rule_result.rule_score, **ai_config)
    ai_score = ai_result.score if ai_result else None
    final_score = compute_final_score(rule_result.rule_score, ai_score)
    verdict, confidence = score_to_verdict(final_score)
    all_signals = list(set(rule_result.signals + (ai_result.signals if ai_result else [])))
    explanation = generate_explanation(verdict, final_score, all_signals, "url",
                                       ai_result.explanation if ai_result else None)
    indicators = build_indicators(rule_result.matches, "url")
    elapsed = round((time.time() - start) * 1000)
    return FinalVerdict(score=final_score, verdict=verdict, confidence=confidence,
                        rule_score=rule_result.rule_score, ai_score=ai_score,
                        signals=all_signals[:10], explanation=explanation,
                        indicators=indicators[:12]).to_dict() | {"analysis_type": "url", "elapsed_ms": elapsed}


def run_header_analysis(raw_headers: str) -> dict:
    start = time.time()
    rule_result = analyze_headers(raw_headers)
    ai_config = _get_ai_config()
    ai_result = analyze_with_ai(content=raw_headers, analysis_type="headers",
                                rule_score=rule_result.rule_score, **ai_config)
    ai_score = ai_result.score if ai_result else None
    final_score = compute_final_score(rule_result.rule_score, ai_score)
    verdict, confidence = score_to_verdict(final_score)
    all_signals = list(set(rule_result.signals + (ai_result.signals if ai_result else [])))
    explanation = generate_explanation(verdict, final_score, all_signals, "headers",
                                       ai_result.explanation if ai_result else None)
    indicators = build_indicators(rule_result.matches, "headers")
    elapsed = round((time.time() - start) * 1000)
    return FinalVerdict(score=final_score, verdict=verdict, confidence=confidence,
                        rule_score=rule_result.rule_score, ai_score=ai_score,
                        signals=all_signals[:10], explanation=explanation,
                        indicators=indicators[:12]).to_dict() | {"analysis_type": "headers", "elapsed_ms": elapsed}