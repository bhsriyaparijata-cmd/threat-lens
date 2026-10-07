
"""
analyzer.py
------------
Orchestrates the complete Threat Lens email investigation.

Pipeline:
1. Forensic parsing
2. AI email-content classification
3. URL analysis
4. Sender / identity analysis
5. SPF / DKIM / DMARC analysis
6. IP / GeoIP intelligence
7. Attachment analysis
8. Multi-signal threat correlation
9. Phishing / BEC classification
10. Explainable threat scoring

Only the email-content classifier uses machine learning.
The remaining analysis uses rules, protocol checks and threat intelligence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from utils import (
    attachment_analyzer,
    auth_analyzer,
    forensic_parser,
    geoip_analyzer,
    sender_analyzer,
    url_analyzer,
)


MODEL_DIR = Path(__file__).parent / "model"


# ---------------------------------------------------------------------------
# Threat scoring configuration
# ---------------------------------------------------------------------------

THREAT_SCORING_CONFIG = {
    # ML
    "ml_spam_high_confidence": 20,
    "ml_spam_low_confidence": 8,

    # URLs
    "url_risk_high": 20,
    "url_risk_medium": 12,

    # Sender / Identity
    "sender_risk_high": 25,
    "sender_risk_medium": 12,

    # Authentication
    "spf_fail": 8,
    "dkim_fail": 8,
    "dmarc_fail": 6,

    # Attachments
    "attachment_risk_high": 20,
    "attachment_risk_medium": 8,

    # Threat intelligence
    "threat_intel_hit": 20,

    # Multi-signal correlation
    "phishing_correlation": 15,
    "bec_correlation": 15,
}


RISK_BANDS = [
    (0, 30, "LOW RISK"),
    (31, 60, "MEDIUM RISK"),
    (61, 100, "HIGH RISK"),
]


# ---------------------------------------------------------------------------
# ML model
# ---------------------------------------------------------------------------

class MLClassifier:
    def __init__(self) -> None:
        self.model = None
        self.vectorizer = None
        self.available = False
        self.load_error = ""
        self._load()

    def _load(self) -> None:
        model_path = MODEL_DIR / "spam_model.pkl"
        vec_path = MODEL_DIR / "vectorizer.pkl"

        if not model_path.exists() or not vec_path.exists():
            self.load_error = (
                "Model files not found. Run 'python train_model.py' after "
                "'python download_dataset.py' to generate model/spam_model.pkl "
                "and model/vectorizer.pkl."
            )
            return

        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vec_path)
            self.available = True

        except Exception as exc:
            self.load_error = f"Failed to load model artifacts: {exc}"

    def classify(self, email_text: str) -> Dict[str, Any]:

        if not self.available:
            return {
                "available": False,
                "prediction": "UNKNOWN",
                "confidence": 0.0,
                "note": self.load_error,
            }

        if not email_text.strip():
            return {
                "available": True,
                "prediction": "UNKNOWN",
                "confidence": 0.0,
                "note": "No email body text available to classify.",
            }

        try:
            vector = self.vectorizer.transform([email_text])

            proba = self.model.predict_proba(vector)[0]
            classes = list(self.model.classes_)

            spam_index = (
                classes.index(1)
                if 1 in classes
                else int(proba.argmax())
            )

            spam_prob = float(proba[spam_index])

            prediction = (
                "SPAM"
                if spam_prob >= 0.5
                else "LIKELY LEGITIMATE"
            )

            confidence = (
                spam_prob
                if prediction == "SPAM"
                else 1 - spam_prob
            )

            return {
                "available": True,
                "prediction": prediction,
                "confidence": round(confidence * 100, 2),
                "note": "",
            }

        except Exception as exc:
            return {
                "available": False,
                "prediction": "UNKNOWN",
                "confidence": 0.0,
                "note": f"Classification failed: {exc}",
            }


_classifier: Optional[MLClassifier] = None


def get_classifier() -> MLClassifier:
    global _classifier

    if _classifier is None:
        _classifier = MLClassifier()

    return _classifier


# ---------------------------------------------------------------------------
# Risk band
# ---------------------------------------------------------------------------

def _risk_band(score: int) -> str:

    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label

    return "HIGH RISK"


# ---------------------------------------------------------------------------
# Multi-signal correlation helpers
# ---------------------------------------------------------------------------

def _get_url_signals(url_results):
    """
    Extract useful URL signals for cross-signal correlation.
    """

    high_urls = [
        u for u in url_results
        if u.get("risk") == "High"
    ]

    medium_urls = [
        u for u in url_results
        if u.get("risk") == "Medium"
    ]

    intel_hits = [
        u for u in url_results
        if u.get("threat_intel")
        == "Known phishing indicator detected"
    ]

    url_indicators = []

    for u in url_results:
        url_indicators.extend(
            u.get("indicators", [])
        )

    return (
        high_urls,
        medium_urls,
        intel_hits,
        url_indicators,
    )


def _detect_phishing_correlation(
    ml_result,
    url_results,
    sender_result,
    auth_result,
):
    """
    Detect when multiple independent signals support phishing.

    This is rule-based explainability, not an ML prediction.
    """

    evidence = []

    ml_spam = (
        ml_result.get("prediction") == "SPAM"
    )

    high_urls, medium_urls, intel_hits, url_indicators = (
        _get_url_signals(url_results)
    )

    sender_risky = sender_result.get("risk") in (
        "Medium",
        "High",
    )

    auth_failure = any(
        auth_result.get(key) == "FAIL"
        for key in ["spf", "dkim", "dmarc"]
    )

    if ml_spam:
        evidence.append(
            "Email content classified as SPAM"
        )

    if high_urls:
        evidence.append(
            f"{len(high_urls)} high-risk URL(s)"
        )

    elif medium_urls:
        evidence.append(
            f"{len(medium_urls)} medium-risk URL(s)"
        )

    if intel_hits:
        evidence.append(
            f"{len(intel_hits)} URL(s) matched "
            "threat intelligence"
        )

    if sender_risky:
        evidence.append(
            f"Sender identity analysis returned "
            f"{sender_result.get('risk')} risk"
        )

    if auth_failure:
        evidence.append(
            "One or more email authentication checks failed"
        )

    # Need at least two independent signals.
    signal_count = sum([
        ml_spam,
        bool(high_urls or medium_urls),
        bool(intel_hits),
        sender_risky,
        auth_failure,
    ])

    if signal_count >= 2:
        return True, evidence

    return False, evidence


def _detect_bec_correlation(
    sender_result,
    auth_result,
    url_results,
):
    """
    Detect possible Business Email Compromise / impersonation patterns.

    This is deliberately conservative.
    """

    evidence = []

    sender_reasons = sender_result.get(
        "reasons",
        []
    )

    sender_mismatch = any(
        "Reply-To domain" in r
        or "Return-Path domain" in r
        for r in sender_reasons
    )

    impersonation = any(
        "Display name references" in r
        or "closely resembles" in r
        or "Free email provider" in r
        for r in sender_reasons
    )

    suspicious_url = any(
        u.get("risk") in ("Medium", "High")
        for u in url_results
    )

    auth_failure = any(
        auth_result.get(key) == "FAIL"
        for key in ["spf", "dkim", "dmarc"]
    )

    if sender_mismatch:
        evidence.append(
            "Sender identity mismatch detected"
        )

    if impersonation:
        evidence.append(
            "Possible brand or organizational "
            "impersonation detected"
        )

    if suspicious_url:
        evidence.append(
            "Suspicious URL associated with the message"
        )

    if auth_failure:
        evidence.append(
            "Email authentication failure detected"
        )

    # BEC requires sender/identity evidence plus
    # another supporting signal.
    if (
        (sender_mismatch or impersonation)
        and (suspicious_url or auth_failure)
    ):
        return True, evidence

    return False, evidence


# ---------------------------------------------------------------------------
# Main threat correlation engine
# ---------------------------------------------------------------------------

def correlate_threat(
    ml_result,
    url_results,
    sender_result,
    auth_result,
    attachment_results,
) -> Dict[str, Any]:

    cfg = THREAT_SCORING_CONFIG

    score = 0

    reasons = []
    investigate = []
    score_breakdown = []

    # ============================================================
    # 1. ML CONTENT SIGNAL
    # ============================================================

    if ml_result.get("prediction") == "SPAM":

        confidence = ml_result.get(
            "confidence",
            0,
        )

        if confidence >= 80:

            score += cfg[
                "ml_spam_high_confidence"
            ]

            score_breakdown.append({
                "signal": "ML spam classification",
                "points": cfg["ml_spam_high_confidence"],
                "reason": f"SPAM with high confidence ({confidence}%)",
            })

            reasons.append(
                f"AI model classified email content "
                f"as SPAM with high confidence "
                f"({confidence}%)"
            )

        else:

            score += cfg[
                "ml_spam_low_confidence"
            ]

            score_breakdown.append({
                "signal": "ML spam classification",
                "points": cfg["ml_spam_low_confidence"],
                "reason": f"SPAM with moderate confidence ({confidence}%)",
            })

            reasons.append(
                f"AI model classified email content "
                f"as SPAM with moderate confidence "
                f"({confidence}%)"
            )

    elif ml_result.get("prediction") == "UNKNOWN":

        investigate.append(
            "Email content could not be classified "
            "by the ML model."
        )

    # ============================================================
    # 2. URL SIGNAL
    # ============================================================

    (
        high_risk_urls,
        medium_risk_urls,
        intel_hits,
        url_indicators,
    ) = _get_url_signals(
        url_results
    )

    if high_risk_urls:

        score += cfg["url_risk_high"]

        score_breakdown.append({
            "signal": "URL analysis",
            "points": cfg["url_risk_high"],
            "reason": f"{len(high_risk_urls)} high-risk URL(s)",
        })

        reasons.append(
            f"{len(high_risk_urls)} URL(s) flagged "
            "High risk by URL analysis"
        )

    elif medium_risk_urls:

        score += cfg["url_risk_medium"]

        score_breakdown.append({
            "signal": "URL analysis",
            "points": cfg["url_risk_medium"],
            "reason": f"{len(medium_risk_urls)} medium-risk URL(s)",
        })

        reasons.append(
            f"{len(medium_risk_urls)} URL(s) flagged "
            "Medium risk by URL analysis"
        )

    # ============================================================
    # 3. THREAT INTELLIGENCE
    # ============================================================

    if intel_hits:

        score += cfg["threat_intel_hit"]

        score_breakdown.append({
            "signal": "Threat intelligence",
            "points": cfg["threat_intel_hit"],
            "reason": f"{len(intel_hits)} URL(s) matched known phishing intelligence",
        })

        reasons.append(
            f"{len(intel_hits)} URL(s) matched known "
            "phishing threat intelligence"
        )

    # ============================================================
    # 4. SENDER SIGNAL
    # ============================================================

    sender_risk = sender_result.get(
        "risk"
    )

    if sender_risk == "High":

        score += cfg[
            "sender_risk_high"
        ]

        score_breakdown.append({
            "signal": "Sender identity",
            "points": cfg["sender_risk_high"],
            "reason": "Sender analysis returned High risk",
        })

        reasons.append(
            "Sender analysis flagged High risk: "
            + "; ".join(
                sender_result.get(
                    "reasons",
                    []
                )
            )
        )

    elif sender_risk == "Medium":

        score += cfg[
            "sender_risk_medium"
        ]

        score_breakdown.append({
            "signal": "Sender identity",
            "points": cfg["sender_risk_medium"],
            "reason": "Sender analysis returned Medium risk",
        })

        reasons.append(
            "Sender analysis flagged Medium risk: "
            + "; ".join(
                sender_result.get(
                    "reasons",
                    []
                )
            )
        )

    # ============================================================
    # 5. AUTHENTICATION SIGNALS
    # ============================================================

    if auth_result.get("spf") == "FAIL":

        score += cfg["spf_fail"]

        score_breakdown.append({
            "signal": "SPF authentication",
            "points": cfg["spf_fail"],
            "reason": "SPF check failed",
        })

        reasons.append(
            "SPF authentication failed"
        )

    if auth_result.get("dkim") == "FAIL":

        score += cfg["dkim_fail"]

        score_breakdown.append({
            "signal": "DKIM authentication",
            "points": cfg["dkim_fail"],
            "reason": "DKIM check failed",
        })

        reasons.append(
            "DKIM authentication failed"
        )

    if auth_result.get("dmarc") == "FAIL":

        score += cfg["dmarc_fail"]

        score_breakdown.append({
            "signal": "DMARC authentication",
            "points": cfg["dmarc_fail"],
            "reason": "DMARC check failed",
        })

        reasons.append(
            "DMARC authentication failed"
        )

    # Missing authentication is not treated
    # as authentication failure.
    if (
        auth_result.get("spf") == "NONE"
        and auth_result.get("dkim") == "NONE"
    ):

        investigate.append(
            "No SPF, DKIM or DMARC authentication "
            "data was present to verify."
        )

    # ============================================================
    # 6. ATTACHMENT SIGNAL
    # ============================================================

    high_risk_attachments = [
        a for a in attachment_results
        if a.get("risk") == "High"
    ]

    medium_risk_attachments = [
        a for a in attachment_results
        if a.get("risk") == "Medium"
    ]

    if high_risk_attachments:

        score += cfg[
            "attachment_risk_high"
        ]

        score_breakdown.append({
            "signal": "Attachment analysis",
            "points": cfg["attachment_risk_high"],
            "reason": f"{len(high_risk_attachments)} high-risk attachment(s)",
        })

        reasons.append(
            f"{len(high_risk_attachments)} attachment(s) "
            "flagged High risk"
        )

    elif medium_risk_attachments:

        score += cfg[
            "attachment_risk_medium"
        ]

        score_breakdown.append({
            "signal": "Attachment analysis",
            "points": cfg["attachment_risk_medium"],
            "reason": f"{len(medium_risk_attachments)} medium-risk attachment(s)",
        })

        reasons.append(
            f"{len(medium_risk_attachments)} attachment(s) "
            "flagged Medium risk"
        )

    # ============================================================
    # 7. CROSS-SIGNAL PHISHING CORRELATION
    # ============================================================

    (
        phishing_detected,
        phishing_evidence,
    ) = _detect_phishing_correlation(
        ml_result,
        url_results,
        sender_result,
        auth_result,
    )

    if phishing_detected:

        score += cfg[
            "phishing_correlation"
        ]

        score_breakdown.append({
            "signal": "Phishing correlation",
            "points": cfg["phishing_correlation"],
            "reason": "Multiple independent signals support phishing",
        })

        reasons.append(
            "Strong multi-signal phishing "
            "correlation detected"
        )

        investigate.append(
            "Multiple independent signals support "
            "a possible phishing attack: "
            + "; ".join(
                phishing_evidence
            )
        )

    # ============================================================
    # 8. BEC / IMPERSONATION CORRELATION
    # ============================================================

    (
        bec_detected,
        bec_evidence,
    ) = _detect_bec_correlation(
        sender_result,
        auth_result,
        url_results,
    )

    if bec_detected:

        score += cfg[
            "bec_correlation"
        ]

        score_breakdown.append({
            "signal": "BEC / impersonation correlation",
            "points": cfg["bec_correlation"],
            "reason": "Sender/identity evidence plus another supporting signal",
        })

        reasons.append(
            "Possible BEC / impersonation "
            "pattern detected"
        )

        investigate.append(
            "Review possible "
            "business-email-compromise indicators: "
            + "; ".join(
                bec_evidence
            )
        )

    # ============================================================
    # 9. FINAL SCORE
    # ============================================================

    score = max(
        0,
        min(
            100,
            int(score)
        )
    )

    risk_level = _risk_band(
        score
    )

    # ============================================================
    # 10. THREAT TYPE
    # ============================================================

    if phishing_detected and bec_detected:

        threat_type = (
            "PHISHING / BEC"
        )

    elif phishing_detected:

        threat_type = "PHISHING"

    elif bec_detected:

        threat_type = (
            "POSSIBLE BEC / IMPERSONATION"
        )

    elif score >= 61:

        threat_type = (
            "MALICIOUS / HIGH RISK"
        )

    elif score >= 31:

        threat_type = "SUSPICIOUS"

    else:

        threat_type = (
            "NO STRONG THREAT SIGNAL"
        )

    # ============================================================
    # 11. DEFAULT EXPLANATION
    # ============================================================

    if not reasons:

        reasons.append(
            "No significant risk indicators "
            "were detected across the "
            "analyzed signals."
        )

    # ============================================================
    # 12. HUMAN-READABLE THREAT EXPLANATION
    # ============================================================

    why_flagged = []

    if high_risk_urls:

        why_flagged.append(
            f"{len(high_risk_urls)} high-risk "
            "URL(s) detected"
        )

    elif medium_risk_urls:

        why_flagged.append(
            f"{len(medium_risk_urls)} medium-risk "
            "URL(s) detected"
        )

    if sender_risk == "High":

        why_flagged.append(
            "Sender identity was assessed "
            "as High risk"
        )

    elif sender_risk == "Medium":

        why_flagged.append(
            "Sender identity was assessed "
            "as Medium risk"
        )

    if phishing_detected:

        why_flagged.append(
            "Multiple signals correlate "
            "with phishing activity"
        )

    if bec_detected:

        why_flagged.append(
            "Sender identity and message indicators "
            "suggest possible BEC / impersonation"
        )

    if auth_result.get("spf") == "FAIL":

        why_flagged.append(
            "SPF authentication failed"
        )

    if auth_result.get("dkim") == "FAIL":

        why_flagged.append(
            "DKIM authentication failed"
        )

    if auth_result.get("dmarc") == "FAIL":

        why_flagged.append(
            "DMARC authentication failed"
        )

    if not why_flagged:

        why_flagged.append(
            "No strong threat indicators "
            "were identified."
        )

    # ============================================================
    # 13. ML / FINAL VERDICT EXPLANATION
    # ============================================================

    verdict_explanation = ""

    ml_prediction = ml_result.get(
        "prediction"
    )

    if (
        ml_prediction == "LIKELY LEGITIMATE"
        and (
            phishing_detected
            or bec_detected
            or score >= 31
        )
    ):

        verdict_explanation = (
            "The ML email-content classifier produced "
            "a likely legitimate prediction, but the "
            "final threat assessment considers multiple "
            "independent security signals including "
            "sender identity, URL analysis, "
            "authentication and threat correlation."
        )

    elif (
        ml_prediction == "SPAM"
        and (
            phishing_detected
            or bec_detected
        )
    ):

        verdict_explanation = (
            "The ML classifier identified suspicious "
            "email content and independent security "
            "signals further supported the final "
            "threat assessment."
        )

    else:

        verdict_explanation = (
            "The final threat assessment is based on "
            "the combined results of content analysis, "
            "sender analysis, URL analysis, "
            "authentication checks and correlation rules."
        )

    # ============================================================
    # 14. RETURN COMPLETE EXPLANATION
    # ============================================================

    return {
        "score": score,

        "risk_level": risk_level,

        # Threat classification
        "threat_type": threat_type,

        # Explainability
        "reasons": reasons,

        "investigate_further": investigate,

        "why_flagged": why_flagged,

        "verdict_explanation": verdict_explanation,

        # Exact score contribution from each detected signal.
        "score_breakdown": score_breakdown,

        # Correlation evidence
        "phishing_detected": phishing_detected,

        "phishing_evidence": phishing_evidence,

        "bec_detected": bec_detected,

        "bec_evidence": bec_evidence,

        # Transparency
        "scoring_config": cfg,
    }


# ---------------------------------------------------------------------------
# Full analysis pipeline
# ---------------------------------------------------------------------------

def run_full_analysis(
    record: Dict[str, Any],
    phishing_lookup=None,
) -> Dict[str, Any]:
    """
    Runs the complete Threat Lens investigation pipeline.
    """

    # ------------------------------------------------------------
    # 1. ML content analysis
    # ------------------------------------------------------------

    classifier = get_classifier()

    email_text_for_ml = (
        f"{record.get('subject', '')} "
        f"{record.get('body_text', '')}"
    )

    ml_result = classifier.classify(
        email_text_for_ml
    )

    # ------------------------------------------------------------
    # 2. URL analysis
    # ------------------------------------------------------------

    url_results = url_analyzer.analyze_urls(
        record.get("urls", []),
        phishing_lookup=phishing_lookup,
    )

    # ------------------------------------------------------------
    # 3. Sender analysis
    # ------------------------------------------------------------

    sender_result = sender_analyzer.analyze_sender(
        record
    )

    # ------------------------------------------------------------
    # 4. Authentication analysis
    # ------------------------------------------------------------

    auth_result = auth_analyzer.analyze_auth(
        record
    )

    # ------------------------------------------------------------
    # 5. GeoIP analysis
    # ------------------------------------------------------------

    geo_results = geoip_analyzer.lookup_ips(
        record.get("public_ips", [])
    )

    # ------------------------------------------------------------
    # 6. Attachment analysis
    # ------------------------------------------------------------

    attachment_results = (
        attachment_analyzer.analyze_attachments(
            record.get("attachments", [])
        )
    )

    # ------------------------------------------------------------
    # 7. Multi-signal correlation
    # ------------------------------------------------------------

    threat = correlate_threat(
        ml_result,
        url_results,
        sender_result,
        auth_result,
        attachment_results,
    )

    # ------------------------------------------------------------
    # 8. Combined result
    # ------------------------------------------------------------

    return {
        "record": record,

        "ml_result": ml_result,

        "url_results": url_results,

        "sender_result": sender_result,

        "auth_result": auth_result,

        "geo_results": geo_results,

        "attachment_results": attachment_results,

        "threat": threat,
    }

