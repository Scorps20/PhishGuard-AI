"""PhishGuard AI web server (FastAPI).

Run from the project folder (after building the interface once, see README):
    python -m uvicorn api:app --port 8000

It serves the React interface from web/dist and two JSON endpoints:
    GET  /api/meta     thresholds, model date, test results and example messages
    POST /api/analyse  analyse one email or SMS

The server only analyses the text it is sent. It never opens links, never
calls external services and does not store or log message content.
"""

import json
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src import config
from src.analysis import CHANNEL_EMAIL, AnalysisResult, analyse_message
from src.phishing_detector import ModelNotFoundError, PhishingDetector
from src.risk_assessment import (
    REASON_BORDERLINE,
    REASON_INDICATORS,
    REASON_MEDIUM_BAND,
    format_score,
    format_threshold,
)

MAX_CHARS = {"email": 20000, "sms": 2000}
MAX_SUBJECT_CHARS = 500

app = FastAPI(title="PhishGuard AI", docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json")


class AnalyseRequest(BaseModel):
    channel: Literal["email", "sms"]
    message: str = Field(default="", max_length=MAX_CHARS["email"])
    subject: str | None = Field(default=None, max_length=MAX_SUBJECT_CHARS)


# ---------------------------------------------------------------- model loading
_detector: PhishingDetector | None = None


def get_detector() -> PhishingDetector:
    """Load the trained model once and reuse it for every request."""
    global _detector
    if _detector is None:
        try:
            _detector = PhishingDetector(config.MODEL_PATH, config.THRESHOLDS_PATH)
        except ModelNotFoundError as error:
            raise HTTPException(status_code=503, detail={
                "message": "The trained model was not found, so messages cannot be analysed yet.",
                "instructions": str(error),
            }) from error
        except Exception as error:  # e.g. a model saved with a different scikit-learn version
            raise HTTPException(status_code=503, detail={
                "message": "The model file exists but could not be loaded.",
                "instructions": "Re-create it with: python train_model.py "
                                "(using the versions in requirements.txt)",
            }) from error
    return _detector


def reset_detector():
    """Forget the loaded model (used by the tests)."""
    global _detector
    _detector = None


# ---------------------------------------------------------------- turning results into JSON
def verdict_for(result: AnalysisResult) -> dict:
    """The verdict headline and its caption, chosen by why the risk is what it is."""
    prediction, risk = result.prediction, result.risk
    if prediction.is_phishing:
        return {"title": "Potential phishing",
                "caption": "The classifier labelled this message as phishing."}
    if risk.uncertainty_reason == REASON_BORDERLINE:
        return {"title": "Legitimate (borderline)",
                "caption": "Classified as legitimate, but the score is just below the phishing threshold."}
    if risk.uncertainty_reason == REASON_MEDIUM_BAND:
        return {"title": "Legitimate (use caution)",
                "caption": "Not classified as phishing, but the score is in the Medium-risk range."}
    if risk.uncertainty_reason == REASON_INDICATORS:
        return {"title": "Legitimate",
                "caption": "The model found little evidence of phishing, but link or phrase warnings "
                           "raised the risk level."}
    return {"title": "Likely legitimate",
            "caption": "The classifier did not find enough evidence of phishing."}


def thresholds_json(detector: PhishingDetector) -> dict:
    t = detector.thresholds
    return {
        "classification": t["classification_threshold"],
        "medium": t["medium_threshold"],
        "high": t["high_threshold"],
        "display": {key: format_threshold(t[name]) for key, name in [
            ("classification", "classification_threshold"),
            ("medium", "medium_threshold"),
            ("high", "high_threshold"),
        ]},
        "source": detector.thresholds_source,
    }


def result_json(result: AnalysisResult) -> dict:
    prediction, risk = result.prediction, result.risk
    return {
        "channel": result.channel,
        "verdict": verdict_for(result),
        "prediction": {
            "label": prediction.label,
            "is_phishing": prediction.is_phishing,
            "score": prediction.phishing_score,
            "score_display": format_score(prediction.phishing_score),
            "threshold": prediction.classification_threshold,
        },
        "risk": {
            "level": risk.level,
            "model_level": risk.model_level,
            "raised_by_indicators": risk.raised_by_indicators,
            "situation": risk.situation,
            "uncertainty_reason": risk.uncertainty_reason,
            "explanation": risk.explanation,
            "recommendations": risk.recommendations,
        },
        "phrases": [{
            "phrase": m.phrase,
            "matched_text": m.matched_text,
            "category": m.category,
            "description": m.description,
            "count": len(m.spans),
        } for m in result.phrase_matches],
        "urls": [{
            "url": r.url,
            "hostname": r.hostname,
            "warnings": r.warnings,
        } for r in result.url_reports],
        "segments": result.segments,
    }


def load_test_results() -> dict | None:
    if not config.EVALUATION_REPORT_PATH.exists():
        return None
    with open(config.EVALUATION_REPORT_PATH, encoding="utf-8") as file:
        test = json.load(file)["splits"]["test"]
    return {group: {k: m[k] for k in ("messages", "phishing_messages", "precision", "recall", "f1")}
            for group, m in test.items()}


# ---------------------------------------------------------------- endpoints
@app.get("/api/meta")
def meta():
    detector = get_detector()
    return {
        "thresholds": thresholds_json(detector),
        "trained_at": detector.thresholds.get("trained_at"),
        "test_results": load_test_results(),
        "examples": config.load_json(config.EXAMPLES_PATH)["examples"],
        "limits": {"email": MAX_CHARS["email"], "sms": MAX_CHARS["sms"], "subject": MAX_SUBJECT_CHARS},
    }


@app.post("/api/analyse")
def analyse(request: AnalyseRequest):
    detector = get_detector()
    subject = request.subject if request.channel == CHANNEL_EMAIL else None
    if len(request.message) > MAX_CHARS[request.channel]:
        raise HTTPException(status_code=422, detail={
            "message": f"The message is too long. The limit is {MAX_CHARS[request.channel]:,} "
                       f"characters for {request.channel.upper() if request.channel == 'sms' else 'an email'}."})
    full_text = f"{subject or ''} {request.message}"
    if not full_text.strip():
        raise HTTPException(status_code=422, detail={
            "message": "Please paste a message to analyse. The text box is empty."})
    if not any(char.isalpha() for char in full_text):
        raise HTTPException(status_code=422, detail={
            "message": "The message contains no words. Please paste the actual text of the email or SMS."})
    try:
        result = analyse_message(detector, request.channel, request.message, subject)
    except ValueError as error:
        raise HTTPException(status_code=422, detail={"message": str(error)}) from error
    return result_json(result)


# ---------------------------------------------------------------- the interface
if config.WEB_DIST_DIR.exists():
    app.mount("/", StaticFiles(directory=config.WEB_DIST_DIR, html=True), name="web")
else:
    @app.get("/", response_class=HTMLResponse)
    def interface_not_built():
        return ("<h1>PhishGuard AI</h1><p>The interface has not been built yet. In the project "
                "folder run:</p><pre>cd web\nnpm install\nnpm run build</pre><p>then restart this server. "
                "The API is already running at <code>/api/meta</code>.</p>")
