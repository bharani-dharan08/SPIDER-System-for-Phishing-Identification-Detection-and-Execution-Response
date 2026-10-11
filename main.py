"""
Multimodal Phishing Detection Framework - FastAPI Asynchronous Backend
Exposes modular ingestion endpoints for Audio, Images/QR, Emails, and Text.
Orchestrates Late-Fusion Threat Analysis with Indirect Prompt Injection defenses.
"""

import os
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from extractors import (
    AudioExtractor,
    ImageExtractor,
    EmailExtractor,
    TextExtractor,
    AdversarialSanitizer
)
from analyzer import PhishingThreatAnalyzer, PhishingAnalysisResult

# Optional Celery dispatch for background queue
try:
    from celery_worker import process_audio_task, process_image_task
    CELERY_AVAILABLE = True
except Exception:
    CELERY_AVAILABLE = False


from rate_limiter import APIRateLimiterMiddleware

app = FastAPI(
    title="Multimodal Phishing Detection API",
    description="Late-fusion threat intelligence framework evaluating Spear/Whaling, Quishing, Vishing, BEC, Clone, and Consent Phishing.",
    version="2.0.0"
)

# Configurable Rate Limiting Parameters
RATE_LIMIT_GLOBAL_MAX = int(os.environ.get("RATE_LIMIT_GLOBAL_MAX", "100"))
RATE_LIMIT_ANALYSIS_MAX = int(os.environ.get("RATE_LIMIT_ANALYSIS_MAX", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Attach API Rate Limiter Middleware to protect engine from exhaustion attacks
app.add_middleware(
    APIRateLimiterMiddleware,
    global_max_requests=RATE_LIMIT_GLOBAL_MAX,
    analysis_max_requests=RATE_LIMIT_ANALYSIS_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global analyzer instance
analyzer_engine = PhishingThreatAnalyzer(
    provider=os.environ.get("LLM_PROVIDER", "openai"),
    model_name=os.environ.get("LLM_MODEL", "gpt-4o")
)


# ==============================================================================
# PYDANTIC DATA TRANSFER OBJECTS (REQUESTS & RESPONSES)
# ==============================================================================

class TextPayloadRequest(BaseModel):
    text: str = Field(..., description="Raw SMS, chat message, or phishing text string")
    channel: Optional[str] = Field("sms", description="Source channel: sms, angler, social_media, chat")

class LateFusionAnalysisRequest(BaseModel):
    transcript: Optional[str] = Field(None, description="[TRANSCRIPT] speech-to-text string")
    decoded_urls: Optional[List[Dict[str, Any]]] = Field(None, description="[DECODED_URLS] decoded QR or parsed links")
    ocr_text: Optional[str] = Field(None, description="[OCR_TEXT] extracted visual text")
    dom_structure: Optional[Dict[str, Any]] = Field(None, description="[DOM_STRUCTURE] parsed DOM summary")
    header_metadata: Optional[Dict[str, Any]] = Field(None, description="[HEADER_METADATA] parsed email headers")
    sanitization_alerts: Optional[List[str]] = Field(None, description="Pre-filtering security sanitization flags")


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@app.get("/health")
async def health_check():
    return {
        "status": "operational",
        "service": "Multimodal Phishing Detection Engine",
        "celery_connected": CELERY_AVAILABLE,
        "llm_provider": analyzer_engine.provider,
        "model": analyzer_engine.model_name,
        "rate_limiting": {
            "active": True,
            "global_max_rpm": RATE_LIMIT_GLOBAL_MAX,
            "analysis_max_rpm": RATE_LIMIT_ANALYSIS_MAX,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "protection_status": "ENABLED - SPIDER Engine Exhaustion Guard Active"
        }
    }


@app.get("/api/rate-limit/status")
async def rate_limit_status():
    return {
        "status": "active",
        "middleware": "APIRateLimiterMiddleware",
        "limits": {
            "global_max_requests_per_window": RATE_LIMIT_GLOBAL_MAX,
            "analysis_max_requests_per_window": RATE_LIMIT_ANALYSIS_MAX,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS
        },
        "protected_endpoints": [
            "/api/analyze/spider-engine",
            "/api/analyze/late-fusion",
            "/api/upload/audio",
            "/api/upload/image",
            "/api/upload/email",
            "/api/upload/text"
        ],
        "headers_returned": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-RateLimit-Protection",
            "Retry-After (on 429)"
        ]
    }


@app.post("/api/upload/audio")
async def upload_audio_endpoint(
    file: UploadFile = File(..., description="Audio file (.mp3 or .wav)"),
    use_celery: bool = Form(False)
):
    """
    Audio (Vishing) Ingestion:
    Accepts .mp3/.wav.
    Extracts Whisper STT transcript and librosa acoustic MFCC feature sequence.
    Detects synthetic voice vocoder anomalies.
    """
    filename = file.filename or "recording.wav"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".mp3", ".wav", ".ogg", ".flac", ".m4a"]:
        raise HTTPException(status_code=400, detail=f"Unsupported audio format '{ext}'. Expected .mp3 or .wav.")

    audio_bytes = await file.read()
    if len(audio_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty audio payload uploaded.")

    # Celery async dispatch path if requested and broker configured
    if use_celery and CELERY_AVAILABLE:
        task = process_audio_task.delay(audio_bytes.hex(), filename)
        return {
            "status": "queued",
            "task_id": task.id,
            "filename": filename,
            "message": "Audio transcription and acoustic feature extraction dispatched to Celery cluster."
        }

    # Synchronous late-fusion extraction
    extracted = AudioExtractor.extract_features(audio_bytes, filename=filename)
    return {
        "status": "success",
        "filename": filename,
        "duration_seconds": extracted["duration_seconds"],
        "transcript": extracted["transcript"],
        "synthetic_voice_anomaly": extracted["synthetic_voice_anomaly"],
        "anomaly_confidence": extracted["anomaly_confidence"],
        "acoustic_flags": extracted["acoustic_flags"],
        "acoustic_features": extracted["acoustic_features"]
    }


@app.post("/api/upload/image")
async def upload_image_endpoint(
    file: UploadFile = File(..., description="Image file (.png or .jpg)"),
    use_celery: bool = Form(False)
):
    """
    Images/QR (Quishing) Ingestion:
    Accepts .png/.jpg.
    Decodes QR codes using OpenCV/pyzbar.
    Extracts overlaid text with pytesseract OCR.
    Sanitizes EXIF metadata to prevent metadata prompt injection.
    """
    filename = file.filename or "image.png"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".png", ".jpg", ".jpeg", ".webp"]:
        raise HTTPException(status_code=400, detail=f"Unsupported image format '{ext}'. Expected .png or .jpg.")

    image_bytes = await file.read()
    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty image payload uploaded.")

    if use_celery and CELERY_AVAILABLE:
        task = process_image_task.delay(image_bytes.hex())
        return {
            "status": "queued",
            "task_id": task.id,
            "filename": filename,
            "message": "QR decoding and OCR extraction dispatched to Celery cluster."
        }

    extracted = ImageExtractor.extract_features(image_bytes)
    return {
        "status": "success",
        "filename": filename,
        "is_quishing_payload": extracted["is_quishing_payload"],
        "qr_codes": extracted["qr_codes"],
        "ocr_text": extracted["ocr_text"],
        "exif_metadata": extracted["exif_metadata"],
        "security_flags": extracted["security_flags"]
    }


@app.post("/api/upload/email")
async def upload_email_endpoint(
    file: UploadFile = File(..., description="Email file (.eml, .msg, or .html)")
):
    """
    Email & HTML (BEC / Clone / Pharming) Ingestion:
    Parses RFC822 headers (SPF/DKIM/DMARC, Received routing path).
    Detects 'Reply-To' mismatches (executive spoofing / whaling).
    Sanitizes DOM trees to eliminate indirect prompt injection (white-text/zero-font jailbreaks).
    """
    filename = file.filename or "message.eml"
    ext = os.path.splitext(filename)[1].lower()
    email_bytes = await file.read()

    if ext in [".html", ".htm"]:
        # Direct raw HTML payload
        html_str = email_bytes.decode('utf-8', errors='ignore')
        sanitized = AdversarialSanitizer.sanitize_html_dom(html_str)
        return {
            "status": "success",
            "filename": filename,
            "header_metadata": {"Subject": "[RAW HTML PAYLOAD]"},
            "reply_to_mismatch": False,
            "dom_structure": sanitized["sanitized_dom_summary"],
            "cleaned_text": sanitized["cleaned_text"],
            "hidden_text_detected": sanitized["hidden_text_detected"],
            "hidden_payloads": sanitized["hidden_payloads"],
            "is_adversarial_injection": sanitized["is_adversarial_injection"],
            "injection_flags": sanitized["injection_flags"]
        }
    else:
        # Standard .eml/.msg RFC parsing
        extracted = EmailExtractor.parse_eml_bytes(email_bytes)
        return {
            "status": "success",
            "filename": filename,
            "header_metadata": extracted["header_metadata"],
            "reply_to_mismatch": extracted["reply_to_mismatch"],
            "auth_summary": extracted["auth_summary"],
            "dom_structure": extracted["dom_structure"],
            "cleaned_text": extracted["cleaned_text"],
            "hidden_text_detected": extracted["hidden_text_detected"],
            "hidden_payloads": extracted["hidden_payloads"],
            "is_adversarial_injection": extracted["is_adversarial_injection"],
            "injection_flags": extracted["injection_flags"]
        }


@app.post("/api/upload/text")
async def upload_text_endpoint(payload: TextPayloadRequest):
    """
    Text & SMS (Smishing / Angler) Ingestion:
    Extracts URLs using RFC regex.
    Performs domain typosquatting & Levenshtein lookalike brand matching.
    Detects Consent Phishing OAuth scope solicitation.
    Filters zero-width characters and prompt injection signatures.
    """
    extracted = TextExtractor.extract_features(payload.text)
    return {
        "status": "success",
        "channel": payload.channel,
        "cleaned_text": extracted["cleaned_text"],
        "urls_detected": extracted["urls_detected"],
        "url_deep_analysis": extracted["url_deep_analysis"],
        "oauth_scopes_solicited": extracted["oauth_scopes_solicited"],
        "is_consent_phishing_risk": extracted["is_consent_phishing_risk"],
        "had_zero_width_characters": extracted["had_zero_width_characters"],
        "is_adversarial_injection": extracted["is_adversarial_injection"],
        "injection_flags": extracted["injection_flags"]
    }


from spider_detection_engine import SPIDERThreatEngine, AggregateThreatVerdict

spider_engine_instance = SPIDERThreatEngine()

class SpiderAnalysisRequest(BaseModel):
    url: Optional[str] = Field(None, description="Target website or form URL to analyze")
    html_content: Optional[str] = Field(None, description="Raw HTML or form DOM content")
    headers: Optional[Dict[str, str]] = Field(None, description="HTTP request or proxy headers")
    additional_iocs: Optional[List[str]] = Field(None, description="Existing IOCs collected from other modalities")


@app.post("/api/analyze/spider-engine", response_model=AggregateThreatVerdict)
async def spider_engine_endpoint(request: SpiderAnalysisRequest):
    """
    SPIDER Vector A & Vector B Engine:
    Executes Weaponized Form Smuggling Detection (Vector A)
    and Real-Time Website URL Phishing Identification (Vector B).
    Computes Aggregate Threat Score (0.0 - 10.0) and Automated Response Rules.
    """
    verdict = spider_engine_instance.evaluate_payload(
        url=request.url,
        html_content=request.html_content,
        headers=request.headers,
        additional_iocs=request.additional_iocs
    )
    return verdict


@app.post("/api/analyze/late-fusion", response_model=PhishingAnalysisResult)
async def late_fusion_analysis_endpoint(request: LateFusionAnalysisRequest):
    """
    Late Fusion Threat Intelligence Engine:
    Ingests multimodal evidence blocks:
    [TRANSCRIPT], [DECODED_URLS], [OCR_TEXT], [DOM_STRUCTURE], [HEADER_METADATA].
    Executes Threat Intelligence prompt with anti-prompt-injection defense.
    Returns strictly formatted JSON response.
    """
    fused_dict = request.model_dump()
    result = await analyzer_engine.analyze_async(fused_dict)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

