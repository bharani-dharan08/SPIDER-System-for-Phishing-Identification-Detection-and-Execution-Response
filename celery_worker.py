"""
Multimodal Phishing Detection Framework - Asynchronous Celery Worker
Handles distributed execution of computationally intensive Whisper transcription & Librosa/CV extraction tasks.
"""

import os
from celery import Celery
from extractors import AudioExtractor, ImageExtractor

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "phishing_detection_worker",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

@celery_app.task(name="tasks.process_audio_vishing", bind=True)
def process_audio_task(self, audio_bytes_hex: str, filename: str):
    """Asynchronous background task for heavy Whisper transcription & librosa MFCC extraction."""
    audio_bytes = bytes.fromhex(audio_bytes_hex)
    features = AudioExtractor.extract_features(audio_bytes, filename=filename)
    return features

@celery_app.task(name="tasks.process_image_quishing", bind=True)
def process_image_task(self, image_bytes_hex: str):
    """Asynchronous background task for QR code matrix decoding and OCR text extraction."""
    image_bytes = bytes.fromhex(image_bytes_hex)
    features = ImageExtractor.extract_features(image_bytes)
    return features
