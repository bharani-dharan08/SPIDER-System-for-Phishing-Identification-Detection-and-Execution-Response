FROM python:3.11-slim

# Install system dependencies for OpenCV, Tesseract OCR, ZBar QR decoding, and librosa audio
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libzbar0 \
    tesseract-ocr \
    ffmpeg \
    libsndfile1 \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 8501

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
