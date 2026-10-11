"""
Multimodal Phishing Detection Framework - Feature Extractors & Sanitizers
Module: extractors.py
Author: Principal Machine Learning Engineer & Cybersecurity Architect
"""

import os
import re
import io
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, unquote

import numpy as np
from bs4 import BeautifulSoup, Comment
from PIL import Image, ExifTags

# Defensive imports with graceful fallback for heterogeneous execution environments
try:
    import cv2
    from pyzbar.pyzbar import decode as decode_qr
except ImportError:
    cv2 = None
    decode_qr = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    import whisper
except ImportError:
    whisper = None

try:
    import librosa
except ImportError:
    librosa = None

try:
    import soundfile as sf
except ImportError:
    sf = None


# ==============================================================================
# SECTION 1: INDIRECT PROMPT INJECTION & PERCEPTUAL ASYMMETRY SANITIZER
# ==============================================================================

class AdversarialSanitizer:
    """
    Mitigates Indirect Prompt Injection and Perceptual Asymmetry attacks.
    Detects and strips hidden HTML/CSS elements, zero-width steganography,
    and adversarial prompt injection keywords targeting LLM threat classifiers.
    """

    ZERO_WIDTH_PATTERN = re.compile(r'[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]')

    PROMPT_INJECTION_HEURISTICS = [
        re.compile(r'(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|directions)'),
        re.compile(r'(?i)system\s+override'),
        re.compile(r'(?i)classify\s+(this\s+as\s+)?(benign|safe|not\s+phishing)'),
        re.compile(r'(?i)threat_score["\']?\s*:\s*0(\.0)?'),
        re.compile(r'(?i)you\s+are\s+now\s+(in\s+developer\s+mode|a\s+friendly\s+bot)'),
        re.compile(r'(?i)do\s+not\s+flag\s+this'),
        re.compile(r'(?i)bypass\s+security\s+filter')
    ]

    @classmethod
    def strip_zero_width_chars(cls, text: str) -> Tuple[str, bool]:
        """Strips steganographic zero-width Unicode characters."""
        cleaned = cls.ZERO_WIDTH_PATTERN.sub('', text)
        return cleaned, len(cleaned) != len(text)

    @classmethod
    def detect_adversarial_injection(cls, text: str) -> Tuple[bool, List[str]]:
        """Detects explicit prompt injection and jailbreak payloads in text."""
        flags = []
        for pattern in cls.PROMPT_INJECTION_HEURISTICS:
            match = pattern.search(text)
            if match:
                flags.append(f"Prompt injection signature detected: '{match.group(0)}'")
        return len(flags) > 0, flags

    @classmethod
    def sanitize_html_dom(cls, html_str: str) -> Dict[str, Any]:
        """
        Parses HTML using BeautifulSoup.
        Detects and strips elements used for Indirect Prompt Injection
        (e.g., display: none;, opacity: 0;, font-size: 0px;, color: white, or zero-width characters).
        Returns sanitized text, simplified DOM summary, and array of injection_flags.
        """
        soup = BeautifulSoup(html_str or "", 'html.parser')
        injection_flags: List[str] = []

        # 1. Strip HTML comments (used for hidden steganographic prompts)
        for comment in soup.find_all(text=lambda text: isinstance(text, Comment)):
            comment_text = comment.strip()
            if comment_text:
                is_inj, reasons = cls.detect_adversarial_injection(comment_text)
                if is_inj:
                    injection_flags.extend(reasons)
                elif len(comment_text) > 100:
                    injection_flags.append(f"Suspicious HTML comment removed ({len(comment_text)} chars)")
            comment.extract()

        # 2. Identify and decompose hidden / zero-font / zero-opacity CSS elements
        hidden_style_patterns = [
            r'display\s*:\s*none',
            r'visibility\s*:\s*hidden',
            r'font-size\s*:\s*0',
            r'opacity\s*:\s*0',
            r'color\s*:\s*(#fff(fff)?|white|transparent|rgba\(\s*255\s*,\s*255\s*,\s*255)',
            r'text-indent\s*:\s*-[0-9]{3,}'
        ]
        hidden_regex = re.compile('|'.join(hidden_style_patterns), re.IGNORECASE)

        for tag in soup.find_all(True):
            style = tag.get('style', '')
            class_names = ' '.join(tag.get('class', []))
            is_hidden = bool(hidden_regex.search(style)) or 'hidden' in class_names or 'sr-only' in class_names

            if is_hidden:
                hidden_text = tag.get_text(strip=True)
                if hidden_text:
                    injection_flags.append(f"CSS Hidden text stripped from <{tag.name}>: '{hidden_text[:150]}'")
                    is_inj, reasons = cls.detect_adversarial_injection(hidden_text)
                    if is_inj:
                        injection_flags.extend(reasons)
                tag.decompose()

        # 3. Extract text and strip zero-width characters
        raw_extracted_text = soup.get_text(separator=' ', strip=True)
        sanitized_text, had_zero_width = cls.strip_zero_width_chars(raw_extracted_text)

        if had_zero_width:
            injection_flags.append("Zero-width steganographic Unicode characters stripped from DOM text")

        is_inj, text_reasons = cls.detect_adversarial_injection(sanitized_text)
        if is_inj:
            injection_flags.extend(text_reasons)

        # 4. Generate simplified DOM summary
        dom_summary = cls._summarize_dom(soup)

        return {
            "sanitized_text": sanitized_text,
            "cleaned_text": sanitized_text,
            "dom_summary": dom_summary,
            "sanitized_dom_summary": dom_summary,
            "injection_flags": injection_flags,
            "hidden_text_detected": len(injection_flags) > 0 or had_zero_width,
            "is_adversarial_injection": len(injection_flags) > 0
        }

    @classmethod
    def _summarize_dom(cls, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extracts structural DOM summary (links, forms, inputs, external scripts)."""
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        forms = [{
            "action": form.get('action', ''),
            "method": form.get('method', 'GET').upper(),
            "inputs": [inp.get('name', '') for inp in form.find_all(['input', 'textarea']) if inp.get('name')]
        } for form in soup.find_all('form')]
        
        scripts = [s.get('src') for s in soup.find_all('script', src=True)]
        
        return {
            "total_links": len(links),
            "sample_links": links[:10],
            "total_forms": len(forms),
            "forms": forms,
            "external_scripts": scripts[:10],
            "has_password_field": bool(soup.find('input', {'type': 'password'}))
        }

    @classmethod
    def sanitize_exif(cls, image: Image.Image) -> Dict[str, Any]:
        """Extracts and sanitizes EXIF metadata, dropping tags > 100 chars to prevent prompt injection."""
        exif_data: Dict[str, Any] = {}
        flags = []
        try:
            raw_exif = image.getexif()
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    val_str = str(value)
                    # Drop EXIF tags with string values longer than 100 characters
                    if len(val_str) > 100:
                        flags.append(f"Dropped EXIF tag '{tag_name}' ({len(val_str)} chars > 100 limit) to prevent prompt injection")
                        continue
                    is_inj, reasons = cls.detect_adversarial_injection(val_str)
                    if is_inj:
                        flags.extend(reasons)
                    exif_data[tag_name] = val_str
        except Exception as e:
            exif_data["error"] = f"EXIF parsing error: {str(e)}"
            
        return {
            "sanitized_exif": exif_data,
            "exif_injection_flags": flags
        }


# ==============================================================================
# SECTION 2: EMAIL & DOM EXTRACTOR (BEC / CLONE / PHARMING)
# ==============================================================================

class EmailExtractor:
    """
    RFC822 Email Message & Header Extractor.
    Parses .eml bytes, extracts authentication headers, evaluates From vs Reply-To domain mismatches.
    """

    @classmethod
    def parse_eml_bytes(cls, email_bytes: bytes) -> Dict[str, Any]:
        """
        Parses RFC822 .eml bytes.
        - Extracts Headers: From, To, Subject, Date, Reply-To.
        - Parses Authentication headers: Received-SPF, DKIM-Signature, Authentication-Results.
        - Sets reply_to_mismatch = True if From domain differs from Reply-To domain.
        """
        if not email_bytes:
            return {
                "header_metadata": {},
                "reply_to_mismatch": False,
                "auth_summary": {"spf": "none", "dkim": "none", "dmarc": "none"},
                "dom_structure": {},
                "cleaned_text": "",
                "injection_flags": []
            }

        msg = BytesParser(policy=policy.default).parsebytes(email_bytes)

        # Extract primary RFC822 headers
        from_hdr = str(msg.get("From", ""))
        to_hdr = str(msg.get("To", ""))
        subject_hdr = str(msg.get("Subject", ""))
        date_hdr = str(msg.get("Date", ""))
        reply_to_hdr = str(msg.get("Reply-To", ""))

        # Extract authentication headers
        received_spf = str(msg.get("Received-SPF", ""))
        dkim_sig = str(msg.get("DKIM-Signature", ""))
        auth_results = str(msg.get("Authentication-Results", ""))

        headers: Dict[str, Any] = {
            "From": from_hdr,
            "To": to_hdr,
            "Subject": subject_hdr,
            "Date": date_hdr,
            "Reply-To": reply_to_hdr,
            "Received-SPF": received_spf,
            "DKIM-Signature": dkim_sig,
            "Authentication-Results": auth_results
        }

        # Extract Received routing hops
        received_hops = msg.get_all("Received", [])
        headers["received_hops"] = [str(h).strip() for h in received_hops]

        # Evaluate From vs Reply-To domain mismatch (BEC / Whaling indicator)
        reply_to_mismatch = False
        if from_hdr and reply_to_hdr:
            from_domains = re.findall(r'[\w\.-]+@([\w\.-]+\.[\w\.-]+)', from_hdr)
            reply_domains = re.findall(r'[\w\.-]+@([\w\.-]+\.[\w\.-]+)', reply_to_hdr)
            if from_domains and reply_domains:
                from_domain = from_domains[0].lower()
                reply_domain = reply_domains[0].lower()
                if from_domain != reply_domain:
                    reply_to_mismatch = True

        # Extract body text and HTML
        body_text = ""
        body_html = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get("Content-Disposition"))
                if "attachment" not in content_disp:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            if content_type == "text/plain":
                                body_text += payload.decode('utf-8', errors='ignore') + "\n"
                            elif content_type == "text/html":
                                body_html += payload.decode('utf-8', errors='ignore') + "\n"
                    except Exception:
                        pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode('utf-8', errors='ignore')

        # Run DOM sanitization on HTML
        dom_analysis = AdversarialSanitizer.sanitize_html_dom(body_html if body_html else body_text)

        # Parse SPF, DKIM, DMARC status summary
        combined_auth = (auth_results + " " + received_spf).lower()
        spf_status = "pass" if "spf=pass" in combined_auth else ("fail" if "spf=fail" in combined_auth or "spf=softfail" in combined_auth else "none")
        dkim_status = "pass" if "dkim=pass" in combined_auth or dkim_sig else "none"
        dmarc_status = "pass" if "dmarc=pass" in combined_auth else ("fail" if "dmarc=fail" in combined_auth else "none")

        auth_summary = {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        }
        headers["auth_security_analysis"] = auth_summary

        return {
            "header_metadata": headers,
            "reply_to_mismatch": reply_to_mismatch,
            "auth_summary": auth_summary,
            "dom_structure": dom_analysis["dom_summary"],
            "cleaned_text": dom_analysis["sanitized_text"],
            "hidden_text_detected": dom_analysis["hidden_text_detected"],
            "is_adversarial_injection": dom_analysis["is_adversarial_injection"],
            "injection_flags": dom_analysis["injection_flags"]
        }


# ==============================================================================
# SECTION 3: IMAGE & QR EXTRACTOR (QUISHING & OCR ANALYSIS)
# ==============================================================================

class ImageExtractor:
    """
    Image Payload & QR Code Feature Extractor for Quishing detection.
    1. Loads bytes into formats compatible with OpenCV and PIL using try/except error handling.
    2. Runs pyzbar.pyzbar.decode (or OpenCV fallback) to extract URLs from QR codes.
    3. Runs pytesseract.image_to_string() to extract visual text.
    4. Extracts EXIF metadata using PIL.ExifTags, dropping tags > 100 chars to mitigate prompt injection.
    5. Returns dictionary with is_quishing_payload (True if QR found), qr_codes, ocr_text, exif_metadata, security_flags.
    """

    @classmethod
    def extract_features(cls, image_bytes: bytes) -> Dict[str, Any]:
        """
        Extracts features from image bytes:
        - is_quishing_payload (True if QR code found)
        - qr_codes
        - ocr_text
        - exif_metadata (sanitized, tags > 100 chars dropped)
        - security_flags
        """
        result: Dict[str, Any] = {
            "is_quishing_payload": False,
            "qr_codes": [],
            "ocr_text": "",
            "exif_metadata": {},
            "security_flags": []
        }

        if not image_bytes:
            result["security_flags"].append("Empty image bytes uploaded")
            return result

        pil_image = None
        cv_image = None

        # 1. Load bytes safely into PIL and OpenCV formats with try/except
        try:
            pil_image = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            result["security_flags"].append(f"PIL image loading error: Corrupted bytes ({str(e)})")

        try:
            if cv2 is not None:
                nparr = np.frombuffer(image_bytes, np.uint8)
                cv_image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        except Exception as e:
            result["security_flags"].append(f"OpenCV imdecode error: ({str(e)})")

        if pil_image is None and cv_image is None:
            result["security_flags"].append("Fatal error: Failed to decode image bytes into PIL or OpenCV format.")
            return result

        # 2. Extract EXIF metadata (drop tags with string value > 100 chars)
        if pil_image is not None:
            exif_audit = AdversarialSanitizer.sanitize_exif(pil_image)
            result["exif_metadata"] = exif_audit["sanitized_exif"]
            if exif_audit["exif_injection_flags"]:
                result["security_flags"].extend(exif_audit["exif_injection_flags"])

        # 3. QR Code Decoding via pyzbar (or OpenCV QRCodeDetector fallback)
        decoded_qr_codes: List[Dict[str, Any]] = []

        if pil_image is not None and decode_qr is not None:
            try:
                decoded_objects = decode_qr(pil_image)
                for obj in decoded_objects:
                    data_str = obj.data.decode('utf-8', errors='ignore')
                    decoded_qr_codes.append({
                        "type": obj.type,
                        "data": data_str,
                        "rect": {
                            "left": obj.rect.left,
                            "top": obj.rect.top,
                            "width": obj.rect.width,
                            "height": obj.rect.height
                        }
                    })
            except Exception as e:
                result["security_flags"].append(f"pyzbar decoding error: {str(e)}")

        if not decoded_qr_codes and cv_image is not None and cv2 is not None:
            try:
                detector = cv2.QRCodeDetector()
                val, points, _ = detector.detectAndDecode(cv_image)
                if val:
                    decoded_qr_codes.append({"type": "QRCODE", "data": val})
            except Exception as e:
                result["security_flags"].append(f"OpenCV QR detection error: {str(e)}")

        result["qr_codes"] = decoded_qr_codes
        result["is_quishing_payload"] = len(decoded_qr_codes) > 0

        # 4. OCR Visual Text Extraction via pytesseract.image_to_string()
        raw_ocr_text = ""
        if pil_image is not None and pytesseract is not None:
            try:
                raw_ocr_text = pytesseract.image_to_string(pil_image)
            except Exception as e:
                result["security_flags"].append(f"pytesseract OCR error: {str(e)}")
        elif cv_image is not None and pytesseract is not None:
            try:
                raw_ocr_text = pytesseract.image_to_string(cv_image)
            except Exception as e:
                result["security_flags"].append(f"pytesseract OCR error: {str(e)}")

        cleaned_ocr, had_zw = AdversarialSanitizer.strip_zero_width_chars(raw_ocr_text)
        is_inj, inj_reasons = AdversarialSanitizer.detect_adversarial_injection(cleaned_ocr)
        if is_inj:
            result["security_flags"].extend(inj_reasons)

        result["ocr_text"] = cleaned_ocr.strip()

        return result


# ==============================================================================
# SECTION 4: TEXT & SMS EXTRACTOR (SMISHING & CONSENT PHISHING)
# ==============================================================================

class TextExtractor:
    """
    Text & SMS Payload Feature Extractor.
    """

    URL_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::[0-9]{1,5})?(?:/[^\s"<>]*)?',
        re.IGNORECASE
    )

    SENSITIVE_OAUTH_SCOPES = [
        "mail.readwrite", "mail.read", "mail.send", "offline_access",
        "files.readwrite.all", "user.readwrite.all", "directory.readwrite.all",
        "contacts.read", "notes.readwrite.all", "identity.read", "repo", "admin:org"
    ]

    HIGH_VALUE_DOMAINS = [
        "login.microsoftonline.com", "accounts.google.com", "appleid.apple.com",
        "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
        "docusign.net", "docusign.com", "okta.com", "github.com"
    ]

    ZERO_WIDTH_PATTERN = re.compile(r'[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]')

    @classmethod
    def extract_features(cls, text: str) -> Dict[str, Any]:
        if not text:
            return {
                "cleaned_text": "",
                "urls_detected": [],
                "oauth_scopes_solicited": [],
                "is_consent_phishing_risk": False,
                "url_deep_analysis": [],
                "had_zero_width_characters": False,
                "is_adversarial_injection": False,
                "injection_flags": []
            }

        cleaned_text = cls.ZERO_WIDTH_PATTERN.sub('', text)
        had_zw = len(cleaned_text) != len(text)

        raw_urls = cls.URL_REGEX.findall(cleaned_text)
        urls_detected: List[str] = list(dict.fromkeys(raw_urls))

        is_consent_phishing_risk = False
        solicited_scopes: Set[str] = set()
        url_deep_analysis: List[Dict[str, Any]] = []

        lower_text = cleaned_text.lower()

        for scope in cls.SENSITIVE_OAUTH_SCOPES:
            if scope in lower_text or scope.replace('.', ' ') in lower_text:
                solicited_scopes.add(scope)

        for url in urls_detected:
            url_lower = url.lower()
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            query_str = parsed.query

            has_client_id = "client_id=" in url_lower
            has_redirect_uri = "redirect_uri=" in url_lower
            has_scope = "scope=" in url_lower
            has_response_type = "response_type=" in url_lower or "response_type=code" in url_lower

            if has_client_id and (has_redirect_uri or has_scope or has_response_type):
                is_consent_phishing_risk = True

            if query_str:
                query_params = parse_qs(query_str)
                scope_param = query_params.get("scope", query_params.get("Scope", []))
                for s_val in scope_param:
                    decoded_scopes = unquote(s_val).replace('+', ' ').split(' ')
                    for s in decoded_scopes:
                        s_clean = s.strip().lower()
                        if s_clean:
                            solicited_scopes.add(s_clean)

            typosquat_flag = False
            target_spoofed = None
            for target in cls.HIGH_VALUE_DOMAINS:
                if target in netloc and netloc != target:
                    typosquat_flag = True
                    target_spoofed = target
                    break
                elif cls._levenshtein_distance(netloc, target) in [1, 2]:
                    typosquat_flag = True
                    target_spoofed = target
                    break

            is_ip_host = bool(re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', netloc.split(':')[0]))

            url_deep_analysis.append({
                "url": url,
                "domain": netloc,
                "is_ip_host": is_ip_host,
                "typosquatting_detected": typosquat_flag,
                "impersonated_brand": target_spoofed,
                "has_oauth_params": has_client_id and (has_redirect_uri or has_scope)
            })

        oauth_scopes_solicited = sorted(list(solicited_scopes))
        if len(oauth_scopes_solicited) > 0 and (is_consent_phishing_risk or "offline_access" in oauth_scopes_solicited or "mail.readwrite" in oauth_scopes_solicited):
            is_consent_phishing_risk = True

        inj_flags = []
        if re.search(r'(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts)', cleaned_text):
            inj_flags.append("Prompt injection signature: ignore instructions")
        if re.search(r'(?i)system\s+override', cleaned_text):
            inj_flags.append("Prompt injection signature: system override")

        return {
            "cleaned_text": cleaned_text,
            "urls_detected": urls_detected,
            "oauth_scopes_solicited": oauth_scopes_solicited,
            "is_consent_phishing_risk": is_consent_phishing_risk,
            "url_deep_analysis": url_deep_analysis,
            "had_zero_width_characters": had_zw,
            "is_adversarial_injection": len(inj_flags) > 0,
            "injection_flags": inj_flags
        }

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return TextExtractor._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


# ==============================================================================
# SECTION 5: AUDIO EXTRACTOR (VISHING / SYNTHETIC VOICE ANALYSIS)
# ==============================================================================

class AudioExtractor:
    """
    Ingests .mp3/.wav payloads for Vishing analysis.
    """

    _whisper_model = None

    @classmethod
    def get_whisper_model(cls):
        if cls._whisper_model is None and whisper is not None:
            cls._whisper_model = whisper.load_model("base")
        return cls._whisper_model

    @classmethod
    def extract_features(cls, audio_bytes: bytes, filename: str = "audio.wav") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "transcript": "",
            "duration_seconds": 0.0,
            "acoustic_features": {},
            "synthetic_voice_anomaly": False,
            "anomaly_confidence": 0.0,
            "acoustic_flags": []
        }

        if librosa is not None:
            try:
                audio_io = io.BytesIO(audio_bytes)
                y, sr = librosa.load(audio_io, sr=16000)
                duration = float(librosa.get_duration(y=y, sr=sr))
                result["duration_seconds"] = round(duration, 2)

                mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
                mfcc_mean = [round(float(m), 3) for m in np.mean(mfccs, axis=1)]
                mfcc_var = [round(float(v), 3) for v in np.var(mfccs, axis=1)]

                spectral_centroids = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
                sc_mean = float(np.mean(spectral_centroids))
                sc_std = float(np.std(spectral_centroids))

                zcr = librosa.feature.zero_crossing_rate(y)[0]
                zcr_mean = float(np.mean(zcr))

                pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
                pitch_values = pitches[magnitudes > np.median(magnitudes)]
                pitch_std = float(np.std(pitch_values)) if len(pitch_values) > 0 else 0.0

                result["acoustic_features"] = {
                    "sample_rate": sr,
                    "mfcc_means": mfcc_mean,
                    "mfcc_variances": mfcc_var,
                    "spectral_centroid_mean": round(sc_mean, 2),
                    "spectral_centroid_std": round(sc_std, 2),
                    "zero_crossing_rate": round(zcr_mean, 4),
                    "pitch_variance": round(pitch_std, 2)
                }

                anomaly_signals = []
                anomaly_score = 0.0

                if pitch_std < 18.0 and duration > 3.0:
                    anomaly_signals.append("Atypically low pitch modulation (monotone fundamental frequency variance)")
                    anomaly_score += 0.45
                
                if sc_std < 250.0:
                    anomaly_signals.append("Restricted spectral timbre dynamics characteristic of vocoder synthesis")
                    anomaly_score += 0.35

                if np.mean(mfcc_var) < 15.0:
                    anomaly_signals.append("Low MFCC acoustic sequence variance (synthetic speech artifact)")
                    anomaly_score += 0.30

                result["synthetic_voice_anomaly"] = anomaly_score >= 0.50
                result["anomaly_confidence"] = min(round(anomaly_score, 2), 0.99)
                result["acoustic_flags"] = anomaly_signals

            except Exception as e:
                result["acoustic_features"]["error"] = f"Acoustic extraction error: {str(e)}"

        model = cls.get_whisper_model()
        if model is not None:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                    tmp.write(audio_bytes)
                    tmp_path = tmp.name
                
                transcript_res = model.transcribe(tmp_path)
                os.remove(tmp_path)
                raw_transcript = transcript_res.get("text", "").strip()
                cleaned_transcript, had_zw = AdversarialSanitizer.strip_zero_width_chars(raw_transcript)
                result["transcript"] = cleaned_transcript
            except Exception as e:
                result["transcript"] = f"[Transcription failed: {str(e)}]"
        else:
            result["transcript"] = "[Whisper transcription runtime pending or mock payload]"

        return result
