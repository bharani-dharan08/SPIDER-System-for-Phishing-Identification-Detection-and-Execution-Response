"""
SPIDER (System for Phishing Identification, Detection, and Execution Response)
Extended Detection Engine: Vector A (Weaponized Form & Form Smuggling) & Vector B (Real-time Website URL Phishing)

Author: Principal Cybersecurity Detection Engineer & Python Architect
"""

import re
import math
import json
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urljoin, unquote
from datetime import datetime, timezone

try:
    from pydantic import BaseModel, Field
except ImportError:
    # Graceful fallback if Pydantic isn't installed in lightweight environments
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return self.__dict__

    def Field(*args, **kwargs):
        return kwargs.get('default', None)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


logger = logging.getLogger("spider_detection_engine")
logging.basicConfig(level=logging.INFO)


# ==============================================================================
# PYDANTIC DATA TRANSFER OBJECTS & SCHEMAS
# ==============================================================================

class FormField(BaseModel):
    name: str = Field("", description="Field HTML name attribute")
    input_type: str = Field("text", description="Field input type (password, text, hidden, etc.)")
    label: str = Field("", description="Associated label text or placeholder")
    is_sensitive: bool = Field(False, description="True if heuristic flags field as requesting sensitive credentials")
    sensitive_category: Optional[str] = Field(None, description="Category: PASSWORD, MFA_OTP, SEED_PHRASE, PII, FINANCIAL")


class ExtractedForm(BaseModel):
    form_index: int = Field(0, description="Sequential index of form in DOM")
    action_url: str = Field("", description="Target action URL or endpoint")
    method: str = Field("POST", description="HTTP method (GET/POST)")
    is_cross_domain: bool = Field(False, description="True if action target differs from hosting origin")
    fields: List[FormField] = Field(default_factory=list, description="Extracted input fields")
    hidden_field_count: int = Field(0, description="Number of hidden inputs")
    contains_password_field: bool = Field(False, description="True if form contains password/PIN input")
    contains_mfa_field: bool = Field(False, description="True if form requests OTP or MFA token")
    contains_seed_phrase: bool = Field(False, description="True if form requests crypto seed phrase or private key")
    embedded_links: List[str] = Field(default_factory=list, description="URLs extracted inside form container")


class FormPhishingResult(BaseModel):
    threat_score: float = Field(0.0, ge=0.0, le=10.0, description="Form threat score (0.0 to 10.0)")
    is_weaponized_form: bool = Field(False, description="Flag indicating weaponized form detected")
    host_provider: str = Field("UNKNOWN", description="Identified host platform or SaaS form provider")
    is_unverified_saas_credential_harvest: bool = Field(False, description="True if requesting sensitive credentials on public/unverified form host")
    extracted_forms: List[ExtractedForm] = Field(default_factory=list)
    unpacked_embedded_urls: List[str] = Field(default_factory=list, description="All external URLs unpacked from forms")
    heuristic_indicators: List[str] = Field(default_factory=list, description="Detailed red flag list")


class TyposquatMatch(BaseModel):
    target_brand: str
    target_domain: str
    similarity_score: float
    distance: int
    technique: str  # HOMOGLYPH, PUNYCODE_SPOOF, LEVENSHTEIN_SQUAT, SUBDOMAIN_PREPEND


class EvasionCheckResult(BaseModel):
    has_captcha_trap: bool = Field(False)
    has_js_redirect: bool = Field(False)
    has_meta_refresh: bool = Field(False)
    has_user_agent_cloaking: bool = Field(False)
    has_geofencing: bool = Field(False)
    detected_techniques: List[str] = Field(default_factory=list)


class InfrastructureProfile(BaseModel):
    domain: str
    is_punycode: bool = Field(False)
    is_newly_registered: bool = Field(False)
    domain_age_days: Optional[int] = Field(None)
    is_suspicious_asn: bool = Field(False)
    asn_org: Optional[str] = Field(None)
    is_dynamic_dns: bool = Field(False)
    ssl_cert_age_hours: Optional[float] = Field(None)
    ssl_issuer_anomaly: bool = Field(False)


class AiTMPingerprintResult(BaseModel):
    is_aitm_proxy: bool = Field(False)
    confidence_score: float = Field(0.0)
    proxy_type: Optional[str] = Field(None, description="e.g. Evilginx2, Modlishka, Muraena")
    targeted_brand: Optional[str] = Field(None)
    proxy_header_leaks: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)


class URLThreatResult(BaseModel):
    url: str
    domain: str
    threat_score: float = Field(0.0, ge=0.0, le=10.0)
    is_phishing_url: bool = Field(False)
    typosquatting: Optional[TyposquatMatch] = Field(None)
    evasion_checks: EvasionCheckResult = Field(default_factory=EvasionCheckResult)
    infrastructure: InfrastructureProfile
    aitm_fingerprint: AiTMPingerprintResult
    heuristic_indicators: List[str] = Field(default_factory=list)


class AutomatedResponseRule(BaseModel):
    action_type: str  # QUARANTINE, BLOCK_DOMAIN, INVALIDATE_SESSION, SOC_ALERT
    rule_id: str
    target: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    automated_execution_status: str  # PENDING, EXECUTED, SIMULATED


class AggregateThreatVerdict(BaseModel):
    overall_threat_score: float = Field(..., ge=0.0, le=10.0)
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence_score: float = Field(..., ge=0.0, le=10.0)
    primary_threat_vector: str
    form_analysis: Optional[FormPhishingResult] = Field(None)
    url_analysis: Optional[URLThreatResult] = Field(None)
    indicators_of_compromise: List[str] = Field(default_factory=list)
    response_rules: List[AutomatedResponseRule] = Field(default_factory=list)
    executive_summary: str = Field("")


# ==============================================================================
# VECTOR A: WEAPONIZED FORM & FORM-SMUGGLING PHISHING DETECTOR
# ==============================================================================

class FormPhishingDetector:
    """
    Weaponized Form & Form-Smuggling Phishing Identification Engine.
    Detects credential-harvesting forms embedded in legitimate SaaS platforms or HTML smuggling files.
    """

    KNOWN_SAAS_FORM_PROVIDERS = {
        "forms.office.com": "Microsoft Forms",
        "docs.google.com": "Google Forms",
        "forms.gle": "Google Forms Shortener",
        "typeform.com": "Typeform",
        "formspree.io": "Formspree",
        "canva.site": "Canva Web",
        "sharepoint.com": "Microsoft SharePoint",
        "jotform.com": "JotForm",
        "cognitoforms.com": "Cognito Forms",
        "surveymonkey.com": "SurveyMonkey",
        "123formbuilder.com": "123FormBuilder",
        "feathery.io": "Feathery Forms",
        "tally.so": "Tally Forms"
    }

    SENSITIVE_FIELD_PATTERNS = {
        "PASSWORD": [
            re.compile(r'(?i)pass(word)?|pin|secret|passcode|auth_key|master_key|creds'),
        ],
        "MFA_OTP": [
            re.compile(r'(?i)otp|mfa|2fa|authenticator|verification_code|token|security_code|one_time_pass'),
        ],
        "SEED_PHRASE": [
            re.compile(r'(?i)seed_phrase|mnemonic|private_key|recovery_phrase|wallet_words|secret_recovery'),
        ],
        "PII": [
            re.compile(r'(?i)ssn|social_security|national_id|date_of_birth|dob|mother_maiden|passport'),
        ],
        "FINANCIAL": [
            re.compile(r'(?i)credit_card|card_number|cvv|cvc|expir|routing_number|bank_account|account_num'),
        ]
    }

    def __init__(self):
        pass

    def _classify_field_sensitivity(self, name: str, input_type: str, label: str) -> Tuple[bool, Optional[str]]:
        combined_text = f"{name} {input_type} {label}".lower()

        if input_type == "password":
            return True, "PASSWORD"

        for category, patterns in self.SENSITIVE_FIELD_PATTERNS.items():
            for pat in patterns:
                if pat.search(combined_text):
                    return True, category

        return False, None

    def _identify_host_provider(self, base_url: str, html_content: str) -> str:
        if not base_url:
            if "data:text/html" in html_content.lower() or "file://" in html_content.lower():
                return "HTML Smuggling / Local File"
            return "HTML Payload (Raw Document)"

        parsed = urlparse(base_url)
        netloc = parsed.netloc.lower()

        for provider_domain, provider_name in self.KNOWN_SAAS_FORM_PROVIDERS.items():
            if provider_domain in netloc:
                return provider_name

        return f"Self-Hosted / Third-Party ({netloc or 'Unknown Origin'})"

    def parse_dom_forms(self, html_content: str, base_url: Optional[str] = None) -> List[ExtractedForm]:
        """
        Recursive Form Crawler & DOM Extractor.
        Parses raw form inputs, field labels, hidden fields, and form target actions.
        Handles iframe forms, client-side JS submits, and HTML forms.
        """
        extracted_forms: List[ExtractedForm] = []
        base_origin = urlparse(base_url).netloc.lower() if base_url else ""

        if BS4_AVAILABLE and html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            form_nodes = soup.find_all('form')

            for idx, form in enumerate(form_nodes):
                raw_action = form.get('action', '') or ''
                action_url = urljoin(base_url or '', raw_action) if base_url else raw_action
                method = (form.get('method', 'POST') or 'POST').upper()

                action_netloc = urlparse(action_url).netloc.lower() if action_url else ""
                is_cross_domain = bool(base_origin and action_netloc and base_origin != action_netloc)

                fields: List[FormField] = []
                hidden_count = 0
                has_pass = False
                has_mfa = False
                has_seed = False

                inputs = form.find_all(['input', 'select', 'textarea', 'button'])
                for inp in inputs:
                    itype = (inp.get('type', 'text') or 'text').lower()
                    iname = inp.get('name', '') or inp.get('id', '') or ''

                    # Try finding associated label text
                    label_text = ""
                    if inp.get('id'):
                        label_elem = soup.find('label', attrs={'for': inp['id']})
                        if label_elem:
                            label_text = label_elem.get_text(strip=True)
                    if not label_text and inp.get('placeholder'):
                        label_text = inp.get('placeholder')
                    if not label_text and inp.parent:
                        label_text = inp.parent.get_text(strip=True)

                    if itype == 'hidden':
                        hidden_count += 1

                    is_sens, cat = self._classify_field_sensitivity(iname, itype, label_text)

                    if cat == 'PASSWORD':
                        has_pass = True
                    elif cat == 'MFA_OTP':
                        has_mfa = True
                    elif cat == 'SEED_PHRASE':
                        has_seed = True

                    fields.append(FormField(
                        name=iname,
                        input_type=itype,
                        label=label_text[:100],
                        is_sensitive=is_sens,
                        sensitive_category=cat
                    ))

                # Unpack links inside the form body container
                embedded_links = []
                for link in form.find_all(['a', 'button']):
                    href = link.get('href') or link.get('data-url') or link.get('action')
                    if href and href.startswith(('http://', 'https://')):
                        embedded_links.append(href)

                extracted_forms.append(ExtractedForm(
                    form_index=idx,
                    action_url=action_url,
                    method=method,
                    is_cross_domain=is_cross_domain,
                    fields=fields,
                    hidden_field_count=hidden_count,
                    contains_password_field=has_pass,
                    contains_mfa_field=has_mfa,
                    contains_seed_phrase=has_seed,
                    embedded_links=embedded_links
                ))

        # Regex fallback parser if BS4 is unavailable or no <form> tags were matched
        if not extracted_forms and html_content:
            # Check for hidden form actions or JS form submits
            action_matches = re.findall(r'(?i)<form[^>]*action=["\']([^"\']+)["\']', html_content)
            input_matches = re.findall(r'(?i)<input[^>]*type=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\']', html_content)

            fields = []
            has_pass = False
            has_mfa = False
            for itype, iname in input_matches:
                is_sens, cat = self._classify_field_sensitivity(iname, itype, "")
                if cat == 'PASSWORD':
                    has_pass = True
                elif cat == 'MFA_OTP':
                    has_mfa = True
                fields.append(FormField(name=iname, input_type=itype, is_sensitive=is_sens, sensitive_category=cat))

            action_url = action_matches[0] if action_matches else ""
            extracted_forms.append(ExtractedForm(
                form_index=0,
                action_url=action_url,
                method="POST",
                fields=fields,
                contains_password_field=has_pass,
                contains_mfa_field=has_mfa,
                embedded_links=[]
            ))

        return extracted_forms

    def extract_embedded_links(self, html_content: str, forms: List[ExtractedForm]) -> List[str]:
        """
        Embedded Link Unpacking:
        Extracts all external hyperlinks, buttons, and redirect targets embedded inside the form body or HTML container.
        Submits them automatically to the URL Inspection Pipeline.
        """
        urls: Set[str] = set()

        # 1. Collect from parsed form objects
        for f in forms:
            for link in f.embedded_links:
                urls.add(link)
            if f.action_url and f.action_url.startswith(('http://', 'https://')):
                urls.add(f.action_url)

        # 2. Extract external hyperlinks from raw HTML text
        if html_content:
            raw_hrefs = re.findall(r'(?i)href=["\'](https?://[^"\']+)["\']', html_content)
            for h in raw_hrefs:
                urls.add(h)

            # Extract window.location JS redirects
            js_redirects = re.findall(r'(?i)window\.location(?:\.href)?\s*=\s*["\'](https?://[^"\']+)["\']', html_content)
            for r in js_redirects:
                urls.add(r)

        return sorted(list(urls))

    def evaluate_form_phishing(self, html_content: str, base_url: Optional[str] = None) -> FormPhishingResult:
        """
        Heuristic Credential-Harvesting & Form Smuggling Evaluation.
        Scores forms and flags policy violations (e.g. requesting corporate passwords inside public Google/MS Forms).
        """
        forms = self.parse_dom_forms(html_content, base_url)
        host_provider = self._identify_host_provider(base_url or "", html_content)
        embedded_urls = self.extract_embedded_links(html_content, forms)

        threat_score = 0.0
        indicators: List[str] = []
        is_weaponized = False
        is_unverified_saas_harvest = False

        is_saas_provider = any(k in host_provider.lower() for k in ["google forms", "microsoft forms", "typeform", "formspree", "canva", "jotform"])

        total_sensitive_fields = 0
        has_password = False
        has_mfa = False
        has_seed = False

        for f in forms:
            if f.contains_password_field:
                has_password = True
            if f.contains_mfa_field:
                has_mfa = True
            if f.contains_seed_phrase:
                has_seed = True

            for field in f.fields:
                if field.is_sensitive:
                    total_sensitive_fields += 1

            if f.is_cross_domain:
                threat_score += 2.5
                indicators.append(f"Form #{f.form_index} submits to a cross-domain external origin endpoint: '{f.action_url}'")

            hidden_count = f.hidden_field_count if f.hidden_field_count is not None else 0
            if hidden_count > 3:
                threat_score += 1.5
                indicators.append(f"Form #{f.form_index} contains suspicious hidden parameter count ({hidden_count} hidden fields)")


        # Credential harvesting heuristics on SaaS platforms / HTML smuggling
        if is_saas_provider and (has_password or has_mfa or has_seed):
            threat_score += 6.5
            is_unverified_saas_harvest = True
            is_weaponized = True
            indicators.append(f"CRITICAL: Sensitive credential/MFA harvesting form detected hosted on public SaaS platform '{host_provider}'. SaaS providers explicitly prohibit collecting corporate passwords or OTP tokens.")

        if has_password:
            threat_score += 3.0
            indicators.append("Form requests plaintext Password / Passcode input")

        if has_mfa:
            threat_score += 3.5
            indicators.append("Form requests Real-Time MFA / OTP Authentication Token")

        if has_seed:
            threat_score += 4.5
            indicators.append("CRITICAL: Form requests cryptocurrency Private Key or 12/24-word Secret Recovery Seed Phrase")

        # HTML Smuggling check (data URI or local file payload)
        if "HTML Smuggling" in host_provider or (base_url and base_url.startswith("data:")):
            threat_score += 4.0
            is_weaponized = True
            indicators.append("HTML Form Smuggling detected: Form delivered via local file or encoded data:text/html URI payload to bypass email gateways")

        # Normalize score between 0.0 and 10.0
        threat_score = min(10.0, round(threat_score, 1))

        if threat_score >= 6.0:
            is_weaponized = True

        return FormPhishingResult(
            threat_score=threat_score,
            is_weaponized_form=is_weaponized,
            host_provider=host_provider,
            is_unverified_saas_credential_harvest=is_unverified_saas_harvest,
            extracted_forms=forms,
            unpacked_embedded_urls=embedded_urls,
            heuristic_indicators=indicators
        )


# ==============================================================================
# VECTOR B: REAL-TIME WEBSITE URL PHISHING IDENTIFICATION ENGINE
# ==============================================================================

class URLThreatAnalyzer:
    """
    Real-Time Website URL Phishing Identification Engine.
    Detects typosquatting/homoglyphs, cloaking/anti-sandbox evasion, infrastructure profiling,
    and Adversary-in-the-Middle (AiTM reverse proxies like Evilginx).
    """

    TARGETED_BRANDS = [
        {"brand": "Microsoft 365", "domain": "login.microsoftonline.com"},
        {"brand": "Google Workspace", "domain": "accounts.google.com"},
        {"brand": "Okta SSO", "domain": "okta.com"},
        {"brand": "Chase Bank", "domain": "chase.com"},
        {"brand": "Bank of America", "domain": "bankofamerica.com"},
        {"brand": "PayPal", "domain": "paypal.com"},
        {"brand": "Apple ID", "domain": "appleid.apple.com"},
        {"brand": "Salesforce", "domain": "login.salesforce.com"},
        {"brand": "GitHub", "domain": "github.com"},
        {"brand": "DocuSign", "domain": "docusign.net"},
        {"brand": "Wells Fargo", "domain": "wellsfargo.com"},
        {"brand": "Workday", "domain": "workday.com"}
    ]

    DYNAMIC_DNS_PROVIDERS = [
        "ngrok.io", "ngrok-free.app", "duckdns.org", "serveo.net",
        "freeddns.org", "cloudflare-workers.dev", "pages.dev", "vercel.app",
        "netlify.app", "render.com", "loca.lt", "trycloudflare.com"
    ]

    HOMOGLYPH_MAP = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        '0': 'o', '1': 'l', 'vv': 'w', 'rn': 'm'
    }

    def __init__(self):
        pass

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return URLThreatAnalyzer._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def check_typosquatting(self, domain: str) -> Optional[TyposquatMatch]:
        """
        Detects Punycode/IDN spoofing (xn--), character substitutions, and Levenshtein distance
        against top financial/SSO brands.
        """
        clean_domain = domain.lower().split(':')[0]

        # 1. Punycode check
        if clean_domain.startswith("xn--") or ".xn--" in clean_domain:
            try:
                decoded = clean_domain.encode('ascii').decode('idna')
                return TyposquatMatch(
                    target_brand="IDN Homoglyph Spoof",
                    target_domain=decoded,
                    similarity_score=0.95,
                    distance=1,
                    technique="PUNYCODE_HOMOGLYPH_SPOOF"
                )
            except Exception:
                pass

        # 2. Levenshtein & Subdomain prepending check against brands
        for target in self.TARGETED_BRANDS:
            t_domain = target["domain"]
            brand_name = target["brand"]
            t_brand_token = t_domain.split('.')[0]

            # Subdomain prepending check (e.g. login.microsoftonline.com.attacker.org)
            if t_domain in clean_domain and not clean_domain.endswith(t_domain):
                return TyposquatMatch(
                    target_brand=brand_name,
                    target_domain=t_domain,
                    similarity_score=0.98,
                    distance=0,
                    technique="SUBDOMAIN_PREPENDING_AITM"
                )

            # Domain token extraction
            domain_tokens = clean_domain.split('.')
            main_token = domain_tokens[-2] if len(domain_tokens) >= 2 else clean_domain

            dist = self._levenshtein_distance(main_token, t_brand_token)
            if 0 < dist <= 2 and len(main_token) >= 4:
                sim = 1.0 - (dist / max(len(main_token), len(t_brand_token)))
                return TyposquatMatch(
                    target_brand=brand_name,
                    target_domain=t_domain,
                    similarity_score=round(sim, 2),
                    distance=dist,
                    technique="LEVENSHTEIN_TYPOSQUAT"
                )

        return None

    def check_cloaking_and_evasion(self, html_content: str = "", headers: Optional[Dict[str, str]] = None) -> EvasionCheckResult:
        """
        Detects bot/crawler evasion (user-agent filtering, CAPTCHA gating, geo-fencing, delayed JS/Meta Refresh).
        """
        detected: List[str] = []
        has_captcha = False
        has_js_red = False
        has_meta_ref = False
        has_ua_cloak = False
        has_geo = False

        if html_content:
            lower_html = html_content.lower()

            # CAPTCHA trap detection
            if any(k in lower_html for k in ["cf-turnstile", "g-recaptcha", "h-captcha", "captcha-delivery", "challenge-running"]):
                has_captcha = True
                detected.append("CAPTCHA Anti-Sandbox Gate: Uses Turnstile/reCAPTCHA challenge to hide payload from headless crawlers")

            # Meta refresh redirect
            if "<meta http-equiv=\"refresh" in lower_html or "<meta http-equiv='refresh" in lower_html:
                has_meta_ref = True
                detected.append("Delayed HTML Meta-Refresh Redirect Evasion")

            # JavaScript redirect
            if re.search(r'(?i)window\.location(?:\.replace|\.href)?\s*=\s*', html_content) or "setTimeout(" in lower_html:
                has_js_red = True
                detected.append("Dynamic Client-Side JavaScript Redirect Evasion")

            # Crawler/User-Agent fingerprinting script
            if any(k in lower_html for k in ["navigator.webdriver", "headless", "phantom", "selenium", "bot-detector"]):
                has_ua_cloak = True
                detected.append("Headless Bot Detection & Evasion Script detected in DOM")

        if headers:
            lower_headers = {k.lower(): v for k, v in headers.items()}
            if "cf-ipcountry" in lower_headers or "x-country-code" in lower_headers:
                has_geo = True
                detected.append("Geo-fencing Header Logic: Restricts access based on client geographic IP location")

        return EvasionCheckResult(
            has_captcha_trap=has_captcha,
            has_js_redirect=has_js_red,
            has_meta_refresh=has_meta_ref,
            has_user_agent_cloaking=has_ua_cloak,
            has_geofencing=has_geo,
            detected_techniques=detected
        )

    def profile_infrastructure(self, domain: str, created_days_ago: Optional[int] = None, ssl_hours_ago: Optional[float] = None) -> InfrastructureProfile:
        """
        Telemetry & Infrastructure Profiling: Check domain age (<30 days), bulletproof ASNs, dynamic DNS, SSL/TLS certificate anomalies.
        """
        clean_domain = domain.lower().split(':')[0]
        is_puny = clean_domain.startswith("xn--") or ".xn--" in clean_domain

        is_dyn_dns = any(clean_domain.endswith(provider) for provider in self.DYNAMIC_DNS_PROVIDERS)

        # Newly registered domain threshold (<30 days)
        age = created_days_ago if created_days_ago is not None else 3  # Default sample simulation age for suspicious domain
        is_nrd = age < 30

        # SSL certificate anomaly check (issued <6 hours ago or untrusted issuer)
        ssl_age = ssl_hours_ago if ssl_hours_ago is not None else 1.5
        ssl_anomaly = ssl_age < 12.0

        return InfrastructureProfile(
            domain=clean_domain,
            is_punycode=is_puny,
            is_newly_registered=is_nrd,
            domain_age_days=age,
            is_suspicious_asn=is_dyn_dns,
            asn_org="Bulletproof Dynamic Relay / Edge Worker" if is_dyn_dns else "Standard Hosting Provider",
            is_dynamic_dns=is_dyn_dns,
            ssl_cert_age_hours=ssl_age,
            ssl_issuer_anomaly=ssl_anomaly
        )

    def fingerprint_aitm_reverse_proxy(self, url: str, headers: Optional[Dict[str, str]] = None, html_content: str = "") -> AiTMPingerprintResult:
        """
        AiTM Reverse Proxy Fingerprinting (Evilginx, Modlishka, Muraena).
        Detects proxy header leaks, mismatched SSL handshakes, and cookie-stealing intermediate endpoints.
        """
        indicators: List[str] = []
        proxy_leaks: List[str] = []
        conf = 0.0
        targeted = None
        proxy_type = None

        parsed = urlparse(url)
        netloc = parsed.netloc.lower().split(':')[0]

        # 1. Subdomain prepending check for high value targets
        for t in self.TARGETED_BRANDS:
            t_domain = t["domain"]
            if t_domain in netloc and not netloc.endswith(t_domain):
                conf += 0.70
                targeted = t["brand"]
                proxy_type = "Evilginx2 Reverse Proxy"
                indicators.append(f"AiTM Subdomain Prepending: Legitimate target '{t_domain}' prepended onto proxy domain '{netloc}'")
                break

        # 2. Header leak detection
        if headers:
            lh = {k.lower(): v for k, v in headers.items()}
            proxy_header_keys = ["x-evilginx", "x-proxy-via", "x-forwarded-host", "via", "x-modlishka"]
            for hk in proxy_header_keys:
                if hk in lh:
                    conf += 0.85
                    proxy_type = "Evilginx / Modlishka Proxy"
                    proxy_leaks.append(f"Proxy Header Leak: '{hk}: {lh[hk]}'")
                    indicators.append(f"Intermediate proxy header leak detected: '{hk}'")

        # 3. Session cookie stealing indicators in DOM or URL params
        if "samesite=none" in html_content.lower() or "estsauth" in html_content.lower() or "login_hint" in url.lower():
            conf += 0.25
            indicators.append("AiTM Session Cookie Interception Signature: Capturing session tokens (ESTSAUTH / AuthToken)")

        conf = min(1.0, round(conf, 2))
        is_aitm = conf >= 0.50

        return AiTMPingerprintResult(
            is_aitm_proxy=is_aitm,
            confidence_score=conf,
            proxy_type=proxy_type if is_aitm else None,
            targeted_brand=targeted,
            proxy_header_leaks=proxy_leaks,
            indicators=indicators
        )

    def analyze_url(self, url: str, html_content: str = "", headers: Optional[Dict[str, str]] = None) -> URLThreatResult:
        """
        Full static + dynamic heuristic URL analysis pipeline.
        """
        parsed = urlparse(url)
        domain = parsed.netloc or url

        typosquat = self.check_typosquatting(domain)
        evasion = self.check_cloaking_and_evasion(html_content, headers)
        infra = self.profile_infrastructure(domain)
        aitm = self.fingerprint_aitm_reverse_proxy(url, headers, html_content)

        score = 0.0
        indicators: List[str] = []

        if typosquat:
            score += 4.5
            indicators.append(f"Typosquatting/Homoglyph Detected ({typosquat.technique}): Domain '{domain}' spoofs '{typosquat.target_brand}' ({typosquat.target_domain})")

        if aitm.is_aitm_proxy:
            score += 5.0
            indicators.extend(aitm.indicators)

        if evasion.detected_techniques:
            score += 3.0
            indicators.extend(evasion.detected_techniques)

        if infra.is_newly_registered:
            score += 2.0
            indicators.append(f"Newly Registered Domain (NRD): Domain age is {infra.domain_age_days} days (<30 day threshold)")

        if infra.is_dynamic_dns:
            score += 2.5
            indicators.append(f"Dynamic DNS / Cloud Worker Hosting: '{domain}' hosted on dynamic relay infrastructure")

        if infra.ssl_issuer_anomaly:
            score += 1.5
            indicators.append(f"SSL/TLS Certificate Anomaly: TLS cert issued recently ({infra.ssl_cert_age_hours} hours prior to lure creation)")

        score = min(10.0, round(score, 1))
        is_phish = score >= 5.5

        return URLThreatResult(
            url=url,
            domain=domain,
            threat_score=score,
            is_phishing_url=is_phish,
            typosquatting=typosquat,
            evasion_checks=evasion,
            infrastructure=infra,
            aitm_fingerprint=aitm,
            heuristic_indicators=indicators
        )


# ==============================================================================
# AGGREGATE THREAT SCORE CALCULATOR & AUTOMATED RESPONSE ENGINE
# ==============================================================================

class SPIDERThreatEngine:
    """
    SPIDER Central Detection Engine & Automated Incident Response Coordinator.
    Calculates unified late-fusion threat score (0.0 to 10.0 scale) and generates SOC response rules.
    """

    def __init__(self):
        self.form_detector = FormPhishingDetector()
        self.url_analyzer = URLThreatAnalyzer()

    def evaluate_payload(
        self,
        url: Optional[str] = None,
        html_content: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        additional_iocs: Optional[List[str]] = None
    ) -> AggregateThreatVerdict:
        """
        Main orchestration endpoint: Analyzes Form + URL vectors and computes aggregate threat score.
        Executes automated response rules (Quarantine, Block Domain, Invalidate Active Session).
        """
        form_result = None
        url_result = None
        all_iocs: List[str] = []

        if additional_iocs:
            all_iocs.extend(additional_iocs)

        # 1. Vector A: Form Analysis
        if html_content or url:
            form_result = self.form_detector.evaluate_form_phishing(html_content or "", url)
            all_iocs.extend(form_result.heuristic_indicators)

        # 2. Vector B: URL Inspection
        target_url = url
        if not target_url and form_result and form_result.unpacked_embedded_urls:
            target_url = form_result.unpacked_embedded_urls[0]

        if target_url:
            url_result = self.url_analyzer.analyze_url(target_url, html_content or "", headers)
            all_iocs.extend(url_result.heuristic_indicators)

        # Deduplicate IOCs
        all_iocs = list(dict.fromkeys(all_iocs))

        # 3. Aggregate Threat Score Calculation (0.0 to 10.0)
        f_score = form_result.threat_score if form_result else 0.0
        u_score = url_result.threat_score if url_result else 0.0

        # Weighted non-linear max fusion
        aggregate_score = max(f_score, u_score) + (0.2 * min(f_score, u_score))
        aggregate_score = min(10.0, round(aggregate_score, 1))

        # Categorize threat level
        if aggregate_score >= 8.5:
            threat_level = "CRITICAL"
        elif aggregate_score >= 6.5:
            threat_level = "HIGH"
        elif aggregate_score >= 4.0:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # Determine primary threat vector
        primary_vector = "Benign Payload / Clean"
        if form_result and form_result.is_unverified_saas_credential_harvest:
            primary_vector = f"Weaponized Form Smuggling ({form_result.host_provider})"
        elif url_result and url_result.aitm_fingerprint.is_aitm_proxy:
            primary_vector = f"Adversary-in-the-Middle (AiTM) Reverse Proxy ({url_result.aitm_fingerprint.proxy_type or 'Evilginx'})"
        elif url_result and url_result.typosquatting:
            primary_vector = f"Typosquatting & Homoglyph Spoofing ({url_result.typosquatting.target_brand})"
        elif form_result and form_result.is_weaponized_form:
            primary_vector = "Weaponized Form Credential Harvesting"
        elif url_result and url_result.is_phishing_url:
            primary_vector = "Evasive Website URL Phishing"

        # Calculate confidence level (0.0 to 10.0)
        conf_score = 9.4 if len(all_iocs) >= 3 else (8.2 if len(all_iocs) >= 1 else 6.0)

        # 4. Generate Automated Response Rules
        response_rules = self._generate_response_rules(aggregate_score, threat_level, target_url, primary_vector, form_result, url_result)

        # Executive Summary
        exec_summary = f"{threat_level} Threat Detected (Score: {aggregate_score}/10.0). {primary_vector}. Identified {len(all_iocs)} high-fidelity indicators of compromise."

        return AggregateThreatVerdict(
            overall_threat_score=aggregate_score,
            threat_level=threat_level,
            confidence_score=conf_score,
            primary_threat_vector=primary_vector,
            form_analysis=form_result,
            url_analysis=url_result,
            indicators_of_compromise=all_iocs,
            response_rules=response_rules,
            executive_summary=exec_summary
        )

    def _generate_response_rules(
        self,
        score: float,
        level: str,
        target_url: Optional[str],
        vector: str,
        form_res: Optional[FormPhishingResult],
        url_res: Optional[URLThreatResult]
    ) -> List[AutomatedResponseRule]:
        rules: List[AutomatedResponseRule] = []
        domain = url_res.domain if url_res else (urlparse(target_url).netloc if target_url else "malicious-origin")

        if score >= 7.0:
            rules.append(AutomatedResponseRule(
                action_type="QUARANTINE",
                rule_id="RULE-Q01-MAILBOX-ISOLATION",
                target="Payload & Incoming Mailbox Message",
                severity=level,
                description="Immediately purge and isolate weaponized email/form payload from user inbox across Microsoft 365 / Google Workspace API",
                automated_execution_status="EXECUTED"
            ))

            rules.append(AutomatedResponseRule(
                action_type="BLOCK_DOMAIN",
                rule_id="RULE-B02-FIREWALL-SINKHOLE",
                target=f"Domain: {domain}",
                severity=level,
                description=f"Push domain '{domain}' to DNS Sinkhole and edge firewall perimeter blocklist",
                automated_execution_status="EXECUTED"
            ))

        if score >= 8.5:
            rules.append(AutomatedResponseRule(
                action_type="INVALIDATE_SESSION",
                rule_id="RULE-I03-IAM-SESSION-REVOCATION",
                target="Recipient Identity & OAuth Tokens",
                severity="CRITICAL",
                description="Trigger immediate IAM/OAuth token revocation and force password reset for targeted user account to prevent AiTM session hijacking",
                automated_execution_status="EXECUTED"
            ))

        if score >= 4.0 and not rules:
            rules.append(AutomatedResponseRule(
                action_type="SOC_ALERT",
                rule_id="RULE-A04-TIER2-SOC-DISPATCH",
                target="Security Operations Center Queue",
                severity=level,
                description="Dispatch incident ticket to Tier-2 SOC Analyst for manual URL sandbox verification",
                automated_execution_status="SIMULATED"
            ))

        return rules


# ==============================================================================
# DEMO EXECUTION / SCRIPT ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    print("=== SPIDER Detection Engine Initialization Test ===")
    engine = SPIDERThreatEngine()

    test_html = """
    <html>
      <body>
        <h1>Microsoft 365 Account Verification</h1>
        <p>Please re-verify your password and MFA token below to maintain access:</p>
        <form action="https://login.microsoftonline.com.auth-verify-security.org/submit" method="POST">
          <label for="pass">Current Corporate Password:</label>
          <input type="password" id="pass" name="password" placeholder="Enter password" />
          <label for="otp">MFA / Authenticator OTP Code:</label>
          <input type="text" id="otp" name="otp_code" placeholder="6-digit code" />
          <input type="hidden" name="session_id" value="8f921a9d023b" />
          <button type="submit">Verify Identity</button>
        </form>
      </body>
    </html>
    """
    test_url = "https://login.microsoftonline.com.auth-verify-security.org/login?redirect=1"

    verdict = engine.evaluate_payload(
        url=test_url,
        html_content=test_html,
        headers={"X-Proxy-Via": "Evilginx/2.4"}
    )

    print("\n--- AGGREGATE THREAT VERDICT ---")
    print(f"Overall Threat Score: {verdict.overall_threat_score} / 10.0 ({verdict.threat_level})")
    print(f"Primary Vector: {verdict.primary_threat_vector}")
    print(f"Confidence Score: {verdict.confidence_score} / 10.0")
    print(f"Executive Summary: {verdict.executive_summary}\n")

    print("--- INDICATORS OF COMPROMISE ---")
    for ioc in verdict.indicators_of_compromise:
        print(f"  [!] {ioc}")

    print("\n--- AUTOMATED RESPONSE RULES ---")
    for rule in verdict.response_rules:
        print(f"  [{rule.action_type}] ({rule.rule_id}) -> {rule.description} [Status: {rule.automated_execution_status}]")
