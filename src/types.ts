export interface ModalConfidenceScores {
  text_analyzer: number;
  email_analyzer: number;
  image_analyzer: number;
  audio_analyzer: number;
}

export interface ThreatAnalysisResult {
  threat_score: number;
  primary_vector: string;
  indicators_of_compromise: string[];
  is_prompt_injection_attempt: boolean;
  executive_summary: string;
  confidence_score?: number;
  modal_confidences?: ModalConfidenceScores;
}

export interface ExplainabilityItem {
  indicator: string;
  threat_factor: string;
  natural_language_breakdown: string;
  risk_impact: string;
  mitigation_hint: string;
}

export interface ExplainabilityResult {
  overall_summary: string;
  explanations: ExplainabilityItem[];
}

export interface FusedPayload {
  transcript: string | null;
  decoded_urls: Array<{ url: string; domain?: string; isTyposquat?: boolean }> | null;
  ocr_text: string | null;
  dom_structure: {
    total_links?: number;
    sample_links?: string[];
    total_forms?: number;
    has_password_field?: boolean;
    has_credit_card_inputs?: boolean;
  } | null;
  header_metadata: {
    From?: string;
    To?: string;
    'Reply-To'?: string;
    ReplyTo?: string;
    Subject?: string;
    'Authentication-Results'?: string;
    reply_to_mismatch?: boolean;
    spf?: string;
    dkim?: string;
    dmarc?: string;
    received_hops?: string[];
  } | null;
  sanitization_alerts: string[];
  synthetic_voice_anomaly?: boolean;
  anomaly_confidence?: number;
  urls_found?: string[];
  oauth_scopes?: string[];
}

export interface AttackPreset {
  id: string;
  name: string;
  category: string;
  vector: string;
  description: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'BENIGN';
  fused: FusedPayload;
  simulatedAudioNote?: string;
  simulatedImageNote?: string;
}
