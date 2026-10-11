/**
 * Multimodal Phishing Detection Framework - Threat Intelligence Analyzer
 * Core Threat Analysis & Heuristics (AiTM & AI-Authorship Detection)
 */

export interface AiTMResult {
  is_aitm_proxy: boolean;
  aitm_confidence_score: number;
  impersonated_target: string | null;
  indicators: string[];
}

export interface AiAuthorResult {
  ai_generated_probability: number;
  burstiness_score: number;
  perplexity_heuristic: number;
  is_ai_generated: boolean;
  indicators: string[];
}

const HIGH_VALUE_TARGETS = [
  'login.microsoftonline.com',
  'accounts.google.com',
  'login.live.com',
  'appleid.apple.com',
  'login.salesforce.com',
  'okta.com',
  'auth0.com',
  'github.com',
  'docusign.net',
];

const EVILGINX_PATTERNS = [
  /\/login\/[a-f0-9]{12,}/i,
  /[?&](sess|session_id|auth_token|lure_id)=/i,
  /\/oauth2\/v2\.0\/authorize\?.*client_id=/i,
  /\/kmsi\?/i,
  /\/common\/oauth2\//i,
];

export function detect_aitm_signatures(url: string): AiTMResult {
  if (!url) {
    return {
      is_aitm_proxy: false,
      aitm_confidence_score: 0.0,
      impersonated_target: null,
      indicators: [],
    };
  }

  const indicators: string[] = [];
  let confidence_score = 0.0;
  let impersonated_target: string | null = null;

  let netloc = '';
  let path = '';
  let query = '';

  try {
    const parsed = new URL(url);
    netloc = parsed.hostname.toLowerCase();
    path = parsed.pathname.toLowerCase();
    query = parsed.search.toLowerCase();
  } catch {
    return {
      is_aitm_proxy: false,
      aitm_confidence_score: 0.0,
      impersonated_target: null,
      indicators: ['Malformed URL string'],
    };
  }

  // 1. Subdomain prepending check (e.g. login.microsoftonline.com.attacker-proxy.org)
  for (const target of HIGH_VALUE_TARGETS) {
    if (netloc.includes(target) && !netloc.endsWith(target)) {
      indicators.push(
        `AiTM Subdomain Prepending: Legitimate target '${target}' prepended onto malicious domain '${netloc}'`
      );
      confidence_score += 0.65;
      impersonated_target = target;
      break;
    }
  }

  // 2. Evilginx2 / Modlishka / Muraena path & parameter routing signatures
  const fullUri = path + query;
  for (const pattern of EVILGINX_PATTERNS) {
    if (pattern.test(fullUri)) {
      indicators.push(`Known Evilginx2/AiTM URL routing pattern matched: '${pattern.source}'`);
      confidence_score += 0.25;
    }
  }

  // 3. Subdomain depth and session entropy heuristics
  const subdomain_parts = netloc.split('.');
  if (subdomain_parts.length >= 4) {
    indicators.push(
      `Excessive subdomain depth (${subdomain_parts.length} levels) typical of AiTM reverse proxies`
    );
    confidence_score += 0.15;
  }

  if (query.length > 120 || /[0-9a-f]{32,}/.test(query)) {
    indicators.push('High-entropy session tracking parameter detected in URI query');
    confidence_score += 0.15;
  }

  confidence_score = Math.min(Math.round(confidence_score * 100) / 100, 1.0);
  const is_aitm_proxy = confidence_score >= 0.5;

  return {
    is_aitm_proxy,
    aitm_confidence_score: confidence_score,
    impersonated_target,
    indicators,
  };
}

export function calculate_ai_authorship(text: string): AiAuthorResult {
  if (!text || text.trim().length < 30) {
    return {
      ai_generated_probability: 0.0,
      burstiness_score: 0.0,
      perplexity_heuristic: 0.0,
      is_ai_generated: false,
      indicators: ['Text payload too short for statistical NLP analysis (<30 chars)'],
    };
  }

  const sentences = text
    .split(/[.!?]+\s+|\n+/)
    .map((s) => s.trim())
    .filter(Boolean);

  let sentence_lengths = sentences.map((s) => s.split(/\s+/).filter(Boolean).length);
  if (sentence_lengths.length === 0) {
    sentence_lengths = [text.split(/\s+/).filter(Boolean).length];
  }

  const mean_len = sentence_lengths.reduce((a, b) => a + b, 0) / sentence_lengths.length;
  const variance =
    sentence_lengths.reduce((acc, len) => acc + Math.pow(len - mean_len, 2), 0) /
    sentence_lengths.length;
  const std_len = Math.sqrt(variance);
  const cv = mean_len > 0 ? std_len / mean_len : 0.0;

  const words = (text.match(/\b[a-zA-Z]{2,}\b/g) || []).map((w) => w.toLowerCase());
  const total_words = words.length;
  const unique_words = new Set(words).size;
  const ttr = total_words > 0 ? unique_words / total_words : 0.0;

  const word_counts: Record<string, number> = {};
  for (const w of words) {
    word_counts[w] = (word_counts[w] || 0) + 1;
  }
  const probs = Object.values(word_counts).map((c) => c / total_words);
  const entropy = probs.reduce((acc, p) => acc - p * Math.log2(p), 0);

  const indicators: string[] = [];
  let ai_prob = 0.1;

  if (cv < 0.25 && sentence_lengths.length >= 3) {
    indicators.push('Low sentence length variance / burstiness (unnatural synthetic rhythm)');
    ai_prob += 0.35;
  } else if (cv < 0.35 && sentence_lengths.length >= 2) {
    indicators.push('Moderately uniform sentence cadence characteristic of LLM generation');
    ai_prob += 0.2;
  }

  if (entropy >= 4.2 && entropy <= 6.8 && ttr >= 0.52 && ttr <= 0.82) {
    indicators.push('Balanced unigram vocabulary entropy matching neural language model sampling');
    ai_prob += 0.3;
  }

  ai_prob = Math.min(Math.round(ai_prob * 100) / 100, 1.0);

  return {
    ai_generated_probability: ai_prob,
    burstiness_score: Math.round(cv * 100) / 100,
    perplexity_heuristic: Math.round(entropy * 100) / 100,
    is_ai_generated: ai_prob >= 0.6,
    indicators,
  };
}
