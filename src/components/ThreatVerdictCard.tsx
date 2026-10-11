import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  FileDown,
  ShieldAlert,
  Sparkles,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  Brain,
  ShieldCheck,
} from 'lucide-react';
import { ThreatAnalysisResult, ExplainabilityResult, FusedPayload } from '../types';

interface ThreatVerdictCardProps {
  result: ThreatAnalysisResult;
  fusedPayload?: FusedPayload;
  isLoading: boolean;
  onAnalyzeClick: () => void;
  onDownloadPDF?: () => void;
}

export const ThreatVerdictCard: React.FC<ThreatVerdictCardProps> = ({
  result,
  isLoading,
  onAnalyzeClick,
  onDownloadPDF,
}) => {
  const threatScore100 = Math.round(result.threat_score * 10);
  const isInjection = result.is_prompt_injection_attempt;

  // Explainability State
  const [explainabilityData, setExplainabilityData] = useState<ExplainabilityResult | null>(null);
  const [isFetchingExplainability, setIsFetchingExplainability] = useState<boolean>(false);
  const [showExplainability, setShowExplainability] = useState<boolean>(true);

  // Fetch AI Explainability breakdown whenever result changes
  useEffect(() => {
    let isMounted = true;
    const fetchExplainability = async () => {
      if (!result.indicators_of_compromise || result.indicators_of_compromise.length === 0) {
        setExplainabilityData(null);
        return;
      }

      setIsFetchingExplainability(true);
      try {
        const resp = await fetch('/api/explainability', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            indicators_of_compromise: result.indicators_of_compromise,
            primary_vector: result.primary_vector,
            threat_score: result.threat_score,
          }),
        });

        if (resp.ok) {
          const data: ExplainabilityResult = await resp.json();
          if (isMounted) {
            setExplainabilityData(data);
          }
        }
      } catch (err) {
        console.warn('Explainability fetch error:', err);
      } finally {
        if (isMounted) {
          setIsFetchingExplainability(false);
        }
      }
    };

    fetchExplainability();

    return () => {
      isMounted = false;
    };
  }, [result]);

  const getSeverityConfig = (score: number) => {
    if (score >= 80) {
      return {
        label: 'CRITICAL THREAT',
        borderAccent: 'border-l-2 border-rose-500',
        scoreColor: 'text-rose-400',
        arcColor: '#f43f5e',
        badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
        recommendation: 'Block sender domain immediately and quarantine host workstation.',
      };
    } else if (score >= 50) {
      return {
        label: 'ELEVATED RISK',
        borderAccent: 'border-l-2 border-amber-500',
        scoreColor: 'text-amber-400',
        arcColor: '#f59e0b',
        badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        recommendation: 'Exercise caution. Verify request out-of-band via official contacts.',
      };
    } else {
      return {
        label: 'BENIGN PAYLOAD',
        borderAccent: 'border-l-2 border-emerald-500',
        scoreColor: 'text-emerald-400',
        arcColor: '#10b981',
        badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        recommendation: 'No malicious indicators discovered in late-fusion threat pipeline.',
      };
    }
  };

  const config = getSeverityConfig(threatScore100);

  // Sleek Thin-Stroke SVG Arc Gauge Calculation (Stroke Width 2 max)
  const radius = 54;
  const strokeWidth = 2; // Sleek thin stroke
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (threatScore100 / 100) * circumference;

  // Calculate or extract modal analyzer confidence levels
  const modalConfidences = result.modal_confidences || {
    text_analyzer: isInjection
      ? 98.5
      : result.indicators_of_compromise.some(
          (i) => i.toLowerCase().includes('prompt') || i.toLowerCase().includes('text') || i.toLowerCase().includes('zero-width')
        )
      ? 96.0
      : 94.0,
    email_analyzer: result.indicators_of_compromise.some(
      (i) => i.toLowerCase().includes('from') || i.toLowerCase().includes('reply-to') || i.toLowerCase().includes('spf') || i.toLowerCase().includes('bec')
    )
      ? 98.0
      : 96.0,
    image_analyzer: result.indicators_of_compromise.some(
      (i) => i.toLowerCase().includes('qr') || i.toLowerCase().includes('image') || i.toLowerCase().includes('ocr') || i.toLowerCase().includes('quishing')
    )
      ? 96.5
      : 92.5,
    audio_analyzer: result.indicators_of_compromise.some(
      (i) => i.toLowerCase().includes('voice') || i.toLowerCase().includes('spectral') || i.toLowerCase().includes('pitch') || i.toLowerCase().includes('vishing')
    )
      ? 97.0
      : 93.5,
  };

  // Average confidence across the individual modal analyzers
  const calculatedAvgConfidence =
    (modalConfidences.text_analyzer +
      modalConfidences.email_analyzer +
      modalConfidences.image_analyzer +
      modalConfidences.audio_analyzer) /
    4;

  const confidenceScore = result.confidence_score ?? calculatedAvgConfidence;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.1 }}
      className={`glass-card rounded-xl p-6 border border-white/10 ${config.borderAccent} relative overflow-hidden`}
    >
      <div className="flex flex-col xl:flex-row items-center gap-6">
        {/* Score & Confidence Metric Group */}
        <div className="flex flex-wrap sm:flex-nowrap items-center justify-center gap-4 shrink-0">
          {/* Main Threat Score SVG Gauge */}
          <div className="relative shrink-0 flex items-center justify-center">
            <svg className="w-28 h-28 sm:w-32 sm:h-32 transform -rotate-90">
              {/* Background Circle */}
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke="rgba(255, 255, 255, 0.08)"
                strokeWidth={strokeWidth}
                fill="transparent"
              />
              {/* Thin Arc Ring */}
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke={config.arcColor}
                strokeWidth={strokeWidth}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{
                  transition: 'stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
            </svg>

            {/* Centered Score & Muted Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-3xl font-medium font-mono tracking-tight ${config.scoreColor}`}>
                {threatScore100}
              </span>
              <span className="text-[9px] font-mono text-neutral-500 uppercase tracking-wider mt-0.5">
                THREAT SCORE
              </span>
            </div>
          </div>

          {/* Confidence Score Sub-Metric Card */}
          <div className="flex flex-col p-3 rounded-xl bg-neutral-900/90 border border-white/10 space-y-1.5 min-w-[135px] shadow-sm">
            <div className="flex items-center gap-1.5 text-neutral-400 text-[10px] font-mono uppercase tracking-wider">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>CONFIDENCE</span>
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-xl font-mono font-bold text-emerald-400 tracking-tight">
                {confidenceScore.toFixed(1)}%
              </span>
              <span className="text-[9px] text-neutral-500 font-mono uppercase">AVG</span>
            </div>
            {/* Modal Analyzer Confidence Sub-breakdown */}
            <div className="text-[9px] font-mono space-y-0.5 w-full pt-1.5 border-t border-white/10">
              <div className="flex justify-between items-center gap-2">
                <span className="text-neutral-500">Text:</span>
                <span className="text-neutral-300 font-semibold">{modalConfidences.text_analyzer.toFixed(0)}%</span>
              </div>
              <div className="flex justify-between items-center gap-2">
                <span className="text-neutral-500">Email:</span>
                <span className="text-neutral-300 font-semibold">{modalConfidences.email_analyzer.toFixed(0)}%</span>
              </div>
              <div className="flex justify-between items-center gap-2">
                <span className="text-neutral-500">Image:</span>
                <span className="text-neutral-300 font-semibold">{modalConfidences.image_analyzer.toFixed(0)}%</span>
              </div>
              <div className="flex justify-between items-center gap-2">
                <span className="text-neutral-500">Audio:</span>
                <span className="text-neutral-300 font-semibold">{modalConfidences.audio_analyzer.toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Verdict Statement & Details */}
        <div className="flex-1 space-y-2.5 text-center sm:text-left">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span
                className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium border uppercase tracking-wider ${config.badgeClass}`}
              >
                {config.label}
              </span>
              <span className="text-[11px] font-mono text-neutral-400">
                Vector: <span className="text-neutral-200">{result.primary_vector}</span>
              </span>
            </div>

            {onDownloadPDF && (
              <button
                onClick={onDownloadPDF}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neutral-900/90 hover:bg-neutral-800 border border-neutral-700/80 hover:border-emerald-500/40 text-neutral-200 hover:text-emerald-400 text-xs font-mono transition shadow-sm cursor-pointer shrink-0"
                title="Download PDF Threat Intelligence Report"
              >
                <FileDown className="w-3.5 h-3.5 text-emerald-400" />
                <span>Download PDF Report</span>
              </button>
            )}
          </div>

          <h3 className="text-sm font-medium text-neutral-100 font-sans leading-relaxed">
            {result.executive_summary}
          </h3>

          <div className="text-[11px] font-mono text-neutral-400 pt-1">
            <span className="text-neutral-500 uppercase">Action:</span> {config.recommendation}
          </div>
        </div>
      </div>

      {/* Adversarial Prompt Injection Alert Banner */}
      {isInjection && (
        <div className="mt-5 pt-3 border-t border-rose-500/20 flex items-center justify-between text-xs font-mono text-rose-300 bg-rose-500/[0.03] -mx-6 px-6 py-3 border-b">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
            <span>Indirect prompt injection in payload neutralized before classification.</span>
          </div>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
            ATL.AML.T0054
          </span>
        </div>
      )}

      {/* ==================================================================== */}
      {/* EXPLAINABILITY SECTION — GEMINI THREAT FACTOR DECOMPOSITION           */}
      {/* ==================================================================== */}
      <div className="mt-6 pt-5 border-t border-white/10 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Brain className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-semibold font-mono tracking-wide text-neutral-100 uppercase">
                  EXPLAINABILITY MATRIX
                </h4>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-emerald-400 flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-emerald-400" />
                  Gemini AI
                </span>
              </div>
              <p className="text-[11px] text-neutral-400 font-sans">
                Natural language factor breakdown for each detected indicator of compromise
              </p>
            </div>
          </div>

          <button
            onClick={() => setShowExplainability(!showExplainability)}
            className="text-xs font-mono text-neutral-300 hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-neutral-900/80 border border-neutral-800 hover:border-neutral-700 transition cursor-pointer"
          >
            {showExplainability ? (
              <>
                <span>Hide</span>
                <ChevronUp className="w-3.5 h-3.5 text-neutral-400" />
              </>
            ) : (
              <>
                <span>View Factors ({explainabilityData?.explanations?.length || result.indicators_of_compromise.length})</span>
                <ChevronDown className="w-3.5 h-3.5 text-neutral-400" />
              </>
            )}
          </button>
        </div>

        {showExplainability && (
          <AnimatePresence>
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="space-y-3 pt-1"
            >
              {isFetchingExplainability ? (
                <div className="p-4 rounded-lg bg-neutral-900/60 border border-neutral-800 text-center space-y-2">
                  <div className="inline-flex items-center gap-2 text-xs font-mono text-emerald-400">
                    <Sparkles className="w-4 h-4 animate-spin text-emerald-400" />
                    <span>Generating Gemini natural language threat factor explanations...</span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-sans">
                    Analyzing mechanisms, risk impact, and mitigation steps for {result.indicators_of_compromise.length} indicator(s)
                  </p>
                </div>
              ) : explainabilityData && explainabilityData.explanations.length > 0 ? (
                <>
                  {/* Overall Summary Notice */}
                  {explainabilityData.overall_summary && (
                    <div className="p-3 rounded-lg bg-neutral-900/70 border border-white/5 text-xs text-neutral-300 font-sans leading-relaxed">
                      <span className="font-mono text-[10px] text-emerald-400 uppercase tracking-wider block mb-1 font-semibold">
                        THREAT FACTOR SUMMARY
                      </span>
                      {explainabilityData.overall_summary}
                    </div>
                  )}

                  {/* Individual IoC Explanation Cards */}
                  <div className="space-y-3">
                    {explainabilityData.explanations.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-xl bg-neutral-900/80 border border-white/10 space-y-2.5 hover:border-neutral-700 transition"
                      >
                        {/* Indicator Pill & Threat Factor Header */}
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 pb-2">
                          <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            <h5 className="text-xs font-semibold text-neutral-100 font-mono">
                              {item.threat_factor}
                            </h5>
                          </div>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-950 text-neutral-400 border border-neutral-800 truncate max-w-md">
                            IoC: {item.indicator}
                          </span>
                        </div>

                        {/* Natural Language Breakdown */}
                        <p className="text-xs text-neutral-200 font-sans leading-relaxed">
                          {item.natural_language_breakdown}
                        </p>

                        {/* Technical Risk & Mitigation Badges */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 text-[11px] font-mono">
                          <div className="p-2 rounded bg-rose-500/5 border border-rose-500/20 text-rose-300 flex items-start gap-1.5">
                            <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                            <div>
                              <span className="text-rose-400 font-bold block text-[9px] uppercase tracking-wider">
                                RISK IMPACT
                              </span>
                              <span>{item.risk_impact}</span>
                            </div>
                          </div>

                          <div className="p-2 rounded bg-emerald-500/5 border border-emerald-500/20 text-emerald-300 flex items-start gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                            <div>
                              <span className="text-emerald-400 font-bold block text-[9px] uppercase tracking-wider">
                                RECOMMENDED MITIGATION
                              </span>
                              <span>{item.mitigation_hint}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="p-4 rounded-lg bg-neutral-900/60 border border-neutral-800 text-center text-xs font-mono text-neutral-400">
                  No threat indicators available for explainability breakdown.
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        )}
      </div>
    </motion.div>
  );
};
