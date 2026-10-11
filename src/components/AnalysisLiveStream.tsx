import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Terminal,
  Play,
  Pause,
  RotateCcw,
  Copy,
  Check,
  Zap,
  Cpu,
  Radio,
  FileText,
  Mail,
  Image as ImageIcon,
  Mic,
  GitMerge,
  Filter,
} from 'lucide-react';
import { FusedPayload, ThreatAnalysisResult } from '../types';

export interface LogEntry {
  id: string;
  timestamp: string;
  channel: 'TEXT' | 'EMAIL' | 'IMAGE' | 'AUDIO' | 'FUSION';
  level: 'INFO' | 'TRACE' | 'WARN' | 'CRITICAL';
  message: string;
  details?: string;
  latencyMs?: number;
}

interface AnalysisLiveStreamProps {
  isLoading: boolean;
  fused: FusedPayload;
  result: ThreatAnalysisResult;
}

export const AnalysisLiveStream: React.FC<AnalysisLiveStreamProps> = ({
  isLoading,
  fused,
  result,
}) => {
  const [activeChannel, setActiveChannel] = useState<
    'ALL' | 'TEXT' | 'EMAIL' | 'IMAGE' | 'AUDIO' | 'FUSION'
  >('ALL');
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [autoLiveUpdate, setAutoLiveUpdate] = useState(true);
  const [lastPollTime, setLastPollTime] = useState<string | null>(null);
  const [pollCount, setPollCount] = useState<number>(0);
  const [copied, setCopied] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-Live Update: Poll backend status endpoint every 3 seconds while long-running analysis or live stream is active
  useEffect(() => {
    if (!autoLiveUpdate || isPaused) return;

    const fetchStatus = async () => {
      try {
        const startTime = performance.now();
        const res = await fetch('/api/rate-limit/status');
        const duration = performance.now() - startTime;
        const nowString =
          new Date().toTimeString().split(' ')[0] +
          '.' +
          String(Math.floor(Math.random() * 900 + 100));

        if (res.ok) {
          const data = await res.json();
          const pollLog: LogEntry = {
            id: 'poll-' + Date.now() + '-' + Math.random(),
            timestamp: nowString,
            channel: 'FUSION',
            level: 'INFO',
            message: `[AUTO-LIVE STREAM 3s] Backend Analyzer Status: ${
              data.status?.toUpperCase() || 'HEALTHY'
            } | Middleware: ${data.middleware || 'APIRateLimiterMiddleware'}`,
            details: `Rate Limit Max: ${
              data.limits?.global_max_requests_per_window || 100
            } RPM | Protection: ACTIVE | Window: ${data.limits?.window_seconds || 60}s`,
            latencyMs: parseFloat(duration.toFixed(1)),
          };
          setLogs((prev) => [...prev.slice(-120), pollLog]);
          setLastPollTime(new Date().toLocaleTimeString());
          setPollCount((prev) => prev + 1);
        }
      } catch (err) {
        console.warn('Auto-Live polling error:', err);
      }
    };

    fetchStatus();
    const pollInterval = setInterval(fetchStatus, 3000);
    return () => clearInterval(pollInterval);
  }, [autoLiveUpdate, isLoading, isPaused]);

  // Generate realistic live pipeline execution logs based on current payload state
  useEffect(() => {
    const now = new Date();
    const getTime = (offsetMs: number) => {
      const d = new Date(now.getTime() + offsetMs);
      return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
    };

    const initialLogs: LogEntry[] = [
      {
        id: 'log-01',
        timestamp: getTime(-1800),
        channel: 'FUSION',
        level: 'INFO',
        message: 'Multimodal Ingest Dispatcher initiated parallel pipeline workers (4 threads)',
        latencyMs: 1.2,
      },
      {
        id: 'log-02',
        timestamp: getTime(-1750),
        channel: 'EMAIL',
        level: 'TRACE',
        message: 'Extracting RFC-822 headers and authentication envelope fields...',
        details: `From: ${fused.header_metadata?.From || 'cfo@acme-corp.com'}, Reply-To: ${
          fused.header_metadata?.['Reply-To'] || 'direct@settlement.xyz'
        }`,
        latencyMs: 4.8,
      },
      {
        id: 'log-03',
        timestamp: getTime(-1680),
        channel: 'EMAIL',
        level: fused.header_metadata?.reply_to_mismatch ? 'WARN' : 'INFO',
        message: fused.header_metadata?.reply_to_mismatch
          ? 'ANOMALY: From vs Reply-To address domain mismatch detected'
          : 'Header alignment: Reply-To matches From domain',
        details: `SPF: ${fused.header_metadata?.spf || 'fail'} | DKIM: ${
          fused.header_metadata?.dkim || 'fail'
        } | DMARC: ${fused.header_metadata?.dmarc || 'fail'}`,
        latencyMs: 8.3,
      },
      {
        id: 'log-04',
        timestamp: getTime(-1520),
        channel: 'TEXT',
        level: 'TRACE',
        message: 'Tokenizing transcript buffer and running regex sanitization filters...',
        details: `Buffer size: ${(fused.transcript || '').length} chars`,
        latencyMs: 12.1,
      },
      {
        id: 'log-05',
        timestamp: getTime(-1410),
        channel: 'TEXT',
        level: result.is_prompt_injection_attempt ? 'CRITICAL' : 'INFO',
        message: result.is_prompt_injection_attempt
          ? 'SECURITY ALERT: Adversarial system prompt injection keywords detected'
          : 'Zero-width space & hidden character sanitization scan passed',
        details: result.is_prompt_injection_attempt
          ? 'Matched tokens: [SYSTEM INSTRUCTION], [DEBUG MODE OVERRIDE]'
          : 'No hidden unicode obfuscation markers found',
        latencyMs: 18.5,
      },
      {
        id: 'log-06',
        timestamp: getTime(-1300),
        channel: 'IMAGE',
        level: 'TRACE',
        message: 'Running Tesseract OCR & OpenCV barcode matrix decoder...',
        details: fused.ocr_text
          ? `Extracted text length: ${fused.ocr_text.length} chars`
          : 'No optical barcode or text detected in visual attachment',
        latencyMs: 24.0,
      },
      {
        id: 'log-07',
        timestamp: getTime(-1150),
        channel: 'AUDIO',
        level: fused.synthetic_voice_anomaly ? 'CRITICAL' : 'INFO',
        message: fused.synthetic_voice_anomaly
          ? 'SPECTRAL ANOMALY DETECTED: ElevenLabs synthetic voice artifact signature matched'
          : 'Audio spectral analysis: Natural formant variance confirmed',
        details: fused.synthetic_voice_anomaly
          ? `Confidence: ${((fused.anomaly_confidence || 0.95) * 100).toFixed(1)}% deepfake probability`
          : 'Phase consistency index within normal human speech threshold',
        latencyMs: 31.2,
      },
      {
        id: 'log-08',
        timestamp: getTime(-900),
        channel: 'FUSION',
        level: 'TRACE',
        message: 'Aggregating cross-modal indicators of compromise into decision matrix...',
        details: `IoCs collected: ${result.indicators_of_compromise.length} items`,
        latencyMs: 42.8,
      },
      {
        id: 'log-09',
        timestamp: getTime(-300),
        channel: 'FUSION',
        level: result.threat_score >= 8.5 ? 'CRITICAL' : result.threat_score >= 5.0 ? 'WARN' : 'INFO',
        message: `LATE FUSION FINAL EVALUATION: Threat Score ${result.threat_score.toFixed(1)}/10.0 (${result.primary_vector})`,
        details: `Executive summary: ${result.executive_summary.slice(0, 100)}...`,
        latencyMs: 56.4,
      },
    ];

    setLogs(initialLogs);
  }, [fused, result]);

  // Live log generator simulation when isLoading is true
  useEffect(() => {
    if (!isLoading || isPaused) return;

    const interval = setInterval(() => {
      const channels: Array<'TEXT' | 'EMAIL' | 'IMAGE' | 'AUDIO' | 'FUSION'> = [
        'TEXT',
        'EMAIL',
        'IMAGE',
        'AUDIO',
        'FUSION',
      ];
      const selectedChan = channels[Math.floor(Math.random() * channels.length)];
      const nowString = new Date().toTimeString().split(' ')[0] + '.' + String(Math.floor(Math.random() * 900 + 100));

      const newLog: LogEntry = {
        id: 'live-' + Date.now() + Math.random(),
        timestamp: nowString,
        channel: selectedChan,
        level: Math.random() > 0.8 ? 'WARN' : 'INFO',
        message: `Streaming thread execution [${selectedChan}_WORKER]: Processing byte chunk #${Math.floor(
          Math.random() * 8999 + 1000
        )}`,
        details: `Thread ID: 0x${Math.floor(Math.random() * 0xffff).toString(16)} | Memory: ${(
          Math.random() * 20 +
          12
        ).toFixed(1)}MB`,
        latencyMs: parseFloat((Math.random() * 15 + 2).toFixed(1)),
      };

      setLogs((prev) => [...prev.slice(-100), newLog]);
    }, 400);

    return () => clearInterval(interval);
  }, [isLoading, isPaused]);

  // Auto scroll terminal log container
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const filteredLogs = logs.filter(
    (log) => activeChannel === 'ALL' || log.channel === activeChannel
  );

  const handleCopyLogs = () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] [${l.channel}] [${l.level}] ${l.message} ${l.details ? `(${l.details})` : ''}`)
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const channelIcon = (channel: string) => {
    switch (channel) {
      case 'TEXT':
        return <FileText className="w-3 h-3 text-amber-400" />;
      case 'EMAIL':
        return <Mail className="w-3 h-3 text-cyan-400" />;
      case 'IMAGE':
        return <ImageIcon className="w-3 h-3 text-emerald-400" />;
      case 'AUDIO':
        return <Mic className="w-3 h-3 text-purple-400" />;
      case 'FUSION':
        return <GitMerge className="w-3 h-3 text-rose-400" />;
      default:
        return <Terminal className="w-3 h-3 text-neutral-400" />;
    }
  };

  const levelBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'WARN':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'TRACE':
        return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/20';
      default:
        return 'bg-neutral-800 text-neutral-300 border-neutral-700';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="glass-card rounded-2xl border border-white/10 bg-[#020406]/95 text-neutral-100 p-5 space-y-4 font-mono relative overflow-hidden shadow-2xl"
    >
      {/* Background Cyber HUD Glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-emerald-500/3 rounded-full blur-3xl pointer-events-none" />

      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center text-emerald-400 shadow-inner">
            <Terminal className="w-4.5 h-4.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-tight font-sans">
                Analysis Live-Stream Console
              </h3>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-full border flex items-center gap-1 ${
                  isLoading
                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    isLoading ? 'bg-amber-400 animate-ping' : 'bg-emerald-400'
                  }`}
                />
                {isLoading ? 'STREAMING ACTIVE' : 'PIPELINE IDLE'}
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5 font-sans">
              Parallel execution telemetry from backend extractors (Text, Email, Image, Audio & Fusion Core)
            </p>
          </div>
        </div>

        {/* Console Action Controls */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <button
            onClick={() => setAutoLiveUpdate(!autoLiveUpdate)}
            className={`px-2.5 py-1 rounded-lg border transition cursor-pointer flex items-center gap-1.5 ${
              autoLiveUpdate
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-sm font-semibold'
                : 'bg-neutral-900 hover:bg-neutral-800 text-neutral-400 border-neutral-800'
            }`}
            title="Toggle 3-second backend status polling for long-running analysis"
          >
            <Radio className={`w-3 h-3 ${autoLiveUpdate ? 'text-emerald-400 animate-pulse' : 'text-neutral-500'}`} />
            <span>Auto-Live {autoLiveUpdate ? '3s ON' : 'OFF'}</span>
          </button>

          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-2.5 py-1 rounded-lg border transition cursor-pointer flex items-center gap-1.5 ${
              isPaused
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                : 'bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border-neutral-800'
            }`}
          >
            {isPaused ? <Play className="w-3 h-3 text-amber-400" /> : <Pause className="w-3 h-3" />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>

          <button
            onClick={handleCopyLogs}
            className="px-2.5 py-1 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 transition cursor-pointer flex items-center gap-1.5"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>

          <button
            onClick={() => setLogs([])}
            className="px-2.5 py-1 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white border border-neutral-800 transition cursor-pointer flex items-center gap-1.5"
            title="Clear Console Buffer"
          >
            <RotateCcw className="w-3 h-3" />
            Clear
          </button>
        </div>
      </div>

      {/* Channel Filter Selector Pills */}
      <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono pb-1 border-b border-white/5">
        <span className="text-neutral-500 text-[10px] mr-1 flex items-center gap-1">
          <Filter className="w-3 h-3" /> CHANNEL:
        </span>
        {(['ALL', 'TEXT', 'EMAIL', 'IMAGE', 'AUDIO', 'FUSION'] as const).map((chan) => (
          <button
            key={chan}
            onClick={() => setActiveChannel(chan)}
            className={`px-2.5 py-1 rounded-md transition cursor-pointer text-[11px] flex items-center gap-1.5 ${
              activeChannel === chan
                ? 'bg-neutral-800 text-white font-bold border border-white/15'
                : 'text-neutral-400 hover:text-neutral-200 bg-neutral-900/50 border border-transparent'
            }`}
          >
            {channelIcon(chan)}
            {chan}
          </button>
        ))}
      </div>

      {/* Main Terminal Output Log Screen */}
      <div
        ref={scrollRef}
        className="h-64 overflow-y-auto bg-black/80 rounded-xl p-3 border border-white/10 font-mono text-xs space-y-2 scrollbar-thin shadow-inner"
      >
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-neutral-500 text-xs italic">
            Console log buffer is empty. Run an analysis or select another channel filter.
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div
              key={log.id}
              className="flex flex-col sm:flex-row sm:items-start gap-2 p-1.5 rounded hover:bg-white/[0.03] transition border-b border-white/[0.03] last:border-0"
            >
              {/* Timestamp & Channel */}
              <div className="flex items-center gap-2 shrink-0 text-[10px]">
                <span className="text-neutral-500">{log.timestamp}</span>
                <span className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-300 font-bold flex items-center gap-1">
                  {channelIcon(log.channel)}
                  {log.channel}
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded border font-bold text-[9px] ${levelBadge(
                    log.level
                  )}`}
                >
                  {log.level}
                </span>
              </div>

              {/* Message Content */}
              <div className="flex-1 space-y-0.5 text-neutral-200">
                <p className="text-xs">{log.message}</p>
                {log.details && (
                  <p className="text-[10px] text-neutral-400 font-sans">{log.details}</p>
                )}
              </div>

              {/* Latency */}
              {log.latencyMs !== undefined && (
                <div className="text-[10px] text-neutral-500 shrink-0 font-mono">
                  {log.latencyMs.toFixed(1)}ms
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Micro Metrics Status Footer */}
      <div className="pt-2 flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono text-neutral-400 border-t border-white/5">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <Cpu className="w-3 h-3 text-cyan-400" /> Active Threads: <span className="text-neutral-200 font-bold">4/4 Parallel</span>
          </span>
          <span className="flex items-center gap-1">
            <Zap className="w-3 h-3 text-amber-400" /> Total Events: <span className="text-neutral-200 font-bold">{logs.length}</span>
          </span>
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-1.5 cursor-pointer text-neutral-400 hover:text-neutral-200">
            <input
              type="checkbox"
              checked={autoLiveUpdate}
              onChange={(e) => setAutoLiveUpdate(e.target.checked)}
              className="rounded bg-neutral-900 border-neutral-800 text-emerald-500 focus:ring-0 cursor-pointer"
            />
            <span className="flex items-center gap-1">
              <Radio className={`w-2.5 h-2.5 ${autoLiveUpdate ? 'text-emerald-400 animate-pulse' : 'text-neutral-500'}`} />
              Auto-Live Poll (3s)
              {autoLiveUpdate && lastPollTime && (
                <span className="text-[9px] text-emerald-400/80 font-mono">
                  ({pollCount} polls • last {lastPollTime})
                </span>
              )}
            </span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-neutral-400">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded bg-neutral-900 border-neutral-800 text-emerald-500 focus:ring-0 cursor-pointer"
            />
            <span>Auto-Scroll</span>
          </label>
        </div>
      </div>
    </motion.div>
  );
};
