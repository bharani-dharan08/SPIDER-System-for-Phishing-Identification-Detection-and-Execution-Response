import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { ChevronRight, ChevronDown, Copy, Check, Terminal, Code2, Table, ShieldCheck, Activity, Radio } from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
} from 'recharts';
import { FusedPayload, ThreatAnalysisResult } from '../types';
import { AudioWaveformInspector } from './AudioWaveformInspector';

interface TelemetryAccordionProps {
  fused: FusedPayload;
  result: ThreatAnalysisResult;
}

export const TelemetryAccordion: React.FC<TelemetryAccordionProps> = ({
  fused,
  result,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const isVishing = Boolean(
    fused.synthetic_voice_anomaly ||
      fused.transcript ||
      result.primary_vector?.toLowerCase().includes('vishing') ||
      result.primary_vector?.toLowerCase().includes('voice') ||
      result.primary_vector?.toLowerCase().includes('audio')
  );

  const [activeTab, setActiveTab] = useState<'waveform' | 'charts' | 'raw_json' | 'headers' | 'audit'>(
    isVishing ? 'waveform' : 'charts'
  );
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isVishing) {
      setActiveTab('waveform');
    }
  }, [fused, isVishing]);

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(fused, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const acousticData = [
    { sample: '0.0s', pitch: 120, centroid: 1800 },
    { sample: '0.5s', pitch: 121, centroid: 1810 },
    { sample: '1.0s', pitch: 119, centroid: 1795 },
    { sample: '1.5s', pitch: 120, centroid: 1805 },
    { sample: '2.0s', pitch: 118, centroid: 1790 },
    { sample: '2.5s', pitch: 120, centroid: 1800 },
    { sample: '3.0s', pitch: 119, centroid: 1802 },
  ];

  const burstinessData = [
    { sentence: 'S1', length: 14 },
    { sentence: 'S2', length: 15 },
    { sentence: 'S3', length: 14 },
    { sentence: 'S4', length: 15 },
    { sentence: 'S5', length: 14 },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.3 }}
      className="glass-card rounded-xl border border-white/10 overflow-hidden"
    >
      {/* Accordion Toggle Bar */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-5 py-3.5 bg-neutral-950/80 hover:bg-neutral-900/60 transition flex items-center justify-between text-left cursor-pointer border-b border-white/5"
      >
        <div className="flex items-center gap-2.5">
          <Terminal className="w-4 h-4 text-neutral-400" />
          <span className="text-xs font-mono font-medium text-neutral-300 uppercase tracking-wider">
            ANALYST TELEMETRY & INSPECTOR
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-neutral-900 border border-neutral-800 text-neutral-400">
            Progressive Disclosure
          </span>
          {isVishing && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 border border-rose-500/30 text-rose-300 font-medium flex items-center gap-1">
              <Radio className="w-3 h-3 text-rose-400 animate-pulse" />
              Vishing Audio Wavesurfer
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 text-neutral-400 text-xs font-mono">
          <span>{isOpen ? 'Collapse' : 'Expand Details'}</span>
          {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {/* Expanded Accordion Area */}
      {isOpen && (
        <div className="p-5 space-y-5 bg-neutral-950/40">
          {/* Sub Navigation */}
          <div className="flex flex-wrap border-b border-white/5 gap-3 text-xs font-mono">
            {isVishing && (
              <button
                onClick={() => setActiveTab('waveform')}
                className={`pb-2 transition flex items-center gap-1.5 cursor-pointer ${
                  activeTab === 'waveform'
                    ? 'border-b-2 border-rose-400 text-rose-300 font-semibold'
                    : 'text-rose-400/70 hover:text-rose-300'
                }`}
              >
                <Radio className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                Audio Waveform Inspector
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-mono">
                  wavesurfer.js
                </span>
              </button>
            )}
            <button
              onClick={() => setActiveTab('charts')}
              className={`pb-2 transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'charts'
                  ? 'border-b-2 border-neutral-200 text-neutral-100 font-medium'
                  : 'text-neutral-500 hover:text-neutral-300'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Recharts Analytics
            </button>
            <button
              onClick={() => setActiveTab('raw_json')}
              className={`pb-2 transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'raw_json'
                  ? 'border-b-2 border-neutral-200 text-neutral-100 font-medium'
                  : 'text-neutral-500 hover:text-neutral-300'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              Raw Fused JSON
            </button>
            <button
              onClick={() => setActiveTab('headers')}
              className={`pb-2 transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'headers'
                  ? 'border-b-2 border-neutral-200 text-neutral-100 font-medium'
                  : 'text-neutral-500 hover:text-neutral-300'
              }`}
            >
              <Table className="w-3.5 h-3.5" />
              RFC822 Hop Trace
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`pb-2 transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'audit'
                  ? 'border-b-2 border-neutral-200 text-neutral-100 font-medium'
                  : 'text-neutral-500 hover:text-neutral-300'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Sanitization Audit
            </button>
          </div>

          {/* Sub Tab: Audio Waveform Inspector */}
          {activeTab === 'waveform' && (
            <AudioWaveformInspector
              transcript={fused.transcript}
              anomalyConfidence={fused.anomaly_confidence || 0.924}
              alerts={fused.sanitization_alerts}
            />
          )}

          {/* Sub Tab 1: Recharts Analytics */}
          {activeTab === 'charts' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800/80">
                <div className="text-[11px] font-mono text-neutral-400 mb-2 font-medium">
                  Acoustic Pitch Contour ($F_0$ Hz)
                </div>
                <div className="h-44 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={acousticData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1f1f1f" />
                      <XAxis dataKey="sample" stroke="#525252" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#525252" tick={{ fontSize: 10 }} domain={[100, 140]} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#262626', fontSize: '11px' }}
                      />
                      <Line
                        type="monotone"
                        dataKey="pitch"
                        stroke="#f43f5e"
                        strokeWidth={1.5}
                        dot={{ r: 2, fill: '#f43f5e' }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800/80">
                <div className="text-[11px] font-mono text-neutral-400 mb-2 font-medium">
                  Sentence Burstiness Variance (Words / Sentence)
                </div>
                <div className="h-44 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={burstinessData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1f1f1f" />
                      <XAxis dataKey="sentence" stroke="#525252" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#525252" tick={{ fontSize: 10 }} domain={[0, 20]} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#262626', fontSize: '11px' }}
                      />
                      <Bar dataKey="length" fill="#a3a3a3" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}

          {/* Sub Tab 2: Raw JSON */}
          {activeTab === 'raw_json' && (
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 relative">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-mono text-neutral-400 uppercase">
                  Fused Evidence Schema
                </span>
                <button
                  onClick={handleCopyJson}
                  className="px-2.5 py-1 rounded bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 text-[11px] font-mono text-neutral-300 transition flex items-center gap-1 cursor-pointer"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="font-mono text-xs text-neutral-300 bg-neutral-900/60 p-3 rounded-lg overflow-x-auto border border-neutral-800/80 leading-relaxed max-h-72">
                {JSON.stringify(fused, null, 2)}
              </pre>
            </div>
          )}

          {/* Sub Tab 3: Headers Table */}
          {activeTab === 'headers' && (
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 overflow-x-auto">
              <table className="w-full text-xs font-mono text-left text-neutral-300">
                <thead className="bg-neutral-900 text-neutral-400 text-[11px] border-b border-neutral-800">
                  <tr>
                    <th className="p-2">Header Field</th>
                    <th className="p-2">Parsed Value</th>
                    <th className="p-2">Validation Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800/60">
                  <tr>
                    <td className="p-2 text-neutral-400">From</td>
                    <td className="p-2">{fused.header_metadata?.From || 'cfo@acme-corporation.com'}</td>
                    <td className="p-2 text-neutral-300">Display Header</td>
                  </tr>
                  <tr>
                    <td className="p-2 text-neutral-400">Reply-To</td>
                    <td className="p-2">{fused.header_metadata?.['Reply-To'] || 'sarah.jenkins.direct@mail-routing.xyz'}</td>
                    <td className="p-2 text-rose-400 font-medium">Domain Discrepancy</td>
                  </tr>
                  <tr>
                    <td className="p-2 text-neutral-400">SPF / DMARC</td>
                    <td className="p-2">fail / softfail</td>
                    <td className="p-2 text-rose-400">Alignment Failed</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* Sub Tab 4: Audit */}
          {activeTab === 'audit' && (
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
              <div className="text-[11px] font-mono text-neutral-400 uppercase mb-2">
                Sanitization & Perceptual Asymmetry Interceptions ({fused.sanitization_alerts.length})
              </div>
              {fused.sanitization_alerts.map((alert, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-neutral-900 border border-neutral-800 font-mono text-xs text-neutral-300 flex items-center gap-2"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-neutral-400 shrink-0" />
                  <span>{alert}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
};
