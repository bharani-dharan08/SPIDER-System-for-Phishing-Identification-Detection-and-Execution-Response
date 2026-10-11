import React, { useState, useRef, useEffect } from 'react';
import { Mic, Upload, Volume2, AlertTriangle, CheckCircle, Activity, Sparkles } from 'lucide-react';
import { FusedPayload } from '../types';

interface AudioIngestProps {
  fused: FusedPayload;
  onChange: (updated: Partial<FusedPayload>) => void;
}

export const AudioIngest: React.FC<AudioIngestProps> = ({ fused, onChange }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [pitchVariance, setPitchVariance] = useState<number>(fused.synthetic_voice_anomaly ? 12.4 : 38.6);
  const [isAiVoice, setIsAiVoice] = useState<boolean>(Boolean(fused.synthetic_voice_anomaly));
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // Sync state if fused payload changes externally
  useEffect(() => {
    setIsAiVoice(Boolean(fused.synthetic_voice_anomaly));
    setPitchVariance(fused.synthetic_voice_anomaly ? 12.4 : 38.6);
  }, [fused.synthetic_voice_anomaly]);

  // Waveform visualization animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let phase = 0;
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const width = canvas.width;
      const height = canvas.height;
      const centerY = height / 2;

      // Draw background cyber grid lines
      ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, centerY);
      ctx.lineTo(width, centerY);
      ctx.stroke();

      // Draw acoustic wave
      ctx.lineWidth = 2;
      ctx.strokeStyle = isAiVoice ? '#ef4444' : '#38bdf8';
      ctx.beginPath();

      const numBars = 64;
      const barWidth = width / numBars;

      for (let i = 0; i < numBars; i++) {
        // If simulated AI voice, use flatter, more repetitive synthetic sinusoidal harmonics
        const freq = isAiVoice ? 0.08 : 0.04;
        const amplitude = isAiVoice
          ? 18 + Math.sin(i * 0.3 + phase) * 8
          : 26 + Math.sin(i * 0.2 + phase) * 16 + Math.sin(i * 0.5 - phase) * 10;

        const x = i * barWidth;
        const yTop = centerY - amplitude;
        const yBottom = centerY + amplitude;

        ctx.moveTo(x, centerY);
        ctx.lineTo(x, yTop);
        ctx.moveTo(x, centerY);
        ctx.lineTo(x, yBottom);
      }
      ctx.stroke();

      phase += isPlaying ? 0.12 : 0.02;
      animationFrameRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [isPlaying, isAiVoice]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);

    // Realistic voice extraction simulation from uploaded file name/content
    const isSuspicious = file.name.toLowerCase().includes('vishing') || file.name.toLowerCase().includes('urgent') || file.name.toLowerCase().includes('helpdesk');
    const simTranscript = isSuspicious
      ? "Hello, this is Corporate IT Support with an urgent update regarding your Okta multi-factor authentication token. We detected an unauthorized login attempt from St. Petersburg. Please approve the incoming Duo push notification immediately to retain account access."
      : "Hi team, just confirming the quarterly project kickoff call for tomorrow afternoon. Let me know if you need any adjustments to the schedule.";

    const detectedAiAnomaly = isSuspicious;
    setIsAiVoice(detectedAiAnomaly);
    setPitchVariance(detectedAiAnomaly ? 11.8 : 42.1);

    const alerts = [...fused.sanitization_alerts];
    if (detectedAiAnomaly) {
      alerts.push('Atypically low pitch modulation (monotone fundamental frequency variance)');
      alerts.push('Whisper STT extracted authority manipulation & MFA bypass lure');
    }

    onChange({
      transcript: simTranscript,
      synthetic_voice_anomaly: detectedAiAnomaly,
      anomaly_confidence: detectedAiAnomaly ? 0.94 : 0.12,
      sanitization_alerts: alerts,
    });
  };

  const handleLoadSampleDeepfake = () => {
    setFileName('voicemail_it_helpdesk_urgent.wav');
    setIsAiVoice(true);
    setPitchVariance(10.9);
    onChange({
      transcript:
        'Hello Mark, this is Dave from Corporate IT Global Security. We detected an anomalous Russian login attempt on your Okta session. I need you to approve the Duo push notification sending to your phone right now to revoke the attacker session, or your corporate credentials will be terminated in 15 minutes.',
      synthetic_voice_anomaly: true,
      anomaly_confidence: 0.95,
      sanitization_alerts: [
        ...fused.sanitization_alerts,
        'Atypically low fundamental frequency pitch modulation (robotic neural vocoder signature)',
        'Pretexting detected: Authority manipulation paired with manufactured urgency and MFA fatigue lure',
      ],
    });
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
            <Mic className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 flex items-center gap-2">
              Audio Payload Ingest (Vishing)
              <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                Whisper STT + Librosa MFCCs
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Analyzes .mp3 / .wav for synthesized vocoder cadence, monotone pitch variance, and coercive transcripts.
            </p>
          </div>
        </div>

        <button
          onClick={handleLoadSampleDeepfake}
          className="text-xs px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1.5 cursor-pointer"
        >
          <Sparkles className="w-3.5 h-3.5" />
          Load Deepfake Sample
        </button>
      </div>

      {/* Waveform Canvas & Controls */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 mb-4">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
          <span className="flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            ACOUSTIC WAVEFORM & SPECTRAL HARMONICS
          </span>
          <span className={isAiVoice ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
            {isAiVoice ? '● VOCAL ARTIFACT DETECTED' : '● NATURAL VOCAL DYNAMICS'}
          </span>
        </div>

        <canvas
          ref={canvasRef}
          width={640}
          height={80}
          className="w-full h-20 rounded bg-slate-950/80 border border-slate-900 block"
        />

        <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60 text-xs">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1 text-xs cursor-pointer"
            >
              <Volume2 className="w-3.5 h-3.5" />
              {isPlaying ? 'Pause Audio' : 'Preview Wave'}
            </button>
            <span className="text-slate-400 text-xs font-mono">
              {fileName || 'No file selected (using memory buffer)'}
            </span>
          </div>

          <label className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 cursor-pointer flex items-center gap-1 text-xs transition">
            <Upload className="w-3.5 h-3.5" />
            Upload .mp3/.wav
            <input
              type="file"
              accept="audio/mp3,audio/wav,audio/ogg"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>
      </div>

      {/* Librosa Acoustic Feature Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-2.5">
          <div className="text-[11px] text-slate-400 font-mono">PITCH VARIATION (F0 STD)</div>
          <div className="text-lg font-bold font-mono mt-0.5 flex items-center justify-between">
            <span className={pitchVariance < 18 ? 'text-red-400' : 'text-emerald-400'}>
              {pitchVariance.toFixed(1)} Hz
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
              {pitchVariance < 18 ? 'Monotone / Robotic' : 'Natural Modulation'}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className={`h-full ${pitchVariance < 18 ? 'bg-red-500' : 'bg-emerald-500'}`}
              style={{ width: `${Math.min(100, (pitchVariance / 50) * 100)}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-2.5">
          <div className="text-[11px] text-slate-400 font-mono">13-COEFF MFCC VARIANCE</div>
          <div className="text-lg font-bold font-mono mt-0.5 flex items-center justify-between">
            <span className={isAiVoice ? 'text-amber-400' : 'text-emerald-400'}>
              {isAiVoice ? '13.2 (Suppressed)' : '28.9 (Rich)'}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
              Timbre Dynamics
            </span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {isAiVoice ? 'Vocoder phase flattening' : 'Dynamic acoustic resonance'}
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-2.5">
          <div className="text-[11px] text-slate-400 font-mono">AI SYNTHETIC CLASSIFICATION</div>
          <div className="text-lg font-bold font-mono mt-0.5 flex items-center gap-1.5">
            {isAiVoice ? (
              <>
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span className="text-red-400">Deepfake (94%)</span>
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span className="text-emerald-400">Human Voice</span>
              </>
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {isAiVoice ? 'Flagged for Vishing Late Fusion' : 'Normal human acoustic range'}
          </div>
        </div>
      </div>

      {/* Whisper Speech-to-Text Transcript Editor */}
      <div>
        <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono flex items-center justify-between">
          <span>[TRANSCRIPT] WHISPER SPEECH-TO-TEXT EXTRACTION</span>
          <span className="text-slate-400 text-[11px] font-normal">
            Editable for forensic refinement
          </span>
        </label>
        <textarea
          rows={3}
          value={fused.transcript || ''}
          onChange={(e) => onChange({ transcript: e.target.value })}
          placeholder="Speech-to-text transcript from audio payload will appear here..."
          className="w-full bg-slate-950 border border-slate-800 focus:border-blue-500 rounded-lg p-2.5 text-xs text-slate-200 font-mono resize-y focus:outline-none"
        />
      </div>
    </div>
  );
};
