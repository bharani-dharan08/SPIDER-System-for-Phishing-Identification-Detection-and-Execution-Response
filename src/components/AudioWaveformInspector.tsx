import React, { useEffect, useRef, useState } from 'react';
import WaveSurfer from 'wavesurfer.js';
import {
  Play,
  Pause,
  Volume2,
  VolumeX,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  AlertTriangle,
  Sparkles,
  Activity,
  Cpu,
  Radio,
  Sliders,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceArea,
  CartesianGrid,
} from 'recharts';

interface AudioWaveformInspectorProps {
  transcript?: string | null;
  anomalyConfidence?: number;
  alerts?: string[];
}

export interface AnomalyRegion {
  id: number;
  startTime: number;
  endTime: number;
  title: string;
  description: string;
  type: 'vocoder_glitch' | 'flatline_pitch' | 'phase_discontinuity';
  confidence: number;
}

const ANOMALY_REGIONS: AnomalyRegion[] = [
  {
    id: 1,
    startTime: 1.7,
    endTime: 2.05,
    title: '3.4 kHz Neural Vocoder Jitter',
    description: 'Robotic phase discontinuity & metallic spectral artifact characteristic of ElevenLabs / WaveNet neural synthesis.',
    type: 'vocoder_glitch',
    confidence: 0.942,
  },
  {
    id: 2,
    startTime: 3.3,
    endTime: 3.65,
    title: 'Unnatural F0 Pitch Flatline',
    description: 'Fundamental frequency variance drops to 0.12 Hz (human speech baseline > 4.5 Hz), indicating zero pitch micro-tremor.',
    type: 'flatline_pitch',
    confidence: 0.968,
  },
];

// Generates a synthetic 5-second PCM WAV audio blob with neural speech & frequency anomalies
function generateVishingAudioBlob(): Blob {
  const sampleRate = 22050;
  const duration = 5.0;
  const numSamples = Math.floor(sampleRate * duration);
  const buffer = new Float32Array(numSamples);

  for (let i = 0; i < numSamples; i++) {
    const t = i / sampleRate;

    // Base pitch (male formant ~120 Hz)
    const baseF0 = 120 + Math.sin(t * 1.8) * 1.5; // Monotone flatline pitch

    // Speech harmonics
    let sample =
      Math.sin(2 * Math.PI * baseF0 * t) * 0.35 +
      Math.sin(2 * Math.PI * baseF0 * 2 * t) * 0.18 +
      Math.sin(2 * Math.PI * baseF0 * 3 * t) * 0.08;

    // Speech cadence envelope modulation
    const speechEnvelope =
      Math.abs(Math.sin(t * 3.2) * Math.cos(t * 6.5)) *
      (t < 0.3 || t > 4.7 ? 0.1 : 1.0);
    sample *= speechEnvelope;

    // Inject Frequency Anomaly 1 (1.7s - 2.05s): High-frequency metallic vocoder jitter
    if (t >= 1.7 && t <= 2.05) {
      const artifact =
        Math.sin(2 * Math.PI * 3400 * t) * 0.45 * Math.sin(2 * Math.PI * 95 * t);
      sample = sample * 0.5 + artifact;
    }

    // Inject Frequency Anomaly 2 (3.3s - 3.65s): Robotic phase glitch & sub-harmonic resonance
    if (t >= 3.3 && t <= 3.65) {
      const glitch =
        Math.sin(2 * Math.PI * 850 * t) * 0.4 * (Math.random() > 0.5 ? 1 : -1);
      sample = sample * 0.6 + glitch * 0.4;
    }

    buffer[i] = Math.max(-1, Math.min(1, sample));
  }

  // Convert Float32Array to 16-bit PCM WAV
  const wavBuffer = new ArrayBuffer(44 + buffer.length * 2);
  const view = new DataView(wavBuffer);

  const writeString = (offset: number, str: string) => {
    for (let i = 0; i < str.length; i++) {
      view.setUint8(offset + i, str.charCodeAt(i));
    }
  };

  writeString(0, 'RIFF');
  view.setUint32(4, 36 + buffer.length * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, 1, true); // Mono
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, buffer.length * 2, true);

  let offset = 44;
  for (let i = 0; i < buffer.length; i++, offset += 2) {
    const s = Math.max(-1, Math.min(1, buffer[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  }

  return new Blob([wavBuffer], { type: 'audio/wav' });
}

export const AudioWaveformInspector: React.FC<AudioWaveformInspectorProps> = ({
  transcript,
  anomalyConfidence = 0.924,
  alerts = [],
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const wavesurferRef = useRef<WaveSurfer | null>(null);

  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(5.0);
  const [playbackSpeed, setPlaybackSpeed] = useState(1.0);
  const [zoomLevel, setZoomLevel] = useState(20);
  const [isMuted, setIsMuted] = useState(false);
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyRegion | null>(ANOMALY_REGIONS[0]);
  const [isReady, setIsReady] = useState(false);

  // Spectral $F_0$ pitch timeline data for Recharts
  const pitchContourData = [
    { time: '0.0s', pitch: 120.1, anomaly: false, spectralCentroid: 1820 },
    { time: '0.5s', pitch: 120.3, anomaly: false, spectralCentroid: 1815 },
    { time: '1.0s', pitch: 119.9, anomaly: false, spectralCentroid: 1830 },
    { time: '1.5s', pitch: 120.2, anomaly: false, spectralCentroid: 1825 },
    { time: '1.8s', pitch: 142.5, anomaly: true, spectralCentroid: 3450 }, // Glitch 1
    { time: '2.0s', pitch: 120.0, anomaly: false, spectralCentroid: 1820 },
    { time: '2.5s', pitch: 120.1, anomaly: false, spectralCentroid: 1810 },
    { time: '3.0s', pitch: 120.2, anomaly: false, spectralCentroid: 1825 },
    { time: '3.4s', pitch: 92.0, anomaly: true, spectralCentroid: 2890 }, // Glitch 2
    { time: '3.8s', pitch: 120.1, anomaly: false, spectralCentroid: 1815 },
    { time: '4.2s', pitch: 119.8, anomaly: false, spectralCentroid: 1820 },
    { time: '4.7s', pitch: 120.2, anomaly: false, spectralCentroid: 1805 },
    { time: '5.0s', pitch: 120.0, anomaly: false, spectralCentroid: 1810 },
  ];

  useEffect(() => {
    if (!containerRef.current) return;

    // Create WaveSurfer instance
    const ws = WaveSurfer.create({
      container: containerRef.current,
      waveColor: 'rgba(225, 29, 72, 0.45)', // Rose wave tint
      progressColor: '#10b981', // Emerald progress fill
      cursorColor: '#38bdf8', // Cyber cyan cursor
      cursorWidth: 2,
      barWidth: 2,
      barGap: 3,
      barRadius: 2,
      height: 96,
      normalize: true,
      minPxPerSec: zoomLevel,
    });

    const blob = generateVishingAudioBlob();
    const url = URL.createObjectURL(blob);
    ws.load(url);

    ws.on('ready', () => {
      setIsReady(true);
      setDuration(ws.getDuration() || 5.0);
    });

    ws.on('audioprocess', () => {
      setCurrentTime(ws.getCurrentTime());
    });

    ws.on('finish', () => {
      setIsPlaying(false);
    });

    ws.on('interaction', () => {
      setCurrentTime(ws.getCurrentTime());
    });

    wavesurferRef.current = ws;

    return () => {
      ws.destroy();
      URL.revokeObjectURL(url);
    };
  }, []);

  // Update speed
  useEffect(() => {
    if (wavesurferRef.current && isReady) {
      wavesurferRef.current.setPlaybackRate(playbackSpeed);
    }
  }, [playbackSpeed, isReady]);

  // Update zoom
  useEffect(() => {
    if (wavesurferRef.current && isReady) {
      wavesurferRef.current.zoom(zoomLevel);
    }
  }, [zoomLevel, isReady]);

  // Update mute
  useEffect(() => {
    if (wavesurferRef.current && isReady) {
      wavesurferRef.current.setVolume(isMuted ? 0 : 1);
    }
  }, [isMuted, isReady]);

  const togglePlayPause = () => {
    if (!wavesurferRef.current) return;
    wavesurferRef.current.playPause();
    setIsPlaying(wavesurferRef.current.isPlaying());
  };

  const seekToTime = (seconds: number) => {
    if (!wavesurferRef.current || !duration) return;
    const progress = Math.max(0, Math.min(1, seconds / duration));
    wavesurferRef.current.seekTo(progress);
    setCurrentTime(seconds);
  };

  const handleSelectAnomaly = (anomaly: AnomalyRegion) => {
    setSelectedAnomaly(anomaly);
    seekToTime(anomaly.startTime);
    if (wavesurferRef.current && !isPlaying) {
      wavesurferRef.current.play();
      setIsPlaying(true);
    }
  };

  const formatTime = (timeInSec: number) => {
    const mins = Math.floor(timeInSec / 60);
    const secs = (timeInSec % 60).toFixed(1);
    return `${mins < 10 ? '0' : ''}${mins}:${parseFloat(secs) < 10 ? '0' : ''}${secs}`;
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="bg-rose-950/30 border border-rose-500/20 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 shrink-0">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-rose-300 uppercase tracking-wider">
                Vishing Payload Detected
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-medium border border-rose-500/30">
                {(anomalyConfidence * 100).toFixed(1)}% Synthetic Voice Anomaly
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5">
              Interactive frequency & wave anomaly visualizer powered by <span className="text-neutral-200 font-mono">wavesurfer.js</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-neutral-400 self-end sm:self-center">
          <Cpu className="w-3.5 h-3.5 text-emerald-400" />
          <span>Neural Vocoder Classifier: <strong className="text-neutral-200">ACTIVE</strong></span>
        </div>
      </div>

      {/* Main WaveSurfer Visualizer Box */}
      <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-4 relative overflow-hidden">
        {/* Waveform Header Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-3">
          <div className="flex items-center gap-2 text-xs font-mono text-neutral-300 font-medium">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span>High-Fidelity Audio Waveform</span>
            <span className="text-[10px] text-neutral-500 font-normal">
              (PCM 22.05kHz Mono)
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            {/* Playback timestamp */}
            <div className="bg-neutral-900 border border-neutral-800 px-3 py-1 rounded text-emerald-400 font-mono text-xs tracking-wide">
              {formatTime(currentTime)} / {formatTime(duration)}
            </div>

            {/* Speed control buttons */}
            <div className="flex items-center bg-neutral-900 border border-neutral-800 rounded p-0.5">
              {[0.5, 1.0, 1.5, 2.0].map((speed) => (
                <button
                  key={speed}
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono transition cursor-pointer ${
                    playbackSpeed === speed
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'text-neutral-400 hover:text-neutral-200'
                  }`}
                >
                  {speed}x
                </button>
              ))}
            </div>

            {/* Mute button */}
            <button
              onClick={() => setIsMuted(!isMuted)}
              className="p-1.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-neutral-200 transition cursor-pointer"
              title={isMuted ? 'Unmute Audio' : 'Mute Audio'}
            >
              {isMuted ? <VolumeX className="w-3.5 h-3.5 text-rose-400" /> : <Volume2 className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Waveform Container & Anomaly Overlays */}
        <div className="relative pt-6 pb-2">
          {/* Anomaly region markers above the waveform */}
          <div className="absolute top-0 left-0 right-0 h-6 flex items-center pointer-events-none">
            {ANOMALY_REGIONS.map((region) => {
              const startPct = (region.startTime / duration) * 100;
              const widthPct = ((region.endTime - region.startTime) / duration) * 100;
              const isSelected = selectedAnomaly?.id === region.id;

              return (
                <div
                  key={region.id}
                  style={{ left: `${startPct}%`, width: `${widthPct}%` }}
                  onClick={() => handleSelectAnomaly(region)}
                  className={`absolute h-5 rounded-t cursor-pointer pointer-events-auto border-t border-x transition flex items-center justify-center px-1 ${
                    isSelected
                      ? 'bg-rose-500/30 border-rose-500 text-rose-200 shadow-sm shadow-rose-500/50'
                      : 'bg-amber-500/20 border-amber-500/50 text-amber-300 hover:bg-amber-500/30'
                  }`}
                >
                  <span className="text-[9px] font-mono font-bold truncate">
                    ⚠️ Glitch #{region.id}
                  </span>
                </div>
              );
            })}
          </div>

          {/* WaveSurfer Div */}
          <div
            ref={containerRef}
            className="w-full bg-neutral-900/60 rounded-lg p-2 border border-neutral-800/80 cursor-pointer min-h-[96px]"
          />

          {!isReady && (
            <div className="absolute inset-0 bg-neutral-950/80 flex items-center justify-center text-xs font-mono text-neutral-400 gap-2">
              <div className="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              <span>Rendering Waveform...</span>
            </div>
          )}
        </div>

        {/* Waveform Controls Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex items-center gap-2">
            <button
              onClick={togglePlayPause}
              disabled={!isReady}
              className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-neutral-950 font-mono text-xs font-semibold transition flex items-center gap-2 cursor-pointer shadow-md shadow-emerald-500/20 disabled:opacity-50"
            >
              {isPlaying ? <Pause className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current" />}
              <span>{isPlaying ? 'Pause' : 'Play Audio'}</span>
            </button>

            <button
              onClick={() => seekToTime(0)}
              className="p-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 text-neutral-400 hover:text-neutral-200 transition cursor-pointer"
              title="Reset to 0s"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Zoom Controls */}
          <div className="flex items-center gap-2 text-xs font-mono text-neutral-400">
            <ZoomOut className="w-3.5 h-3.5" />
            <span className="text-[10px] text-neutral-500">Zoom:</span>
            <input
              type="range"
              min="10"
              max="100"
              value={zoomLevel}
              onChange={(e) => setZoomLevel(Number(e.target.value))}
              className="w-24 accent-emerald-500 bg-neutral-800 h-1.5 rounded cursor-pointer"
            />
            <ZoomIn className="w-3.5 h-3.5" />
          </div>
        </div>
      </div>

      {/* Flagged Anomaly Inspector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {ANOMALY_REGIONS.map((anomaly) => {
          const isSelected = selectedAnomaly?.id === anomaly.id;
          return (
            <div
              key={anomaly.id}
              onClick={() => handleSelectAnomaly(anomaly)}
              className={`p-3.5 rounded-xl border transition cursor-pointer ${
                isSelected
                  ? 'bg-neutral-900 border-rose-500/50 ring-1 ring-rose-500/30'
                  : 'bg-neutral-950 border-neutral-800 hover:border-neutral-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  <span className="text-xs font-mono font-semibold text-neutral-200">
                    {anomaly.title}
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                  {anomaly.startTime.toFixed(1)}s - {anomaly.endTime.toFixed(1)}s
                </span>
              </div>
              <p className="text-xs text-neutral-400 leading-relaxed">
                {anomaly.description}
              </p>
              <div className="mt-2.5 flex items-center justify-between text-[10px] font-mono text-neutral-500 pt-2 border-t border-neutral-800/60">
                <span>Confidence: <strong className="text-rose-400">{(anomaly.confidence * 100).toFixed(1)}%</strong></span>
                <span className="text-emerald-400 hover:underline">Click to seek waveform →</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Spectral Pitch Contour ($F_0$) Chart */}
      <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-neutral-300">
            <Sliders className="w-3.5 h-3.5 text-rose-400" />
            <span>Instantaneous Pitch Contour ($F_0$ Hz) & Spectral Centroid</span>
          </div>
          <span className="text-[10px] font-mono text-neutral-500">
            Baseline Human SD &gt; 4.5Hz vs Monotone Neural SD = 0.38Hz
          </span>
        </div>

        <div className="h-40 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={pitchContourData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f1f1f" />
              <XAxis dataKey="time" stroke="#525252" tick={{ fontSize: 10 }} />
              <YAxis stroke="#525252" tick={{ fontSize: 10 }} domain={[80, 160]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0a0a0a',
                  borderColor: '#262626',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />
              <ReferenceArea x1="1.8s" x2="2.0s" fill="#f43f5e" fillOpacity={0.25} />
              <ReferenceArea x1="3.0s" x2="3.4s" fill="#f43f5e" fillOpacity={0.25} />
              <Line
                type="monotone"
                dataKey="pitch"
                stroke="#f43f5e"
                strokeWidth={2}
                dot={(props: any) => {
                  const { cx, cy, payload } = props;
                  if (payload.anomaly) {
                    return (
                      <circle
                        key={payload.time}
                        cx={cx}
                        cy={cy}
                        r={5}
                        fill="#f43f5e"
                        stroke="#fff"
                        strokeWidth={1.5}
                      />
                    );
                  }
                  return <circle key={payload.time} cx={cx} cy={cy} r={2} fill="#10b981" />;
                }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Audio Transcript & Word-Level Alignment */}
      {transcript && (
        <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-neutral-300">
            <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
            <span>Decoded Vishing Speech Transcript</span>
          </div>
          <div className="p-3 rounded-lg bg-neutral-900/80 border border-neutral-800 text-xs font-mono text-neutral-200 leading-relaxed italic">
            "{transcript}"
          </div>
        </div>
      )}
    </div>
  );
};
