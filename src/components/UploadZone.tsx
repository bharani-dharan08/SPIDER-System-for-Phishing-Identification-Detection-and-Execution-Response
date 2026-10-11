import React, { useState } from 'react';
import { UploadCloud, FileText, CheckCircle2, Sparkles, ArrowUpRight } from 'lucide-react';
import { motion } from 'motion/react';

interface UploadZoneProps {
  onPayloadSubmit: (payload: { type: 'file' | 'text' | 'url'; content: string; inspectEmbeddedLinks?: boolean; file?: File }) => void;
  onPresetSelect: (presetId: string) => void;
  isLoading: boolean;
}

export const UploadZone: React.FC<UploadZoneProps> = ({
  onPayloadSubmit,
  onPresetSelect,
  isLoading,
}) => {
  const [activeTab, setActiveTab] = useState<'text' | 'url' | 'upload'>('url');
  const [pastedText, setPastedText] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [inspectEmbeddedLinks, setInspectEmbeddedLinks] = useState(true);
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      onPayloadSubmit({ type: 'file', content: file.name, file });
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      onPayloadSubmit({ type: 'file', content: file.name, file });
    }
  };

  const handleTextSubmit = () => {
    if (!pastedText.trim()) return;
    onPayloadSubmit({ type: 'text', content: pastedText });
  };

  const handleUrlSubmit = () => {
    if (!targetUrl.trim()) return;
    onPayloadSubmit({ type: 'url', content: targetUrl, inspectEmbeddedLinks });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="glass-card rounded-xl p-5 border border-white/10 bg-[#080D11]"
    >
      {/* Header & 3-Way Minimalist Toggle Group */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/5">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <h2 className="text-xs font-medium text-neutral-300 uppercase tracking-widest font-mono">
            INGESTION DOCK
          </h2>
        </div>

        {/* 3-Way Toggle Group: [ Raw Text / SMS ] | [ URL & Website Scanner ] | [ Form & File Payload ] */}
        <div className="flex items-center gap-1 bg-neutral-900/90 p-1 rounded-lg border border-neutral-800 self-start sm:self-auto">
          <button
            onClick={() => setActiveTab('text')}
            className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'text'
                ? 'bg-neutral-800 text-emerald-400 border border-emerald-500/20 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Raw Text / SMS
          </button>
          <button
            onClick={() => setActiveTab('url')}
            className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'url'
                ? 'bg-neutral-800 text-emerald-400 border border-emerald-500/20 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            URL & Website Scanner
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'upload'
                ? 'bg-neutral-800 text-emerald-400 border border-emerald-500/20 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Form & File Payload
          </button>
        </div>
      </div>

      {/* Mode 1: URL & Website Scanner Tab */}
      {activeTab === 'url' && (
        <div className="mt-4 space-y-3">
          <div className="relative">
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Enter target URL, shortened link, or form landing page (e.g., https://forms.office.com/r/xyz or https://login-micros0ft.com)..."
              className="w-full bg-neutral-950/90 border border-neutral-800 focus:border-emerald-500/50 rounded-lg py-3 px-3.5 pr-28 text-xs text-neutral-100 font-mono focus:outline-none placeholder:text-neutral-600 transition"
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleUrlSubmit();
              }}
            />
            <button
              onClick={handleUrlSubmit}
              disabled={!targetUrl.trim() || isLoading}
              className="absolute right-1.5 top-1.5 bottom-1.5 px-3 rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-medium transition cursor-pointer disabled:opacity-40 flex items-center gap-1"
            >
              <Sparkles className="w-3 h-3 text-emerald-400" />
              <span>Scan URL</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-neutral-300 select-none">
              <input
                type="checkbox"
                checked={inspectEmbeddedLinks}
                onChange={(e) => setInspectEmbeddedLinks(e.target.checked)}
                className="w-3.5 h-3.5 rounded bg-neutral-900 border-neutral-700 text-emerald-500 focus:ring-emerald-500/30 accent-emerald-500"
              />
              <span>Inspect Embedded Child Links & Post-Submit Redirects</span>
            </label>

            <span className="text-[11px] font-mono text-neutral-500">
              Punycode IDN • Form Crawler • AiTM Reverse Proxy Fingerprinting
            </span>
          </div>
        </div>
      )}

      {/* Mode 2: Raw Text / SMS Tab */}
      {activeTab === 'text' && (
        <div className="mt-4 space-y-3">
          <textarea
            rows={4}
            value={pastedText}
            onChange={(e) => setPastedText(e.target.value)}
            placeholder="Paste raw email body, SMS string, or OAuth authorization URL..."
            className="w-full bg-neutral-950/80 border border-neutral-800 focus:border-emerald-500/50 rounded-lg p-3 text-xs text-neutral-200 font-mono resize-y focus:outline-none leading-relaxed placeholder:text-neutral-600"
          />

          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-neutral-500">
              {pastedText.length} characters
            </span>

            <button
              onClick={handleTextSubmit}
              disabled={!pastedText.trim() || isLoading}
              className="px-4 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-medium transition cursor-pointer disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
            >
              <span>Analyze Text Payload</span>
            </button>
          </div>
        </div>
      )}

      {/* Mode 3: Form & File Payload Drag & Drop Tab */}
      {activeTab === 'upload' && (
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className={`relative mt-4 border border-dashed rounded-xl p-8 text-center transition-all duration-200 group ${
            dragActive
              ? 'border-emerald-500 bg-emerald-500/[0.03]'
              : 'border-neutral-800 hover:border-neutral-700 bg-neutral-950/40'
          }`}
        >
          <input
            type="file"
            id="file-upload-input"
            onChange={handleFileChange}
            accept=".eml,.msg,.html,.wav,.mp3,.png,.jpg,.jpeg,.txt"
            className="hidden"
          />

          {/* Radial subtle background glow */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-40">
            <div className="w-32 h-32 rounded-full bg-emerald-500/10 blur-2xl" />
          </div>

          <div className="relative z-10 max-w-sm mx-auto flex flex-col items-center">
            <div className="w-10 h-10 rounded-full bg-neutral-900 border border-neutral-800 flex items-center justify-center text-neutral-300 mb-3 shadow-sm group-hover:scale-105 transition-transform">
              <UploadCloud className="w-5 h-5 text-emerald-400 group-hover:text-emerald-300 transition-colors" />
            </div>

            <h3 className="text-xs font-medium text-neutral-200 mb-1">
              Drop file or click to browse
            </h3>
            <p className="text-[11px] text-neutral-500 mb-4 font-mono">
              Accepts .eml, .wav/.mp3, .png/.jpg, or .html
            </p>

            <label
              htmlFor="file-upload-input"
              className="px-3.5 py-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 text-xs font-medium transition cursor-pointer flex items-center gap-1.5 shadow-sm"
            >
              Select File
              <ArrowUpRight className="w-3 h-3 text-neutral-400" />
            </label>

            {selectedFile && (
              <div className="mt-4 px-3 py-1 rounded-md bg-neutral-900 border border-neutral-800 text-neutral-300 text-[11px] font-mono flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>{selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            )}
          </div>

          {/* Minimalist File Type Pills */}
          <div className="mt-6 pt-4 border-t border-white/5 flex flex-wrap justify-center gap-2">
            <span className="rounded-full bg-neutral-900/90 border border-neutral-800 text-[11px] px-2.5 py-0.5 text-neutral-400 font-mono">
              .eml Headers
            </span>
            <span className="rounded-full bg-neutral-900/90 border border-neutral-800 text-[11px] px-2.5 py-0.5 text-neutral-400 font-mono">
              .html Form DOM
            </span>
            <span className="rounded-full bg-neutral-900/90 border border-neutral-800 text-[11px] px-2.5 py-0.5 text-neutral-400 font-mono">
              .wav Whisper
            </span>
            <span className="rounded-full bg-neutral-900/90 border border-neutral-800 text-[11px] px-2.5 py-0.5 text-neutral-400 font-mono">
              .png QR/OCR
            </span>
          </div>
        </div>
      )}

      {/* Sleek Preset Scenario Pills */}
      <div className="mt-5 pt-4 border-t border-white/5 flex items-center justify-between gap-2 flex-wrap">
        <span className="text-[11px] font-mono text-neutral-500 uppercase tracking-wider">
          SCENARIOS:
        </span>

        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => onPresetSelect('weaponized-form-bypass')}
            className="rounded-full bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-[11px] px-2.5 py-1 text-amber-300 font-mono transition cursor-pointer font-medium"
          >
            Weaponized Form Bypass (SaaS Lure)
          </button>
          <button
            onClick={() => onPresetSelect('aitm-homoglyph-proxy')}
            className="rounded-full bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-[11px] px-2.5 py-1 text-rose-300 font-mono transition cursor-pointer font-medium"
          >
            AiTM Homoglyph URL Proxy
          </button>
          <button
            onClick={() => onPresetSelect('bec-whaling')}
            className="rounded-full bg-neutral-900/80 hover:bg-neutral-800 border border-neutral-800/80 text-[11px] px-2.5 py-1 text-neutral-300 font-mono transition cursor-pointer"
          >
            BEC Whaling ($74.5k Wire)
          </button>
          <button
            onClick={() => onPresetSelect('quishing-qr')}
            className="rounded-full bg-neutral-900/80 hover:bg-neutral-800 border border-neutral-800/80 text-[11px] px-2.5 py-1 text-neutral-300 font-mono transition cursor-pointer"
          >
            Quishing QR Parking
          </button>
          <button
            onClick={() => onPresetSelect('vishing-deepfake')}
            className="rounded-full bg-neutral-900/80 hover:bg-neutral-800 border border-neutral-800/80 text-[11px] px-2.5 py-1 text-neutral-300 font-mono transition cursor-pointer"
          >
            Vishing Deepfake (Okta MFA)
          </button>
          <button
            onClick={() => onPresetSelect('consent-phishing')}
            className="rounded-full bg-neutral-900/80 hover:bg-neutral-800 border border-neutral-800/80 text-[11px] px-2.5 py-1 text-neutral-300 font-mono transition cursor-pointer"
          >
            Consent Phishing (OAuth)
          </button>
          <button
            onClick={() => onPresetSelect('prompt-injection')}
            className="rounded-full bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-[11px] px-2.5 py-1 text-rose-300 font-mono transition cursor-pointer"
          >
            Adversarial Prompt Injection
          </button>
        </div>
      </div>
    </motion.div>
  );
};

