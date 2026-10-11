import React, { useState } from 'react';
import { MessageSquare, Link, Key, ShieldAlert, Sparkles, AlertTriangle } from 'lucide-react';
import { FusedPayload } from '../types';

interface TextIngestProps {
  fused: FusedPayload;
  onChange: (updated: Partial<FusedPayload>) => void;
}

export const TextIngest: React.FC<TextIngestProps> = ({ fused, onChange }) => {
  const [rawText, setRawText] = useState<string>(
    'Microsoft OneDrive: An executive file "Q4 Executive Compensation.xlsx" was shared with you. Authorize application access with scopes: offline_access Mail.ReadWrite Files.ReadWrite.All to review: https://login.microsoftonline.com/oauth2/authorize?client_id=badf00d'
  );

  const [extractedUrls, setExtractedUrls] = useState<string[]>([
    'https://login.microsoftonline.com/oauth2/authorize?client_id=badf00d',
  ]);
  const [detectedScopes, setDetectedScopes] = useState<string[]>([
    'offline_access',
    'Mail.ReadWrite',
    'Files.ReadWrite.All',
  ]);

  const handleTextChange = (text: string) => {
    setRawText(text);

    // Extract URLs via regex
    const urlRegex = /https?:\/\/[^\s<>"'{}|\\^`]+/gi;
    const matches = text.match(urlRegex) || [];
    const unique = Array.from(new Set(matches));
    setExtractedUrls(unique);

    // Consent phishing scopes
    const knownScopes = [
      'offline_access',
      'mail.readwrite',
      'mail.read',
      'files.readwrite.all',
      'user.readwrite.all',
      'directory.readwrite.all',
    ];
    const lower = text.toLowerCase();
    const foundScopes = knownScopes.filter((s) => lower.includes(s));
    setDetectedScopes(foundScopes);

    const alerts = [...(fused.sanitization_alerts || [])];
    if (foundScopes.length > 0 && !alerts.some((a) => a.includes('Consent Phishing'))) {
      alerts.push(`Consent Phishing alert: High-privilege OAuth scopes solicited: ${foundScopes.join(', ')}`);
    }

    onChange({
      decoded_urls: unique.map((u) => ({ url: u })),
      sanitization_alerts: alerts,
    });
  };

  const handleLoadConsentSample = () => {
    const sample =
      'Important Microsoft Office 365 Shared Document: "Executive Compensation & Equity Plan.xlsx" requires one-time permission. Grant scopes: offline_access Mail.ReadWrite Files.ReadWrite.All to open in browser: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=d3adb33f-91a2-4c28&scope=openid%20offline_access%20Mail.ReadWrite%20Files.ReadWrite.All';
    handleTextChange(sample);
  };

  const handleLoadSmishingSample = () => {
    const sample =
      'USPS ALERT: Your parcel #92841 is on hold due to incomplete residential address. A redelivery fee of $1.85 is required. Final notice before return to sender: https://usps-track-fee.top/resolve';
    handleTextChange(sample);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
            <MessageSquare className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 flex items-center gap-2">
              Text & SMS Ingestion (Smishing / Consent Phishing)
              <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono">
                Regex RFC URLs + OAuth Scope Analyzer
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Parses raw SMS, chat messages, and social lure texts. Extracts embedded URLs and flags dangerous OAuth scopes.
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleLoadSmishingSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer"
          >
            SMS Smishing
          </button>
          <button
            onClick={handleLoadConsentSample}
            className="text-xs px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1.5 cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Consent Phishing
          </button>
        </div>
      </div>

      <div className="mb-4">
        <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
          RAW PAYLOAD TEXT
        </label>
        <textarea
          rows={3}
          value={rawText}
          onChange={(e) => handleTextChange(e.target.value)}
          placeholder="Paste SMS payload, chat string, or email body text here..."
          className="w-full bg-slate-950 border border-slate-800 focus:border-amber-500 rounded-lg p-2.5 text-xs text-slate-200 font-mono resize-y focus:outline-none"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Extracted URLs */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div className="text-xs font-mono text-slate-400 mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Link className="w-3.5 h-3.5 text-blue-400" />
              EXTRACTED HYPERLINKS ({extractedUrls.length})
            </span>
          </div>

          {extractedUrls.length > 0 ? (
            <div className="space-y-1.5">
              {extractedUrls.map((u, i) => (
                <div
                  key={i}
                  className="bg-slate-900 border border-slate-800 p-2 rounded text-xs font-mono text-slate-300 break-all flex items-start gap-1.5"
                >
                  <span className="text-slate-500 text-[10px] mt-0.5">#{i + 1}</span>
                  <span>{u}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 font-mono text-center py-3">
              No URLs discovered in text string.
            </div>
          )}
        </div>

        {/* Consent Phishing OAuth Scopes */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div className="text-xs font-mono text-slate-400 mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-amber-400" />
              OAUTH TOKEN SCOPES IDENTIFIED ({detectedScopes.length})
            </span>
            {detectedScopes.length > 0 && (
              <span className="text-red-400 font-bold text-[10px]">HIGH PRIVILEGE RISK</span>
            )}
          </div>

          {detectedScopes.length > 0 ? (
            <div className="space-y-2">
              <div className="flex flex-wrap gap-1.5">
                {detectedScopes.map((scope, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-red-950/60 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-1"
                  >
                    <AlertTriangle className="w-3 h-3 text-red-400" />
                    {scope}
                  </span>
                ))}
              </div>
              <p className="text-[11px] text-red-300/80">
                ⚠️ Application requests full persistent access to user mailboxes and cloud documents without user presence. Classic Consent Phishing technique (MITRE ATT&CK T1528).
              </p>
            </div>
          ) : (
            <div className="text-xs text-slate-500 font-mono text-center py-3">
              No sensitive OAuth scopes requested in payload.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
