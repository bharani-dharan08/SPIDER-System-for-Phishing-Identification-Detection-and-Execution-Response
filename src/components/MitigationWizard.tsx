import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldX,
  MailX,
  Ban,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  Lock,
  RefreshCw,
  Zap,
  Terminal,
  ShieldCheck,
  ChevronRight,
  Copy,
  Check,
} from 'lucide-react';
import { FusedPayload, ThreatAnalysisResult } from '../types';

interface MitigationWizardProps {
  result: ThreatAnalysisResult;
  fusedPayload: FusedPayload;
  onToast?: (title: string, description?: string, type?: 'success' | 'critical' | 'warning' | 'info') => void;
}

interface ActionStatus {
  status: 'idle' | 'executing' | 'completed';
  timestamp?: string;
  executionId?: string;
}

export const MitigationWizard: React.FC<MitigationWizardProps> = ({
  result,
  fusedPayload,
  onToast,
}) => {
  const [activeStep, setActiveStep] = useState<1 | 2 | 3>(1);

  // Individual Action States
  const [quarantineState, setQuarantineState] = useState<ActionStatus>({ status: 'idle' });
  const [blacklistState, setBlacklistState] = useState<ActionStatus>({ status: 'idle' });
  const [revokeOAuthState, setRevokeOAuthState] = useState<ActionStatus>({ status: 'idle' });

  // Batch Execution State
  const [isBatchExecuting, setIsBatchExecuting] = useState(false);
  const [auditCopied, setAuditCopied] = useState(false);

  // Reset actions if payload changes
  useEffect(() => {
    setQuarantineState({ status: 'idle' });
    setBlacklistState({ status: 'idle' });
    setRevokeOAuthState({ status: 'idle' });
    setActiveStep(1);
  }, [result, fusedPayload]);

  // Extract Targets from Fused Payload / Analysis Result
  const emailTarget =
    fusedPayload.header_metadata?.From ||
    fusedPayload.header_metadata?.['Reply-To'] ||
    'cfo@acme-corporation.com';

  const extractedDomain = (() => {
    if (fusedPayload.decoded_urls && fusedPayload.decoded_urls.length > 0) {
      const first = fusedPayload.decoded_urls[0];
      if (first.domain) return first.domain;
      try {
        const parsed = new URL(first.url);
        return parsed.hostname;
      } catch {
        return first.url;
      }
    }
    if (fusedPayload.urls_found && fusedPayload.urls_found.length > 0) {
      try {
        const parsed = new URL(fusedPayload.urls_found[0]);
        return parsed.hostname;
      } catch {
        return fusedPayload.urls_found[0];
      }
    }
    return 'mail-settlement-routing.xyz';
  })();

  const oauthTarget =
    fusedPayload.oauth_scopes && fusedPayload.oauth_scopes.length > 0
      ? `App Scope: ${fusedPayload.oauth_scopes.join(', ')}`
      : 'Token ID: tok_live_9a82b41f802c';

  // Handlers for individual actions
  const handleQuarantineEmail = () => {
    if (quarantineState.status === 'executing') return;
    setQuarantineState({ status: 'executing' });

    setTimeout(() => {
      const now = new Date().toLocaleTimeString();
      const execId = `QRN-MSG-${Math.floor(100000 + Math.random() * 900000)}`;
      setQuarantineState({
        status: 'completed',
        timestamp: now,
        executionId: execId,
      });

      if (onToast) {
        onToast(
          'Email Quarantined',
          `Successfully isolated email message from ${emailTarget} [ID: ${execId}]`,
          'success'
        );
      }
    }, 1200);
  };

  const handleBlacklistDomain = () => {
    if (blacklistState.status === 'executing') return;
    setBlacklistState({ status: 'executing' });

    setTimeout(() => {
      const now = new Date().toLocaleTimeString();
      const execId = `BLK-DOM-${Math.floor(100000 + Math.random() * 900000)}`;
      setBlacklistState({
        status: 'completed',
        timestamp: now,
        executionId: execId,
      });

      if (onToast) {
        onToast(
          'Domain Blacklisted',
          `Added ${extractedDomain} to Enterprise DNS & SEG Blocklist [ID: ${execId}]`,
          'critical'
        );
      }
    }, 1400);
  };

  const handleRevokeOAuth = () => {
    if (revokeOAuthState.status === 'executing') return;
    setRevokeOAuthState({ status: 'executing' });

    setTimeout(() => {
      const now = new Date().toLocaleTimeString();
      const execId = `REV-TOK-${Math.floor(100000 + Math.random() * 900000)}`;
      setRevokeOAuthState({
        status: 'completed',
        timestamp: now,
        executionId: execId,
      });

      if (onToast) {
        onToast(
          'OAuth Token Revoked',
          `Invalidated session tokens and active grants for ${extractedDomain} [ID: ${execId}]`,
          'warning'
        );
      }
    }, 1100);
  };

  // Handler for Batch Full Remediation
  const handleBatchFullRemediation = () => {
    setIsBatchExecuting(true);
    if (quarantineState.status !== 'completed') handleQuarantineEmail();

    setTimeout(() => {
      if (blacklistState.status !== 'completed') handleBlacklistDomain();
    }, 400);

    setTimeout(() => {
      if (revokeOAuthState.status !== 'completed') handleRevokeOAuth();
      setIsBatchExecuting(false);
      setActiveStep(3); // Jump to Audit step
    }, 1800);
  };

  const completedCount =
    (quarantineState.status === 'completed' ? 1 : 0) +
    (blacklistState.status === 'completed' ? 1 : 0) +
    (revokeOAuthState.status === 'completed' ? 1 : 0);

  const copyAuditLog = () => {
    const auditData = {
      timestamp: new Date().toISOString(),
      threat_score: result.threat_score,
      primary_vector: result.primary_vector,
      actions_executed: {
        email_quarantine: quarantineState,
        domain_blacklist: blacklistState,
        oauth_revocation: revokeOAuthState,
      },
      targets: {
        email: emailTarget,
        domain: extractedDomain,
        oauth: oauthTarget,
      },
    };
    navigator.clipboard.writeText(JSON.stringify(auditData, null, 2));
    setAuditCopied(true);
    setTimeout(() => setAuditCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.2 }}
      className="glass-card rounded-xl p-6 border border-rose-500/20 bg-neutral-950/80 space-y-5 relative overflow-hidden"
    >
      {/* Wizard Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 shrink-0">
            <Zap className="w-5 h-5 text-rose-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold font-mono text-neutral-100 uppercase tracking-wider">
                MITIGATION ACTION PLAN
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-semibold border border-rose-500/30">
                SOAR Automated Response Wizard
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5">
              One-click remediation controls for isolated threat containment & session invalidation
            </p>
          </div>
        </div>

        {/* Wizard Steps Indicator */}
        <div className="flex items-center gap-1.5 text-xs font-mono bg-neutral-900/90 p-1 rounded-lg border border-neutral-800">
          <button
            onClick={() => setActiveStep(1)}
            className={`px-2.5 py-1 rounded transition cursor-pointer ${
              activeStep === 1
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            1. Remediation
          </button>
          <ChevronRight className="w-3 h-3 text-neutral-600" />
          <button
            onClick={() => setActiveStep(2)}
            className={`px-2.5 py-1 rounded transition cursor-pointer ${
              activeStep === 2
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            2. Controls
          </button>
          <ChevronRight className="w-3 h-3 text-neutral-600" />
          <button
            onClick={() => setActiveStep(3)}
            className={`px-2.5 py-1 rounded transition cursor-pointer ${
              activeStep === 3
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            3. SIEM Audit
          </button>
        </div>
      </div>

      {/* Step 1: One-Click Instant Action Cards */}
      {activeStep === 1 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-neutral-400">
            <span>Recommended Containment Actions ({completedCount}/3 Executed)</span>
            {completedCount < 3 && (
              <button
                onClick={handleBatchFullRemediation}
                disabled={isBatchExecuting}
                className="px-3 py-1 rounded bg-rose-500 hover:bg-rose-400 text-neutral-950 font-bold transition flex items-center gap-1.5 cursor-pointer shadow-md shadow-rose-500/20 disabled:opacity-50 text-[11px]"
              >
                <Zap className="w-3.5 h-3.5 fill-current" />
                <span>Execute Full One-Click Remediation</span>
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Action 1: Quarantine Email */}
            <div
              className={`p-4 rounded-xl border transition flex flex-col justify-between space-y-3 ${
                quarantineState.status === 'completed'
                  ? 'bg-emerald-950/20 border-emerald-500/40 ring-1 ring-emerald-500/20'
                  : 'bg-neutral-900/80 border-neutral-800 hover:border-neutral-700'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <MailX
                      className={`w-4 h-4 ${
                        quarantineState.status === 'completed'
                          ? 'text-emerald-400'
                          : 'text-rose-400'
                      }`}
                    />
                    <span className="text-xs font-mono font-bold text-neutral-100 uppercase">
                      Quarantine Email
                    </span>
                  </div>
                  {quarantineState.status === 'completed' ? (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      QUARANTINED
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                      HIGH PRIORITY
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-neutral-400 font-sans">
                  Isolate email payload from user inbox across Exchange/SEG.
                </p>
                <div className="text-[10px] font-mono text-neutral-500 bg-neutral-950 p-2 rounded border border-neutral-800 truncate">
                  Target: <span className="text-neutral-300">{emailTarget}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                {quarantineState.status === 'completed' ? (
                  <div className="text-[10px] font-mono text-emerald-400 space-y-0.5">
                    <div>Executed at {quarantineState.timestamp}</div>
                    <div className="text-neutral-500">ID: {quarantineState.executionId}</div>
                  </div>
                ) : (
                  <button
                    onClick={handleQuarantineEmail}
                    disabled={quarantineState.status === 'executing'}
                    className="w-full py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 hover:text-white font-mono text-xs font-semibold transition flex items-center justify-center gap-2 border border-neutral-700 cursor-pointer disabled:opacity-50"
                  >
                    {quarantineState.status === 'executing' ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-rose-400" />
                        <span>Isolating...</span>
                      </>
                    ) : (
                      <>
                        <MailX className="w-3.5 h-3.5 text-rose-400" />
                        <span>Quarantine Email</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>

            {/* Action 2: Blacklist Domain */}
            <div
              className={`p-4 rounded-xl border transition flex flex-col justify-between space-y-3 ${
                blacklistState.status === 'completed'
                  ? 'bg-emerald-950/20 border-emerald-500/40 ring-1 ring-emerald-500/20'
                  : 'bg-neutral-900/80 border-neutral-800 hover:border-neutral-700'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Ban
                      className={`w-4 h-4 ${
                        blacklistState.status === 'completed'
                          ? 'text-emerald-400'
                          : 'text-rose-400'
                      }`}
                    />
                    <span className="text-xs font-mono font-bold text-neutral-100 uppercase">
                      Blacklist Domain
                    </span>
                  </div>
                  {blacklistState.status === 'completed' ? (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      BLOCKED
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                      DNS / FIREWALL
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-neutral-400 font-sans">
                  Block domain infrastructure on perimeter firewall & DNS filter.
                </p>
                <div className="text-[10px] font-mono text-neutral-500 bg-neutral-950 p-2 rounded border border-neutral-800 truncate">
                  Domain: <span className="text-neutral-300">{extractedDomain}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                {blacklistState.status === 'completed' ? (
                  <div className="text-[10px] font-mono text-emerald-400 space-y-0.5">
                    <div>Executed at {blacklistState.timestamp}</div>
                    <div className="text-neutral-500">ID: {blacklistState.executionId}</div>
                  </div>
                ) : (
                  <button
                    onClick={handleBlacklistDomain}
                    disabled={blacklistState.status === 'executing'}
                    className="w-full py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 hover:text-white font-mono text-xs font-semibold transition flex items-center justify-center gap-2 border border-neutral-700 cursor-pointer disabled:opacity-50"
                  >
                    {blacklistState.status === 'executing' ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-rose-400" />
                        <span>Updating DNS...</span>
                      </>
                    ) : (
                      <>
                        <Ban className="w-3.5 h-3.5 text-rose-400" />
                        <span>Blacklist Domain</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>

            {/* Action 3: Revoke OAuth Token */}
            <div
              className={`p-4 rounded-xl border transition flex flex-col justify-between space-y-3 ${
                revokeOAuthState.status === 'completed'
                  ? 'bg-emerald-950/20 border-emerald-500/40 ring-1 ring-emerald-500/20'
                  : 'bg-neutral-900/80 border-neutral-800 hover:border-neutral-700'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <KeyRound
                      className={`w-4 h-4 ${
                        revokeOAuthState.status === 'completed'
                          ? 'text-emerald-400'
                          : 'text-rose-400'
                      }`}
                    />
                    <span className="text-xs font-mono font-bold text-neutral-100 uppercase">
                      Revoke OAuth Token
                    </span>
                  </div>
                  {revokeOAuthState.status === 'completed' ? (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      REVOKED
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                      IDP / TOKEN
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-neutral-400 font-sans">
                  Revoke active refresh tokens & third-party OAuth app authorizations.
                </p>
                <div className="text-[10px] font-mono text-neutral-500 bg-neutral-950 p-2 rounded border border-neutral-800 truncate">
                  Target: <span className="text-neutral-300">{oauthTarget}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                {revokeOAuthState.status === 'completed' ? (
                  <div className="text-[10px] font-mono text-emerald-400 space-y-0.5">
                    <div>Executed at {revokeOAuthState.timestamp}</div>
                    <div className="text-neutral-500">ID: {revokeOAuthState.executionId}</div>
                  </div>
                ) : (
                  <button
                    onClick={handleRevokeOAuth}
                    disabled={revokeOAuthState.status === 'executing'}
                    className="w-full py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 hover:text-white font-mono text-xs font-semibold transition flex items-center justify-center gap-2 border border-neutral-700 cursor-pointer disabled:opacity-50"
                  >
                    {revokeOAuthState.status === 'executing' ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-rose-400" />
                        <span>Invalidating...</span>
                      </>
                    ) : (
                      <>
                        <KeyRound className="w-3.5 h-3.5 text-rose-400" />
                        <span>Revoke OAuth Token</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Step 2: Policy & Automated Controls */}
      {activeStep === 2 && (
        <div className="space-y-3 bg-neutral-900/60 p-4 rounded-xl border border-neutral-800 font-mono text-xs">
          <div className="text-neutral-200 font-bold uppercase tracking-wider mb-2 flex items-center justify-between">
            <span>Automated Incident Escalation Switches</span>
            <span className="text-[10px] text-neutral-500 font-normal">Active Policy ID: SPIDER-SOAR-882</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-neutral-300">
            <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 flex items-center justify-between">
              <div>
                <div className="text-neutral-100 font-semibold">SOAR Auto-Quarantine on Score &gt; 8.0</div>
                <div className="text-[10px] text-neutral-500">Automatically isolate email without manual approval</div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] border border-emerald-500/30">
                ENABLED
              </span>
            </div>

            <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 flex items-center justify-between">
              <div>
                <div className="text-neutral-100 font-semibold">Force User Session Revocation</div>
                <div className="text-[10px] text-neutral-500">Invalidate active MFA & OAuth sessions on high-risk AiTM</div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] border border-emerald-500/30">
                ENABLED
              </span>
            </div>

            <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 flex items-center justify-between">
              <div>
                <div className="text-neutral-100 font-semibold">Splunk / Sentinel SIEM Webhook Push</div>
                <div className="text-[10px] text-neutral-500">Stream JSON forensic log to enterprise security telemetry</div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] border border-emerald-500/30">
                ACTIVE
              </span>
            </div>

            <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 flex items-center justify-between">
              <div>
                <div className="text-neutral-100 font-semibold">Target Domain Auto-Submission to PhishTank</div>
                <div className="text-[10px] text-neutral-500">Submit extracted homoglyph URLs to threat intelligence feeds</div>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Step 3: SIEM Incident Audit Log */}
      {activeStep === 3 && (
        <div className="space-y-3 bg-neutral-900/90 p-4 rounded-xl border border-neutral-800 font-mono text-xs relative">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span className="text-neutral-200 font-bold uppercase tracking-wider">
                SIEM Incident Response Audit Log (JSON)
              </span>
            </div>
            <button
              onClick={copyAuditLog}
              className="px-2.5 py-1 rounded bg-neutral-950 hover:bg-neutral-800 border border-neutral-800 text-[11px] text-neutral-300 flex items-center gap-1.5 transition cursor-pointer"
            >
              {auditCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{auditCopied ? 'Copied Log' : 'Copy JSON'}</span>
            </button>
          </div>

          <pre className="p-3 rounded-lg bg-neutral-950 text-[11px] text-emerald-400 border border-neutral-800/80 overflow-x-auto leading-relaxed max-h-60 font-mono">
            {JSON.stringify(
              {
                incident_id: `INC-${Math.floor(100000 + Math.random() * 900000)}`,
                timestamp: new Date().toISOString(),
                detector: 'SPIDER SOAR Mitigation Engine',
                threat_score: result.threat_score,
                primary_vector: result.primary_vector,
                actions_taken: {
                  quarantine_email: quarantineState,
                  blacklist_domain: blacklistState,
                  revoke_oauth: revokeOAuthState,
                },
                contained_targets: {
                  email: emailTarget,
                  domain: extractedDomain,
                  oauth: oauthTarget,
                },
              },
              null,
              2
            )}
          </pre>
        </div>
      )}
    </motion.div>
  );
};
