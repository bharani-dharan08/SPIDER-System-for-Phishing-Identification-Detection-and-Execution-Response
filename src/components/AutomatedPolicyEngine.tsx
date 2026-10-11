import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Zap,
  Plus,
  Play,
  Trash2,
  Edit2,
  CheckCircle2,
  AlertTriangle,
  Shield,
  ShieldAlert,
  ArrowRight,
  Sliders,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  Power,
  Layers,
  Sparkles,
  Info,
  X,
  Lock,
  Download,
  Filter
} from 'lucide-react';
import { ThreatAnalysisResult, FusedPayload } from '../types';

export interface PolicyRuleCondition {
  id: string;
  field: 'threat_score' | 'primary_vector' | 'confidence_score' | 'has_password_field' | 'is_aitm_proxy' | 'is_homoglyph' | 'synthetic_voice_anomaly';
  operator: '>' | '>=' | '==' | '!=' | 'contains' | 'is_true';
  value: string | number | boolean;
}

export interface PolicyRuleAction {
  id: string;
  actionType: 'AUTO_BLOCK_IP' | 'QUARANTINE_EMAIL' | 'REVOKE_OAUTH_TOKEN' | 'FORCE_MFA_REBIND' | 'TRIGGER_SIEM_WEBHOOK' | 'ISOLATE_ENDPOINT';
  target: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface IFTTTRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  logicalOperator: 'AND' | 'OR';
  conditions: PolicyRuleCondition[];
  actions: PolicyRuleAction[];
  lastTriggered?: string;
  matchCount: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

interface AutomatedPolicyEngineProps {
  analysisResult?: ThreatAnalysisResult;
  fusedPayload?: FusedPayload;
  addToast: (title: string, description?: string, type?: 'success' | 'critical' | 'warning' | 'info') => void;
}

const DEFAULT_PRESET_RULES: IFTTTRule[] = [
  {
    id: 'RULE-POL-001',
    name: 'Auto-Block Vishing High-Risk Calls',
    description: 'If threat score exceeds 9.0 and vector is Voice/Vishing, immediately block caller IP and isolate gateway.',
    enabled: true,
    logicalOperator: 'AND',
    severity: 'CRITICAL',
    matchCount: 14,
    lastTriggered: '12 mins ago',
    conditions: [
      { id: 'c1', field: 'threat_score', operator: '>', value: 9.0 },
      { id: 'c2', field: 'primary_vector', operator: 'contains', value: 'Vishing' }
    ],
    actions: [
      {
        id: 'a1',
        actionType: 'AUTO_BLOCK_IP',
        target: 'Attacker Gateway IP (203.0.113.88)',
        severity: 'CRITICAL',
        description: 'Push immediate perimeter BGP blackhole & firewall rule'
      },
      {
        id: 'a2',
        actionType: 'TRIGGER_SIEM_WEBHOOK',
        target: 'Splunk / Microsoft Sentinel SIEM',
        severity: 'HIGH',
        description: 'Dispatch high-priority incident webhook to SOC Tier-3'
      }
    ]
  },
  {
    id: 'RULE-POL-002',
    name: 'Weaponized SaaS Form Quarantine',
    description: 'If third-party form requests password/PIN fields on unverified host, quarantine target inbox message.',
    enabled: true,
    logicalOperator: 'AND',
    severity: 'HIGH',
    matchCount: 28,
    lastTriggered: '1 hour ago',
    conditions: [
      { id: 'c3', field: 'has_password_field', operator: 'is_true', value: true },
      { id: 'c4', field: 'primary_vector', operator: 'contains', value: 'Form' }
    ],
    actions: [
      {
        id: 'a3',
        actionType: 'QUARANTINE_EMAIL',
        target: 'Microsoft Exchange / SEG Inbox',
        severity: 'HIGH',
        description: 'Purge weaponized phishing email from all recipient mailboxes'
      }
    ]
  },
  {
    id: 'RULE-POL-003',
    name: 'AiTM Homoglyph OAuth Token Revocation',
    description: 'If Adversary-in-the-Middle proxy or IDN homoglyph domain detected, revoke OAuth tokens and force MFA rebind.',
    enabled: true,
    logicalOperator: 'OR',
    severity: 'CRITICAL',
    matchCount: 9,
    lastTriggered: '3 hours ago',
    conditions: [
      { id: 'c5', field: 'is_aitm_proxy', operator: 'is_true', value: true },
      { id: 'c6', field: 'is_homoglyph', operator: 'is_true', value: true }
    ],
    actions: [
      {
        id: 'a4',
        actionType: 'REVOKE_OAUTH_TOKEN',
        target: 'Entra ID / Okta Session Tokens',
        severity: 'CRITICAL',
        description: 'Invalidate all active refresh tokens & force full re-authentication'
      },
      {
        id: 'a5',
        actionType: 'FORCE_MFA_REBIND',
        target: 'Target User Identity Principal',
        severity: 'HIGH',
        description: 'Require hardware FIDO2 key / authenticator app re-registration'
      }
    ]
  },
  {
    id: 'RULE-POL-004',
    name: 'Synthetic Voice Neural Anomaly Containment',
    description: 'When deepfake audio neural vocoder phase jitter detected with high confidence, isolate targeted endpoint.',
    enabled: false,
    logicalOperator: 'AND',
    severity: 'MEDIUM',
    matchCount: 3,
    lastTriggered: '2 days ago',
    conditions: [
      { id: 'c7', field: 'synthetic_voice_anomaly', operator: 'is_true', value: true },
      { id: 'c8', field: 'confidence_score', operator: '>=', value: 8.5 }
    ],
    actions: [
      {
        id: 'a6',
        actionType: 'ISOLATE_ENDPOINT',
        target: 'CrowdStrike / Defender EDR Gateway',
        severity: 'CRITICAL',
        description: 'Host-based firewall network containment for targeted agent'
      }
    ]
  }
];

export function AutomatedPolicyEngine({ analysisResult, fusedPayload, addToast }: AutomatedPolicyEngineProps) {
  const [rules, setRules] = useState<IFTTTRule[]>(DEFAULT_PRESET_RULES);
  const [selectedRuleId, setSelectedRuleId] = useState<string>(DEFAULT_PRESET_RULES[0].id);
  const [isCreatingRule, setIsCreatingRule] = useState<boolean>(false);
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [simulationResult, setSimulationResult] = useState<{
    matchedRules: IFTTTRule[];
    executedActions: PolicyRuleAction[];
    evalCount: number;
    timestamp: string;
  } | null>(null);

  // Form state for creating custom rules
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleDesc, setNewRuleDesc] = useState('');
  const [newLogicalOp, setNewLogicalOp] = useState<'AND' | 'OR'>('AND');
  const [newSeverity, setNewSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [newCondField, setNewCondField] = useState<PolicyRuleCondition['field']>('threat_score');
  const [newCondOp, setNewCondOp] = useState<PolicyRuleCondition['operator']>('>');
  const [newCondVal, setNewCondVal] = useState<string>('9.0');
  const [newActionType, setNewActionType] = useState<PolicyRuleAction['actionType']>('AUTO_BLOCK_IP');
  const [newActionTarget, setNewActionTarget] = useState<string>('Perimeter Firewall / IP Pool');

  const selectedRule = rules.find((r) => r.id === selectedRuleId) || rules[0];

  const handleToggleRule = (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setRules((prev) =>
      prev.map((rule) => {
        if (rule.id === id) {
          const updated = !rule.enabled;
          addToast(
            `Policy ${updated ? 'Enabled' : 'Disabled'}`,
            `Rule '${rule.name}' is now ${updated ? 'active in policy engine' : 'paused'}`,
            updated ? 'success' : 'warning'
          );
          return { ...rule, enabled: updated };
        }
        return rule;
      })
    );
  };

  const handleDeleteRule = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (rules.length <= 1) {
      addToast('Cannot Delete', 'At least one policy rule must remain active in the engine', 'warning');
      return;
    }
    const target = rules.find((r) => r.id === id);
    setRules((prev) => prev.filter((r) => r.id !== id));
    if (selectedRuleId === id) {
      setSelectedRuleId(rules.find((r) => r.id !== id)?.id || rules[0].id);
    }
    addToast('Rule Deleted', `Removed policy rule '${target?.name || id}'`, 'info');
  };

  const handleCopyJSON = (rule: IFTTTRule) => {
    navigator.clipboard.writeText(JSON.stringify(rule, null, 2));
    setCopiedRuleId(rule.id);
    addToast('Copied JSON', 'Policy rule configuration copied to clipboard', 'info');
    setTimeout(() => setCopiedRuleId(null), 2000);
  };

  const evaluateRuleAgainstBuffer = (rule: IFTTTRule): boolean => {
    if (!rule.enabled) return false;

    const currentScore = analysisResult?.threat_score ?? 9.2;
    const currentVector = (analysisResult?.primary_vector ?? '').toLowerCase();
    const currentConf = analysisResult?.confidence_score ?? (analysisResult?.modal_confidences ? (Object.values(analysisResult.modal_confidences).reduce((a, b) => a + b, 0) / 4) * 10 : 9.1);
    const hasPassword = fusedPayload?.dom_structure?.has_password_field ?? false;
    const isAitm = currentVector.includes('aitm') || currentVector.includes('proxy') || (fusedPayload?.sanitization_alerts ?? []).some(a => a.toLowerCase().includes('proxy'));
    const isHomoglyph = currentVector.includes('homoglyph') || (fusedPayload?.decoded_urls ?? []).some(u => u.isTyposquat);
    const voiceAnomaly = fusedPayload?.synthetic_voice_anomaly ?? currentVector.includes('vishing');

    const condResults = rule.conditions.map((cond) => {
      switch (cond.field) {
        case 'threat_score': {
          const numVal = Number(cond.value);
          if (cond.operator === '>') return currentScore > numVal;
          if (cond.operator === '>=') return currentScore >= numVal;
          if (cond.operator === '==') return currentScore === numVal;
          return false;
        }
        case 'confidence_score': {
          const numVal = Number(cond.value);
          if (cond.operator === '>=') return currentConf >= numVal;
          if (cond.operator === '>') return currentConf > numVal;
          return false;
        }
        case 'primary_vector': {
          const strVal = String(cond.value).toLowerCase();
          if (cond.operator === 'contains') return currentVector.includes(strVal);
          if (cond.operator === '==') return currentVector === strVal;
          return false;
        }
        case 'has_password_field':
          return cond.operator === 'is_true' ? hasPassword : !hasPassword;
        case 'is_aitm_proxy':
          return cond.operator === 'is_true' ? isAitm : !isAitm;
        case 'is_homoglyph':
          return cond.operator === 'is_true' ? isHomoglyph : !isHomoglyph;
        case 'synthetic_voice_anomaly':
          return cond.operator === 'is_true' ? voiceAnomaly : !voiceAnomaly;
        default:
          return false;
      }
    });

    if (rule.logicalOperator === 'AND') {
      return condResults.every(Boolean);
    } else {
      return condResults.some(Boolean);
    }
  };

  const handleRunPolicySimulation = () => {
    const matched: IFTTTRule[] = [];
    const actions: PolicyRuleAction[] = [];

    rules.forEach((rule) => {
      if (evaluateRuleAgainstBuffer(rule)) {
        matched.push(rule);
        actions.push(...rule.actions);
      }
    });

    // Update match count for matched rules
    setRules((prev) =>
      prev.map((r) => {
        if (matched.some((m) => m.id === r.id)) {
          return {
            ...r,
            matchCount: r.matchCount + 1,
            lastTriggered: 'Just now'
          };
        }
        return r;
      })
    );

    setSimulationResult({
      matchedRules: matched,
      executedActions: actions,
      evalCount: rules.filter((r) => r.enabled).length,
      timestamp: new Date().toLocaleTimeString()
    });

    if (matched.length > 0) {
      addToast(
        'Policy Engine Evaluation Complete',
        `Matched ${matched.length} rule(s) and triggered ${actions.length} automated SOAR action(s)`,
        'critical'
      );
    } else {
      addToast(
        'Policy Evaluation Complete',
        `Evaluated ${rules.filter((r) => r.enabled).length} active rule(s). No policy thresholds triggered.`,
        'info'
      );
    }
  };

  const handleCreateCustomRule = () => {
    if (!newRuleName.trim()) {
      addToast('Validation Error', 'Please enter a rule name', 'warning');
      return;
    }

    const newRule: IFTTTRule = {
      id: `RULE-POL-00${rules.length + 1}`,
      name: newRuleName,
      description: newRuleDesc || `Automated policy rule triggered when ${newCondField} ${newCondOp} ${newCondVal}`,
      enabled: true,
      logicalOperator: newLogicalOp,
      severity: newSeverity,
      matchCount: 0,
      lastTriggered: 'Never',
      conditions: [
        {
          id: `c-${Date.now()}`,
          field: newCondField,
          operator: newCondOp,
          value: newCondField === 'has_password_field' || newCondField === 'is_aitm_proxy' || newCondField === 'is_homoglyph' || newCondField === 'synthetic_voice_anomaly'
            ? true
            : isNaN(Number(newCondVal)) ? newCondVal : Number(newCondVal)
        }
      ],
      actions: [
        {
          id: `a-${Date.now()}`,
          actionType: newActionType,
          target: newActionTarget,
          severity: newSeverity,
          description: `Automatically execute ${newActionType.replace(/_/g, ' ')} response on ${newActionTarget}`
        }
      ]
    };

    setRules((prev) => [newRule, ...prev]);
    setSelectedRuleId(newRule.id);
    setIsCreatingRule(false);
    setNewRuleName('');
    setNewRuleDesc('');
    addToast('Custom Rule Added', `Policy rule '${newRule.name}' registered and activated in SPIDER engine`, 'success');
  };

  const filteredRules = rules.filter((r) => {
    if (filterSeverity === 'ALL') return true;
    return r.severity === filterSeverity;
  });

  const getFieldLabel = (field: PolicyRuleCondition['field']) => {
    switch (field) {
      case 'threat_score': return 'Threat Score (0-10)';
      case 'primary_vector': return 'Primary Threat Vector';
      case 'confidence_score': return 'Confidence Score (0-10)';
      case 'has_password_field': return 'Contains Credential / Password Input';
      case 'is_aitm_proxy': return 'Adversary-in-the-Middle (AiTM) Proxy';
      case 'is_homoglyph': return 'Punycode / Homoglyph Domain Spoof';
      case 'synthetic_voice_anomaly': return 'Vishing / Deepfake Voice Anomaly';
    }
  };

  const getActionBadgeColor = (type: PolicyRuleAction['actionType']) => {
    switch (type) {
      case 'AUTO_BLOCK_IP': return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'QUARANTINE_EMAIL': return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'REVOKE_OAUTH_TOKEN': return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'FORCE_MFA_REBIND': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'TRIGGER_SIEM_WEBHOOK': return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'ISOLATE_ENDPOINT': return 'bg-rose-600/10 text-rose-300 border-rose-600/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#0D151C] border border-[#1E293B] rounded-xl p-6 relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-64 h-64 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                <Zap className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                  Automated Policy & IFTTT Engine
                  <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                    SOAR Active
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Real-time threat response automation using If-This-Then-That conditional policy logic
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRunPolicySimulation}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium text-xs shadow-lg shadow-emerald-950/40 transition-all border border-emerald-400/30"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Evaluate Active Rules Now
            </button>
            <button
              onClick={() => setIsCreatingRule(true)}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#15202B] hover:bg-[#1E293B] text-slate-200 border border-[#2A3B4C] text-xs font-medium transition-all"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-400" />
              New Policy Rule
            </button>
          </div>
        </div>

        {/* Evaluation Summary Strip */}
        {simulationResult && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 pt-4 border-t border-[#1E293B] flex flex-wrap items-center justify-between gap-3 text-xs"
          >
            <div className="flex items-center gap-3 text-slate-300">
              <span className="flex items-center gap-1.5 font-medium text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                Evaluated {simulationResult.evalCount} Rules at {simulationResult.timestamp}
              </span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-300">
                Matched Rules:{' '}
                <strong className="text-emerald-400 font-mono">{simulationResult.matchedRules.length}</strong>
              </span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-300">
                Executed Actions:{' '}
                <strong className="text-rose-400 font-mono">{simulationResult.executedActions.length}</strong>
              </span>
            </div>
            <button
              onClick={() => setSimulationResult(null)}
              className="text-slate-500 hover:text-slate-300 text-[11px] underline"
            >
              Clear Log
            </button>
          </motion.div>
        )}
      </div>

      {/* Main Split Layout: Rule List & Visual Flow Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Rule Manager (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0D151C] border border-[#1E293B] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Sliders className="w-3.5 h-3.5 text-emerald-400" />
                Active Policy Rules ({filteredRules.length})
              </h3>

              {/* Severity Filter */}
              <div className="flex items-center gap-1 bg-[#15202B] p-1 rounded-lg border border-[#2A3B4C]">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setFilterSeverity(sev)}
                    className={`px-2 py-0.5 rounded text-[10px] font-medium transition-all ${
                      filterSeverity === sev
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {/* Rule Cards List */}
            <div className="space-y-2.5 max-h-[580px] overflow-y-auto pr-1 custom-scrollbar">
              {filteredRules.map((rule) => {
                const isSelected = rule.id === selectedRuleId;
                const isMatchedInSim = simulationResult?.matchedRules.some((m) => m.id === rule.id);

                return (
                  <div
                    key={rule.id}
                    onClick={() => setSelectedRuleId(rule.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer relative overflow-hidden ${
                      isSelected
                        ? 'bg-[#15232D] border-emerald-500/50 shadow-md shadow-emerald-950/30'
                        : 'bg-[#111A22] border-[#1E293B] hover:border-slate-700 hover:bg-[#15202B]'
                    }`}
                  >
                    {isMatchedInSim && (
                      <div className="absolute top-0 right-0 w-2 h-2 bg-emerald-400 rounded-full animate-ping m-2" />
                    )}

                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => handleToggleRule(rule.id, e)}
                          title={rule.enabled ? 'Click to Disable' : 'Click to Enable'}
                          className={`p-1 rounded transition-colors ${
                            rule.enabled
                              ? 'text-emerald-400 hover:text-emerald-300'
                              : 'text-slate-600 hover:text-slate-400'
                          }`}
                        >
                          <Power className="w-4 h-4" />
                        </button>

                        <div>
                          <span className="text-xs font-mono text-slate-500 block leading-none mb-0.5">
                            {rule.id}
                          </span>
                          <h4 className="text-xs font-semibold text-slate-100 line-clamp-1">
                            {rule.name}
                          </h4>
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-semibold border ${
                            rule.severity === 'CRITICAL'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : rule.severity === 'HIGH'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                          }`}
                        >
                          {rule.severity}
                        </span>
                        <button
                          onClick={(e) => handleDeleteRule(rule.id, e)}
                          className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 line-clamp-2 mb-3 leading-relaxed">
                      {rule.description}
                    </p>

                    {/* Quick Stats & Condition summary */}
                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-[#1E293B]/60">
                      <span className="flex items-center gap-1 text-slate-400">
                        <Layers className="w-3 h-3 text-slate-500" />
                        {rule.conditions.length} IF ({rule.logicalOperator}) &rarr; {rule.actions.length} THEN
                      </span>
                      <span className="font-mono text-slate-400">
                        Triggered: <span className="text-emerald-400 font-bold">{rule.matchCount}x</span>
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Visual Pipeline & Node Execution Flow (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#0D151C] border border-[#1E293B] rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider block">
                  Interactive Node Pipeline
                </span>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  {selectedRule.name}
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                      selectedRule.enabled
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-slate-800 text-slate-500'
                    }`}
                  >
                    {selectedRule.enabled ? 'ACTIVE' : 'PAUSED'}
                  </span>
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopyJSON(selectedRule)}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#15202B] hover:bg-[#1E293B] border border-[#2A3B4C] text-[11px] text-slate-300 font-mono transition-all"
                >
                  {copiedRuleId === selectedRule.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-400" /> Copy JSON
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Visual Node Diagram (IFTTT Flow) */}
            <div className="bg-[#080D11] border border-[#1E293B] rounded-xl p-5 relative overflow-hidden">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-4 flex items-center justify-between">
                <span>IFTTT Execution Logic Diagram</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> Real-time Node Binding
                </span>
              </div>

              {/* Node Graph Flow */}
              <div className="space-y-4 relative">
                {/* 1. IF CONDITIONS NODE */}
                <div className="bg-[#111A22] border border-emerald-500/30 rounded-xl p-4 relative shadow-lg shadow-emerald-950/20">
                  <div className="absolute -top-3 left-4 px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 text-[10px] font-mono font-bold uppercase tracking-wider">
                    IF (Trigger Condition)
                  </div>

                  <div className="pt-1 space-y-2">
                    {selectedRule.conditions.map((cond, idx) => (
                      <div
                        key={cond.id}
                        className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg bg-[#0D151C] border border-[#1E293B]"
                      >
                        <div className="flex items-center gap-2 text-xs">
                          <span className="font-mono text-slate-400 font-bold">
                            [{getFieldLabel(cond.field)}]
                          </span>
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-amber-400 font-mono font-bold text-[11px]">
                            {cond.operator}
                          </span>
                          <span className="font-mono text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                            {String(cond.value)}
                          </span>
                        </div>

                        {idx < selectedRule.conditions.length - 1 && (
                          <span className="text-[10px] font-mono font-bold text-teal-400 px-2 py-0.5 bg-teal-500/10 rounded border border-teal-500/20">
                            {selectedRule.logicalOperator}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Animated Arrow Connector */}
                <div className="flex items-center justify-center py-1 relative">
                  <div className="w-0.5 h-6 bg-gradient-to-b from-emerald-500 to-rose-500" />
                  <div className="absolute p-1 rounded-full bg-[#111A22] border border-slate-700 text-slate-300 shadow-md">
                    <ArrowRight className="w-3.5 h-3.5 rotate-90 text-emerald-400 animate-bounce" />
                  </div>
                </div>

                {/* 2. THEN ACTIONS NODE */}
                <div className="bg-[#111A22] border border-rose-500/30 rounded-xl p-4 relative shadow-lg shadow-rose-950/20">
                  <div className="absolute -top-3 left-4 px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-400 text-[10px] font-mono font-bold uppercase tracking-wider">
                    THEN (Automated SOAR Action)
                  </div>

                  <div className="pt-1 space-y-2.5">
                    {selectedRule.actions.map((act) => (
                      <div
                        key={act.id}
                        className="p-3 rounded-lg bg-[#0D151C] border border-[#1E293B] space-y-1.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span
                            className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${getActionBadgeColor(
                              act.actionType
                            )}`}
                          >
                            {act.actionType}
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            Target: <strong className="text-slate-200">{act.target}</strong>
                          </span>
                        </div>
                        <p className="text-xs text-slate-300">{act.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Live Buffer Evaluation Status for Selected Rule */}
            <div className="bg-[#111A22] border border-[#1E293B] rounded-xl p-4 space-y-3">
              <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Live Analysis Buffer Matching
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-[#0D151C] border border-[#1E293B]">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">
                    Current Threat Score
                  </span>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-lg font-bold text-rose-400">
                      {analysisResult?.threat_score ?? 9.2} / 10.0
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono">
                      CRITICAL
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#0D151C] border border-[#1E293B]">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">
                    Evaluated Rule Status
                  </span>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-200">
                      {evaluateRuleAgainstBuffer(selectedRule) ? (
                        <span className="text-rose-400 flex items-center gap-1 font-bold">
                          <ShieldAlert className="w-4 h-4 text-rose-400" /> Rule Triggered
                        </span>
                      ) : (
                        <span className="text-slate-400 flex items-center gap-1">
                          <Shield className="w-4 h-4 text-slate-500" /> Condition Unmet
                        </span>
                      )}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      Match Count: {selectedRule.matchCount}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Custom Rule Creation Modal */}
      <AnimatePresence>
        {isCreatingRule && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0D151C] border border-[#1E293B] rounded-2xl p-6 w-full max-w-xl space-y-5 shadow-2xl relative"
            >
              <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <Zap className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-100">
                      Create Custom IFTTT Policy Rule
                    </h3>
                    <p className="text-xs text-slate-400">
                      Define condition logic and automated mitigation actions
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setIsCreatingRule(false)}
                  className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-[#15202B]"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4 text-xs">
                {/* Rule Name & Description */}
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Policy Rule Name
                  </label>
                  <input
                    type="text"
                    value={newRuleName}
                    onChange={(e) => setNewRuleName(e.target.value)}
                    placeholder="e.g., Auto-Block Vishing High-Risk Calls"
                    className="w-full px-3 py-2 rounded-lg bg-[#15202B] border border-[#2A3B4C] text-slate-100 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Rule Description
                  </label>
                  <input
                    type="text"
                    value={newRuleDesc}
                    onChange={(e) => setNewRuleDesc(e.target.value)}
                    placeholder="Brief explanation of policy trigger..."
                    className="w-full px-3 py-2 rounded-lg bg-[#15202B] border border-[#2A3B4C] text-slate-100 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                {/* IF CONDITION BUILDER */}
                <div className="p-3.5 rounded-xl bg-[#111A22] border border-emerald-500/20 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-emerald-400 uppercase tracking-wider">
                      IF Condition
                    </span>
                    <select
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value as any)}
                      className="px-2 py-1 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs font-mono"
                    >
                      <option value="CRITICAL">Severity: CRITICAL</option>
                      <option value="HIGH">Severity: HIGH</option>
                      <option value="MEDIUM">Severity: MEDIUM</option>
                      <option value="LOW">Severity: LOW</option>
                    </select>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <div>
                      <label className="block text-slate-400 text-[10px] mb-1">
                        Field
                      </label>
                      <select
                        value={newCondField}
                        onChange={(e) => setNewCondField(e.target.value as any)}
                        className="w-full px-2.5 py-1.5 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs"
                      >
                        <option value="threat_score">Threat Score (0-10)</option>
                        <option value="primary_vector">Primary Threat Vector</option>
                        <option value="confidence_score">Confidence Score</option>
                        <option value="has_password_field font-mono">Form Has Password</option>
                        <option value="is_aitm_proxy">AiTM Proxy Detected</option>
                        <option value="is_homoglyph">Homoglyph / Punycode</option>
                        <option value="synthetic_voice_anomaly">Voice Deepfake Anomaly</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 text-[10px] mb-1">
                        Operator
                      </label>
                      <select
                        value={newCondOp}
                        onChange={(e) => setNewCondOp(e.target.value as any)}
                        className="w-full px-2.5 py-1.5 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs font-mono"
                      >
                        <option value=">">&gt; (Greater than)</option>
                        <option value=">=">&gt;= (Greater or equal)</option>
                        <option value="==">== (Equals)</option>
                        <option value="contains">CONTAINS</option>
                        <option value="is_true">IS TRUE</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 text-[10px] mb-1">
                        Threshold / Value
                      </label>
                      <input
                        type="text"
                        value={newCondVal}
                        onChange={(e) => setNewCondVal(e.target.value)}
                        placeholder="e.g., 9.0 or Vishing"
                        className="w-full px-2.5 py-1.5 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs"
                      />
                    </div>
                  </div>
                </div>

                {/* THEN ACTION BUILDER */}
                <div className="p-3.5 rounded-xl bg-[#111A22] border border-rose-500/20 space-y-3">
                  <span className="font-mono font-bold text-rose-400 uppercase tracking-wider block">
                    THEN Action
                  </span>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 text-[10px] mb-1">
                        Mitigation Action Type
                      </label>
                      <select
                        value={newActionType}
                        onChange={(e) => setNewActionType(e.target.value as any)}
                        className="w-full px-2.5 py-1.5 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs font-mono"
                      >
                        <option value="AUTO_BLOCK_IP">AUTO_BLOCK_IP</option>
                        <option value="QUARANTINE_EMAIL">QUARANTINE_EMAIL</option>
                        <option value="REVOKE_OAUTH_TOKEN">REVOKE_OAUTH_TOKEN</option>
                        <option value="FORCE_MFA_REBIND">FORCE_MFA_REBIND</option>
                        <option value="TRIGGER_SIEM_WEBHOOK">TRIGGER_SIEM_WEBHOOK</option>
                        <option value="ISOLATE_ENDPOINT">ISOLATE_ENDPOINT</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 text-[10px] mb-1">
                        Target Object / Pool
                      </label>
                      <input
                        type="text"
                        value={newActionTarget}
                        onChange={(e) => setNewActionTarget(e.target.value)}
                        placeholder="e.g. Perimeter BGP Firewall"
                        className="w-full px-2.5 py-1.5 rounded bg-[#15202B] border border-[#2A3B4C] text-slate-200 text-xs"
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Modal Footer */}
              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#1E293B]">
                <button
                  onClick={() => setIsCreatingRule(false)}
                  className="px-4 py-2 rounded-lg bg-[#15202B] hover:bg-[#1E293B] text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateCustomRule}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs shadow-lg shadow-emerald-950/40"
                >
                  Activate Custom Policy
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
