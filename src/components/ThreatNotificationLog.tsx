import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Bell,
  X,
  Search,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Shield,
  Trash2,
  Copy,
  Check,
  Zap,
  Filter,
  ArrowUpDown,
  FileSpreadsheet,
  ExternalLink,
  Ban,
  MailCheck,
  UserX
} from 'lucide-react';

export interface ThreatNotificationItem {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  primaryVector: string;
  targetRecipient?: string;
  threatScore: number;
  iocs: string[];
  isRead: boolean;
  status: 'active' | 'acknowledged' | 'actioned';
  executedRule?: string;
}

export const INITIAL_NOTIFICATIONS: ThreatNotificationItem[] = [
  {
    id: 'notif-101',
    title: 'CRITICAL: Weaponized Form Smuggling Detected',
    description: 'Microsoft Forms lure (forms.office.com) requesting M365 corporate password and 2FA authenticator OTP token.',
    severity: 'critical',
    timestamp: '2 mins ago',
    primaryVector: 'Form-Smuggling / Credential Harvesting',
    targetRecipient: 'finance-team@acme-corp.com',
    threatScore: 9.8,
    iocs: [
      'Credential harvesting form on forms.office.com asking for corporate password',
      'Cross-domain POST target submit: auth-relay-harvest.org/submit',
      'Hidden parameter entropy anomaly (7 hidden fields)'
    ],
    isRead: false,
    status: 'active'
  },
  {
    id: 'notif-102',
    title: 'HIGH: AiTM Reverse Proxy Reverse Probe',
    description: 'Detected Evilginx2 reverse proxy prepend lure login.microsoftonline.com.auth-verify-security.org.',
    severity: 'high',
    timestamp: '18 mins ago',
    primaryVector: 'Adversary-in-the-Middle (AiTM)',
    targetRecipient: 'sarah.jenkins@acme-corp.com',
    threatScore: 9.2,
    iocs: [
      'Subdomain prepending: login.microsoftonline.com.auth-verify-security.org',
      'Proxy header leak: X-Proxy-Via: Evilginx/2.4',
      'Session token interception attempt: ESTSAUTH cookie harvesting'
    ],
    isRead: false,
    status: 'active'
  },
  {
    id: 'notif-103',
    title: 'HIGH: Vishing Deepfake IT Helpdesk Attack',
    description: 'Synthetic voice vocoder pitch contour variance flatline (0.38 Hz) requesting MFA bypass push approval.',
    severity: 'high',
    timestamp: '1 hour ago',
    primaryVector: 'Vishing (Deepfake Voice)',
    targetRecipient: 'it-helpdesk@acme-corp.com',
    threatScore: 8.7,
    iocs: [
      'Spectral artifact peak at 14.2 kHz (neural vocoder footprint)',
      'Utterance: "Approve the Okta verify push request immediately"',
      'Spoofed caller ID: +1 (800) 555-0199'
    ],
    isRead: true,
    status: 'acknowledged'
  },
  {
    id: 'notif-104',
    title: 'MEDIUM: Quishing Parking Meter Typosquat',
    description: 'QR Code decoding redirected to newly registered domain (3 days old) with CAPTCHA gating evasion.',
    severity: 'medium',
    timestamp: '3 hours ago',
    primaryVector: 'Quishing / Typosquat',
    targetRecipient: 'mobile-fleet@acme-corp.com',
    threatScore: 6.4,
    iocs: [
      'QR Code decoded target: https://pay-citymeter-sanfrancisco.top',
      'Cloudflare Turnstile CAPTCHA sandbox evasion gate',
      'Domain age: 3 days old'
    ],
    isRead: true,
    status: 'actioned',
    executedRule: 'Block Domain at DNS Sinkhole'
  }
];

interface Props {
  isOpen: boolean;
  onClose: () => void;
  notifications: ThreatNotificationItem[];
  setNotifications: React.Dispatch<React.SetStateAction<ThreatNotificationItem[]>>;
  onExecuteRule?: (notificationId: string, ruleName: string) => void;
}

export function ThreatNotificationLog({
  isOpen,
  onClose,
  notifications,
  setNotifications,
  onExecuteRule
}: Props) {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'unread' | 'actioned'>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const unreadCount = notifications.filter((n) => !n.isRead).length;

  const handleMarkAllAsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
  };

  const handleClearAll = () => {
    if (window.confirm('Are you sure you want to clear all notification logs?')) {
      setNotifications([]);
    }
  };

  const handleToggleRead = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: !n.isRead } : n))
    );
  };

  const handleAcknowledge = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) =>
        n.id === id ? { ...n, isRead: true, status: 'acknowledged' } : n
      )
    );
  };

  const handleExecuteSOCRule = (id: string, ruleName: string) => {
    setNotifications((prev) =>
      prev.map((n) =>
        n.id === id
          ? {
              ...n,
              isRead: true,
              status: 'actioned',
              executedRule: ruleName
            }
          : n
      )
    );
    if (onExecuteRule) {
      onExecuteRule(id, ruleName);
    }
  };

  const handleCopyIOCs = (item: ThreatNotificationItem) => {
    const text = `[SPIDER INCIDENT REPORT]\nTitle: ${item.title}\nSeverity: ${item.severity.toUpperCase()}\nVector: ${item.primaryVector}\nScore: ${item.threatScore}/10.0\nIOCs:\n${item.iocs.map((i) => ` - ${i}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopiedId(item.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredNotifications = notifications.filter((item) => {
    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchesTitle = item.title.toLowerCase().includes(q);
      const matchesDesc = item.description.toLowerCase().includes(q);
      const matchesVector = item.primaryVector.toLowerCase().includes(q);
      const matchesIOCs = item.iocs.some((i) => i.toLowerCase().includes(q));
      if (!matchesTitle && !matchesDesc && !matchesVector && !matchesIOCs) {
        return false;
      }
    }

    // Severity
    if (severityFilter !== 'all' && item.severity !== severityFilter) {
      return false;
    }

    // Status
    if (statusFilter === 'unread' && item.isRead) {
      return false;
    }
    if (statusFilter === 'actioned' && item.status !== 'actioned') {
      return false;
    }

    return true;
  });

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden">
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm"
          />

          {/* Drawer panel */}
          <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="w-screen max-w-xl bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col"
            >
              {/* Header */}
              <div className="px-6 py-5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between sticky top-0 z-10 backdrop-blur">
                <div className="flex items-center space-x-3">
                  <div className="relative p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
                    <Bell className="w-5 h-5" />
                    {unreadCount > 0 && (
                      <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white rounded-full text-[10px] font-bold flex items-center justify-center animate-pulse">
                        {unreadCount}
                      </span>
                    )}
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                      Threat Notification Log
                      <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                        {notifications.length} Total
                      </span>
                    </h2>
                    <p className="text-xs text-slate-400">
                      Persistent SOC detection alerts and incident audit trail
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  {unreadCount > 0 && (
                    <button
                      onClick={handleMarkAllAsRead}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium px-2.5 py-1 rounded-md bg-cyan-950/40 border border-cyan-800/40 transition"
                      title="Mark all as read"
                    >
                      Read All
                    </button>
                  )}
                  <button
                    onClick={onClose}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Filters & Search Toolbar */}
              <div className="p-4 bg-slate-950/60 border-b border-slate-800/80 space-y-3">
                {/* Search */}
                <div className="relative">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search alerts by title, vector, IOCs, or target..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 text-xs"
                    >
                      Clear
                    </button>
                  )}
                </div>

                {/* Filter chips */}
                <div className="flex items-center justify-between text-xs gap-2 flex-wrap">
                  <div className="flex items-center space-x-1">
                    <span className="text-slate-500 mr-1 flex items-center gap-1 text-[11px]">
                      <Filter className="w-3 h-3" /> Severity:
                    </span>
                    {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
                      <button
                        key={sev}
                        onClick={() => setSeverityFilter(sev)}
                        className={`px-2 py-0.5 rounded capitalize text-[11px] font-medium transition ${
                          severityFilter === sev
                            ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                            : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center space-x-1">
                    <span className="text-slate-500 mr-1 text-[11px]">Status:</span>
                    {(['all', 'unread', 'actioned'] as const).map((st) => (
                      <button
                        key={st}
                        onClick={() => setStatusFilter(st)}
                        className={`px-2 py-0.5 rounded capitalize text-[11px] font-medium transition ${
                          statusFilter === st
                            ? 'bg-slate-700 text-cyan-300 border border-cyan-500/30'
                            : 'bg-slate-800/50 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Notification List */}
              <div className="flex-1 overflow-y-auto p-4 space-y-3">
                {filteredNotifications.length === 0 ? (
                  <div className="text-center py-12 px-4">
                    <Shield className="w-10 h-10 text-slate-600 mx-auto mb-3 opacity-60" />
                    <p className="text-sm font-medium text-slate-400">No matching threat notifications</p>
                    <p className="text-xs text-slate-500 mt-1">
                      {searchQuery || severityFilter !== 'all'
                        ? 'Try clearing your search filters'
                        : 'New critical detection events will be logged here automatically'}
                    </p>
                  </div>
                ) : (
                  filteredNotifications.map((item) => {
                    const isCritical = item.severity === 'critical';
                    const isHigh = item.severity === 'high';
                    const isMedium = item.severity === 'medium';

                    const borderClass = isCritical
                      ? 'border-red-500/40 bg-red-950/10 hover:border-red-500/70'
                      : isHigh
                      ? 'border-amber-500/40 bg-amber-950/10 hover:border-amber-500/70'
                      : isMedium
                      ? 'border-yellow-500/30 bg-yellow-950/10'
                      : 'border-slate-800 bg-slate-900/50';

                    const badgeBg = isCritical
                      ? 'bg-red-500/20 text-red-300 border-red-500/30'
                      : isHigh
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';

                    return (
                      <motion.div
                        key={item.id}
                        layout
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className={`p-4 rounded-xl border ${borderClass} transition-all relative group ${
                          !item.isRead ? 'ring-1 ring-cyan-500/30 shadow-lg' : ''
                        }`}
                      >
                        {!item.isRead && (
                          <span className="absolute top-4 right-4 w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                        )}

                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border font-mono ${badgeBg}`}
                            >
                              {item.severity}
                            </span>
                            <span className="text-[11px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                              Score: {item.threatScore}/10
                            </span>
                            <span className="text-[11px] text-slate-400 font-mono">
                              {item.timestamp}
                            </span>
                          </div>

                          <button
                            onClick={() => handleToggleRead(item.id)}
                            className="text-slate-500 hover:text-slate-300 text-[11px] opacity-0 group-hover:opacity-100 transition"
                            title={item.isRead ? 'Mark as Unread' : 'Mark as Read'}
                          >
                            {item.isRead ? 'Mark Unread' : 'Mark Read'}
                          </button>
                        </div>

                        {/* Title & Vector */}
                        <h3 className="text-sm font-semibold text-slate-100 leading-snug">
                          {item.title}
                        </h3>
                        <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                          {item.description}
                        </p>

                        {/* Metadata Tag */}
                        <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                          <span className="flex items-center gap-1 font-medium text-cyan-400">
                            <Zap className="w-3 h-3" /> Vector: {item.primaryVector}
                          </span>
                          {item.targetRecipient && (
                            <span className="font-mono text-slate-400 truncate max-w-[180px]">
                              {item.targetRecipient}
                            </span>
                          )}
                        </div>

                        {/* IOC List */}
                        {item.iocs.length > 0 && (
                          <div className="mt-2.5 bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
                            <p className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                              Extracted IOC Flags ({item.iocs.length}):
                            </p>
                            <ul className="space-y-1">
                              {item.iocs.map((ioc, idx) => (
                                <li
                                  key={idx}
                                  className="text-[11px] font-mono text-red-300/90 flex items-start gap-1.5 leading-tight"
                                >
                                  <span className="text-red-400 font-bold">•</span>
                                  <span>{ioc}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Status / Executed Action Indicator */}
                        {item.status === 'actioned' && item.executedRule && (
                          <div className="mt-3 p-2 rounded bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            <span>
                              <strong>Automated Response Rule Executed:</strong> {item.executedRule}
                            </span>
                          </div>
                        )}

                        {/* Quick SOC Actions */}
                        <div className="mt-3.5 flex items-center justify-between pt-2 border-t border-slate-800/40 gap-2 flex-wrap">
                          <div className="flex items-center space-x-2">
                            {item.status !== 'actioned' ? (
                              <>
                                <button
                                  onClick={() =>
                                    handleExecuteSOCRule(
                                      item.id,
                                      'Quarantine Payload & Revoke Active Session'
                                    )
                                  }
                                  className="text-[11px] font-bold px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 flex items-center gap-1 transition"
                                >
                                  <UserX className="w-3 h-3" /> Execute Quarantine
                                </button>
                                <button
                                  onClick={() =>
                                    handleExecuteSOCRule(
                                      item.id,
                                      'Block Domain at DNS Sinkhole'
                                    )
                                  }
                                  className="text-[11px] font-bold px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 flex items-center gap-1 transition"
                                >
                                  <Ban className="w-3 h-3" /> Block Domain
                                </button>
                              </>
                            ) : (
                              <span className="text-[11px] text-emerald-400 font-mono font-semibold flex items-center gap-1">
                                <CheckCircle2 className="w-3.5 h-3.5" /> SOC Action Completed
                              </span>
                            )}
                          </div>

                          <button
                            onClick={() => handleCopyIOCs(item)}
                            className="text-[11px] text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800/80 border border-slate-700/80 flex items-center gap-1 transition"
                          >
                            {copiedId === item.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" /> Copied
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" /> Copy IOCs
                              </>
                            )}
                          </button>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </div>

              {/* Drawer Footer */}
              <div className="p-4 bg-slate-900 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                <span>Auto-refreshing live SOC telemetry stream</span>
                {notifications.length > 0 && (
                  <button
                    onClick={handleClearAll}
                    className="text-red-400 hover:text-red-300 flex items-center gap-1 font-medium hover:underline transition"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Clear All Logs
                  </button>
                )}
              </div>
            </motion.div>
          </div>
        </div>
      )}
    </AnimatePresence>
  );
}
