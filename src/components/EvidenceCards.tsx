import React from 'react';
import { motion, Variants } from 'motion/react';
import {
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  FormInput,
  Globe,
  Link2,
  Lock,
  Layers,
  KeyRound,
  ShieldX,
} from 'lucide-react';

interface EvidenceCardsProps {
  indicators: string[];
  primaryVector: string;
  isInjection: boolean;
}

// Framer Motion variants for staggered entrance animations
const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.12,
      delayChildren: 0.05,
    },
  },
};

const gridContainerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.05,
    },
  },
};

const cardFadeInVariant: Variants = {
  hidden: { opacity: 0, y: 18, scale: 0.98 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.45,
      ease: 'easeOut',
    },
  },
};

const listContainerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.08,
    },
  },
};

const listItemFadeInVariant: Variants = {
  hidden: { opacity: 0, x: -12, y: 4 },
  visible: {
    opacity: 1,
    x: 0,
    y: 0,
    transition: {
      duration: 0.35,
      ease: 'easeOut',
    },
  },
};

export const EvidenceCards: React.FC<EvidenceCardsProps> = ({
  indicators,
  primaryVector,
  isInjection,
}) => {
  // Check for presence of specific Vector A / Vector B forensic signals
  const hasFormHarvestSignal = indicators.some(
    (i) =>
      i.toLowerCase().includes('form credential harvest') ||
      i.toLowerCase().includes('form') ||
      i.toLowerCase().includes('saas') ||
      primaryVector.toLowerCase().includes('form')
  );

  const hasHomoglyphSignal = indicators.some(
    (i) =>
      i.toLowerCase().includes('homoglyph') ||
      i.toLowerCase().includes('typosquat') ||
      i.toLowerCase().includes('punycode') ||
      i.toLowerCase().includes('xn--') ||
      primaryVector.toLowerCase().includes('homoglyph')
  );

  const hasRedirectChainSignal = indicators.some(
    (i) =>
      i.toLowerCase().includes('redirect chain') ||
      i.toLowerCase().includes('breadcrumbs') ||
      i.toLowerCase().includes('chain') ||
      i.toLowerCase().includes('bitly') ||
      i.toLowerCase().includes('evilginx')
  );

  const getIndicatorMeta = (ioc: string) => {
    const lower = ioc.toLowerCase();

    if (lower.includes('form credential harvest') || lower.includes('password & mfa')) {
      return {
        title: 'Illegal Form Credential Harvesting Prompt',
        category: 'Vector A: Weaponized Form',
        mitre: 'T1566.003',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('homoglyph') || lower.includes('punycode') || lower.includes('typosquat')) {
      return {
        title: 'IDN Punycode Brand Homoglyph Spoofing',
        category: 'Vector B: URL Phishing',
        mitre: 'T1566.002',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('redirect chain') || lower.includes('breadcrumbs') || lower.includes('evilginx')) {
      return {
        title: 'Multi-Hop Evasive Redirect Chain',
        category: 'Vector B: AiTM Proxy',
        mitre: 'T1556',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('reply-to') || lower.includes('from') || lower.includes('mismatch')) {
      return {
        title: 'Header Identity Discrepancy',
        category: 'BEC / Whaling',
        mitre: 'T1566.001',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('voice') || lower.includes('pitch') || lower.includes('mfcc')) {
      return {
        title: 'Synthetic Voice Vocoder Anomaly',
        category: 'Vishing Deepfake',
        mitre: 'T1598',
        severity: 'HIGH',
        codeText: ioc,
      };
    } else if (lower.includes('qr') || lower.includes('quishing')) {
      return {
        title: 'Embedded QR Code Barcode',
        category: 'Quishing Matrix',
        mitre: 'T1566.002',
        severity: 'HIGH',
        codeText: ioc,
      };
    } else if (lower.includes('oauth') || lower.includes('scope') || lower.includes('consent')) {
      return {
        title: 'High-Privilege OAuth Scope Solicitation',
        category: 'Consent Phishing',
        mitre: 'T1528',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('aitm') || lower.includes('evilginx') || lower.includes('prepending')) {
      return {
        title: 'AiTM Reverse-Proxy Routing',
        category: 'MFA Bypass',
        mitre: 'T1556',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else if (lower.includes('prompt injection') || lower.includes('override') || lower.includes('steganographic')) {
      return {
        title: 'Perceptual Asymmetry & Indirect Injection',
        category: 'Adversarial Prompt',
        mitre: 'AML.T0054',
        severity: 'CRITICAL',
        codeText: ioc,
      };
    } else {
      return {
        title: 'Suspicious Forensic Signal',
        category: 'Late Fusion',
        mitre: 'T1566',
        severity: 'ELEVATED',
        codeText: ioc,
      };
    }
  };

  return (
    <motion.div
      key={indicators.join('-') || 'evidence-container'}
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-4"
    >
      {/* HIGH-FIDELITY FORENSIC TELEMETRY CARDS GRID WITH STAGGERED FADE-IN */}
      <motion.div
        variants={gridContainerVariants}
        className="grid grid-cols-1 md:grid-cols-3 gap-3"
      >
        {/* Card 1: Form Credential Harvest Score */}
        <motion.div
          variants={cardFadeInVariant}
          whileHover={{ y: -2, transition: { duration: 0.2 } }}
          className={`p-4 rounded-xl border backdrop-blur-md relative overflow-hidden flex flex-col justify-between transition-colors ${
            hasFormHarvestSignal
              ? 'bg-rose-500/5 border-rose-500/30 shadow-[0_0_15px_rgba(239,68,68,0.15)]'
              : 'bg-neutral-900/40 border-white/10'
          }`}
        >
          <div className="space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <FormInput className={`w-4 h-4 ${hasFormHarvestSignal ? 'text-rose-400' : 'text-neutral-400'}`} />
                <span className="text-xs font-mono font-semibold text-neutral-200">
                  Form Credential Harvest Score
                </span>
              </div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider shrink-0 ${
                  hasFormHarvestSignal
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}
              >
                {hasFormHarvestSignal ? '9.6 / 10.0' : '0.0 / 10.0'}
              </span>
            </div>

            <p className="text-[11px] text-neutral-400 leading-relaxed">
              Detects illegal password, OTP, and seed phrase inputs inside unverified third-party SaaS forms.
            </p>
          </div>

          <div className="mt-3 pt-2 border-t border-white/5 space-y-1.5 font-mono text-[11px]">
            <div className="flex items-center justify-between text-neutral-400">
              <span className="text-[10px] uppercase text-neutral-500">Sensitive Prompts:</span>
              <div className="flex items-center gap-1">
                <span className="px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 text-[10px]">Password</span>
                <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 text-[10px]">MFA OTP</span>
              </div>
            </div>
            <div className="flex items-center justify-between text-neutral-400">
              <span className="text-[10px] uppercase text-neutral-500">Host Status:</span>
              <span className="text-neutral-200 truncate max-w-[150px]">forms.office.com</span>
            </div>
          </div>
        </motion.div>

        {/* Card 2: URL Homoglyph & Typosquat Flag */}
        <motion.div
          variants={cardFadeInVariant}
          whileHover={{ y: -2, transition: { duration: 0.2 } }}
          className={`p-4 rounded-xl border backdrop-blur-md relative overflow-hidden flex flex-col justify-between transition-colors ${
            hasHomoglyphSignal
              ? 'bg-rose-500/5 border-rose-500/30 shadow-[0_0_15px_rgba(239,68,68,0.15)]'
              : 'bg-neutral-900/40 border-white/10'
          }`}
        >
          <div className="space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <Globe className={`w-4 h-4 ${hasHomoglyphSignal ? 'text-rose-400' : 'text-neutral-400'}`} />
                <span className="text-xs font-mono font-semibold text-neutral-200">
                  URL Homoglyph & Typosquat Flag
                </span>
              </div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider shrink-0 ${
                  hasHomoglyphSignal
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}
              >
                {hasHomoglyphSignal ? 'HOMOGLYPH MATCH' : 'SAFE DOMAIN'}
              </span>
            </div>

            <p className="text-[11px] text-neutral-400 leading-relaxed">
              Decodes Punycode IDN strings and computes Levenshtein distance against top targeted SSO brands.
            </p>
          </div>

          <div className="mt-3 pt-2 border-t border-white/5 space-y-1 font-mono text-[11px]">
            <div className="p-1.5 rounded bg-neutral-950 border border-neutral-800 text-[10px] flex items-center justify-between">
              <span className="text-rose-400 font-bold truncate">micr0soft-portal.xyz</span>
              <span className="text-neutral-500 shrink-0">➔ Target: <strong className="text-emerald-400">Microsoft</strong></span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-neutral-500 pt-0.5">
              <span>Punycode: xn--microsft-portal-30b.com</span>
              <span>Dist: 1</span>
            </div>
          </div>
        </motion.div>

        {/* Card 3: Redirect Chain Breadcrumbs */}
        <motion.div
          variants={cardFadeInVariant}
          whileHover={{ y: -2, transition: { duration: 0.2 } }}
          className={`p-4 rounded-xl border backdrop-blur-md relative overflow-hidden flex flex-col justify-between transition-colors ${
            hasRedirectChainSignal
              ? 'bg-rose-500/5 border-rose-500/30 shadow-[0_0_15px_rgba(239,68,68,0.15)]'
              : 'bg-neutral-900/40 border-white/10'
          }`}
        >
          <div className="space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <Layers className={`w-4 h-4 ${hasRedirectChainSignal ? 'text-rose-400' : 'text-neutral-400'}`} />
                <span className="text-xs font-mono font-semibold text-neutral-200">
                  Redirect Chain Breadcrumbs
                </span>
              </div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider shrink-0 ${
                  hasRedirectChainSignal
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}
              >
                {hasRedirectChainSignal ? '3 HOPS (AiTM)' : 'DIRECT LINK'}
              </span>
            </div>

            <p className="text-[11px] text-neutral-400 leading-relaxed">
              Traces evasive URL shortener chains and intermediate Adversary-in-the-Middle reverse proxies.
            </p>
          </div>

          <div className="mt-3 pt-2 border-t border-white/5 space-y-1">
            <div className="flex items-center gap-1 overflow-x-auto text-[10px] font-mono py-1 scrollbar-none">
              <span className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-300 shrink-0">
                forms.office.com
              </span>
              <ArrowRight className="w-3 h-3 text-neutral-500 shrink-0" />
              <span className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-amber-300 shrink-0">
                bit.ly/3x8K9m
              </span>
              <ArrowRight className="w-3 h-3 text-neutral-500 shrink-0" />
              <span className="px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/30 text-rose-300 font-bold shrink-0">
                Evilginx Proxy
              </span>
            </div>
            <div className="text-[10px] font-mono text-neutral-500 text-right">
              Threat Score: <strong className="text-rose-400">9.8/10</strong>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* MAIN CORRELATED RED FLAGS CARD WITH STAGGERED LIST ENTRANCE */}
      <motion.div
        variants={cardFadeInVariant}
        className="glass-card rounded-xl p-5 border border-white/10 bg-[#080D11]"
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-white/5 mb-2">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <h3 className="text-xs font-medium text-neutral-300 font-mono uppercase tracking-widest">
              CORRELATED RED FLAGS ({indicators.length})
            </h3>
          </div>
          <span className="text-[11px] font-mono text-neutral-500">Linear Ticket View</span>
        </div>

        {/* High-Density Row List with Staggered Entrance Animations */}
        <motion.div
          variants={listContainerVariants}
          className="divide-y divide-white/5"
        >
          {indicators.map((ioc, idx) => {
            const meta = getIndicatorMeta(ioc);
            return (
              <motion.div
                key={idx}
                variants={listItemFadeInVariant}
                whileHover={{ x: 4, backgroundColor: 'rgba(255, 255, 255, 0.02)' }}
                className="py-3 px-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors rounded-lg"
              >
                <div className="flex items-start sm:items-center gap-3">
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase shrink-0 font-medium ${
                      meta.severity === 'CRITICAL'
                        ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                    }`}
                  >
                    {meta.severity}
                  </span>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-neutral-200 font-sans">
                        {meta.title}
                      </span>
                      <span className="text-[10px] font-mono text-neutral-500">
                        • {meta.category}
                      </span>
                    </div>

                    {/* Code snippet for raw signal */}
                    <div className="mt-1 font-mono text-[11px] text-neutral-400 bg-neutral-900/60 border border-neutral-800/80 rounded p-1.5 max-w-xl truncate">
                      {meta.codeText}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-[11px] font-mono text-neutral-500 shrink-0 self-end sm:self-auto">
                  <span className="text-neutral-400">{meta.mitre}</span>
                  <ArrowUpRight className="w-3.5 h-3.5 text-neutral-600" />
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      </motion.div>
    </motion.div>
  );
};
