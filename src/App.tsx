import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Search, FlaskConical } from 'lucide-react';
import { UploadZone } from './components/UploadZone';
import { ThreatVerdictCard } from './components/ThreatVerdictCard';
import { EvidenceCards } from './components/EvidenceCards';
import { TelemetryAccordion } from './components/TelemetryAccordion';
import { CodeExplorer } from './components/CodeExplorer';
import { ArchitectureView } from './components/ArchitectureView';
import { ToastContainer, ToastMessage } from './components/Toast';
import { SpiderLogo } from './components/SpiderLogo';
import { CommandPalette } from './components/CommandPalette';
import { ThreatHistoryTimeline, ThreatHistoryItem } from './components/ThreatHistoryTimeline';
import { ThreatHeatmap } from './components/ThreatHeatmap';
import { AnalysisLiveStream } from './components/AnalysisLiveStream';
import { PayloadSimulatorModal } from './components/PayloadSimulatorModal';
import { ThreatNotificationLog, ThreatNotificationItem, INITIAL_NOTIFICATIONS } from './components/ThreatNotificationLog';
import { INITIAL_THREAT_HISTORY } from './data/initialHistory';
import { generatePDFReport } from './utils/pdfGenerator';
import { ATTACK_PRESETS } from './data/presetAttacks';
import { FusedPayload, ThreatAnalysisResult } from './types';
import { MitigationWizard } from './components/MitigationWizard';
import { AutomatedPolicyEngine } from './components/AutomatedPolicyEngine';
import { Bell, Zap } from 'lucide-react';

export default function App() {
  const [activeNavTab, setActiveNavTab] = useState<'dashboard' | 'policy' | 'lab' | 'code' | 'blueprint'>('dashboard');

  // Unified Multimodal Ingest Buffer
  const [fusedPayload, setFusedPayload] = useState<FusedPayload>(ATTACK_PRESETS[0].fused);

  // Default initial analysis result
  const [analysisResult, setAnalysisResult] = useState<ThreatAnalysisResult>({
    threat_score: 9.2,
    primary_vector: 'Business Email Compromise (BEC) / Whaling',
    indicators_of_compromise: [
      "Executive identity discrepancy: 'From' (cfo@acme-corporation.com) != 'Reply-To' (sarah.jenkins.direct@mail-settlement-routing.xyz)",
      'SPF, DKIM, and DMARC authentication alignment validation failed',
      'Urgent financial wire settlement routing instructions ($74,500)',
    ],
    is_prompt_injection_attempt: false,
    executive_summary:
      'Critical Threat Detected: The payload attempts Business Email Compromise by impersonating CFO Sarah Jenkins with a spoofed Reply-To address demanding an immediate $74,500 wire transfer.',
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState<boolean>(false);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState<boolean>(false);
  const [isNotifLogOpen, setIsNotifLogOpen] = useState<boolean>(false);

  const [notifications, setNotifications] = useState<ThreatNotificationItem[]>(() => {
    try {
      const saved = localStorage.getItem('spider_threat_notifications');
      return saved ? JSON.parse(saved) : INITIAL_NOTIFICATIONS;
    } catch {
      return INITIAL_NOTIFICATIONS;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('spider_threat_notifications', JSON.stringify(notifications));
    } catch (e) {
      console.warn('Failed to persist notifications:', e);
    }
  }, [notifications]);

  const [threatHistory, setThreatHistory] = useState<ThreatHistoryItem[]>(INITIAL_THREAT_HISTORY);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | undefined>('hist-01');


  const handleApplySimulatorMutation = async (updatedFused: FusedPayload) => {
    setFusedPayload(updatedFused);
    addToast(
      'Synthetic Mutation Injected',
      'Updated analysis buffer with synthetic headers and metadata. Re-running detection logic...',
      'warning'
    );
    await triggerLateFusionAnalysis(updatedFused);
  };

  useEffect(() => {
    const handleOpenPalette = () => setIsCommandPaletteOpen(true);
    window.addEventListener('spider-open-command-palette', handleOpenPalette);
    return () => window.removeEventListener('spider-open-command-palette', handleOpenPalette);
  }, []);

  const handleTriggerUpload = () => {
    setActiveNavTab('dashboard');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    addToast('Upload Zone Focused', 'Use the ingestion dock or drag and drop files directly', 'info');
  };

  const addToast = (
    title: string,
    description?: string,
    type: 'success' | 'critical' | 'warning' | 'info' = 'info',
    duration = 5000
  ) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev.slice(-3), { id, title, description, type, duration }]);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const handleExportPDF = () => {
    try {
      generatePDFReport(fusedPayload, analysisResult);
      addToast(
        'PDF Report Generated',
        'Downloaded SPIDER Threat Intelligence Summary Report',
        'success'
      );
    } catch (e) {
      console.error('Failed to generate PDF:', e);
      addToast('PDF Generation Failed', 'An error occurred while compiling the PDF report.', 'warning');
    }
  };

  const handlePayloadSubmit = async (payloadData: { type: 'file' | 'text' | 'url'; content: string; inspectEmbeddedLinks?: boolean; file?: File }) => {
    setIsLoading(true);

    if (payloadData.type === 'url') {
      const target = payloadData.content.toLowerCase();
      addToast(
        'URL Scan Initiated',
        `Scanning ${payloadData.content} ${payloadData.inspectEmbeddedLinks ? '(with Embedded Link & Form Unpacking)' : ''}`,
        'info'
      );

      try {
        const resp = await fetch('/api/analyze/spider-engine', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: payloadData.content,
            additional_iocs: payloadData.inspectEmbeddedLinks ? ['Inspect Embedded Child Links Enabled'] : [],
          }),
        });

        if (resp.ok) {
          const spiderVerdict = await resp.json();
          const isFormTarget = target.includes('forms') || target.includes('typeform') || target.includes('canva');
          const presetBase = isFormTarget
            ? ATTACK_PRESETS.find((p) => p.id === 'weaponized-form-bypass') || ATTACK_PRESETS[0]
            : ATTACK_PRESETS.find((p) => p.id === 'aitm-homoglyph-proxy') || ATTACK_PRESETS[0];

          const updatedFused: FusedPayload = {
            ...presetBase.fused,
            decoded_urls: [{ url: payloadData.content, domain: payloadData.content.split('/')[2] || 'target-domain.com', isTyposquat: target.includes('xn--') || target.includes('0') }],
            sanitization_alerts: [
              ...(spiderVerdict.indicators || []),
              ...(spiderVerdict.automation_rules ? spiderVerdict.automation_rules.map((r: any) => `SOC Automated Rule Triggered: ${r.action} (${r.reason})`) : []),
            ],
          };
          setFusedPayload(updatedFused);
          await triggerLateFusionAnalysis(updatedFused);
          setIsLoading(false);
          return;
        }
      } catch (e) {
        console.warn('Spider engine API fallback:', e);
      }

      // Fallback matching
      const isFormTarget = target.includes('forms') || target.includes('typeform') || target.includes('canva');
      const presetBase = isFormTarget
        ? ATTACK_PRESETS.find((p) => p.id === 'weaponized-form-bypass') || ATTACK_PRESETS[0]
        : ATTACK_PRESETS.find((p) => p.id === 'aitm-homoglyph-proxy') || ATTACK_PRESETS[0];

      const updatedFused: FusedPayload = {
        ...presetBase.fused,
        decoded_urls: [{ url: payloadData.content, domain: payloadData.content.split('/')[2] || 'target-domain.com', isTyposquat: target.includes('xn--') || target.includes('0') }],
      };
      setFusedPayload(updatedFused);
      await triggerLateFusionAnalysis(updatedFused);
    } else if (payloadData.type === 'text') {
      addToast(
        'Text Payload Ingested',
        `Parsed ${payloadData.content.length} characters for URL & OAuth scope analysis`,
        'success'
      );
      try {
        const resp = await fetch('/api/upload/text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: payloadData.content }),
        });
        if (resp.ok) {
          const textData = await resp.json();
          const updatedFused: FusedPayload = {
            ...fusedPayload,
            decoded_urls: textData.urls ? textData.urls.map((u: any) => ({ url: u.url })) : null,
            sanitization_alerts: textData.injection_flags || [],
          };
          setFusedPayload(updatedFused);
          await triggerLateFusionAnalysis(updatedFused);
        }
      } catch (e) {
        console.warn('Text upload API fallback:', e);
      }
    } else if (payloadData.file) {
      const fname = payloadData.file.name.toLowerCase();
      addToast(
        'File Payload Ingested',
        `Successfully loaded ${payloadData.file.name} (${(payloadData.file.size / 1024).toFixed(1)} KB)`,
        'success'
      );

      let updatedFused: FusedPayload = { ...fusedPayload };

      if (fname.includes('qr') || fname.includes('png') || fname.includes('jpg')) {
        updatedFused = ATTACK_PRESETS[1].fused;
      } else if (fname.includes('wav') || fname.includes('mp3') || fname.includes('voice')) {
        updatedFused = ATTACK_PRESETS[2].fused;
      } else {
        updatedFused = ATTACK_PRESETS[0].fused;
      }

      setFusedPayload(updatedFused);
      await triggerLateFusionAnalysis(updatedFused);
    }
    setIsLoading(false);
  };

  const handlePresetSelect = async (presetId: string) => {
    const found = ATTACK_PRESETS.find((p) => p.id === presetId) || ATTACK_PRESETS[0];
    addToast('Scenario Loaded', `Loaded test case: ${found.name}`, 'info');
    setFusedPayload(found.fused);
    await triggerLateFusionAnalysis(found.fused);
  };

  const triggerLateFusionAnalysis = async (payloadToAnalyze: FusedPayload) => {
    setIsLoading(true);
    try {
      const resp = await fetch('/api/analyze/late-fusion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payloadToAnalyze),
      });

      if (resp.ok) {
        const data: ThreatAnalysisResult = await resp.json();
        setAnalysisResult(data);

        // Record in Threat History Timeline
        const subject = payloadToAnalyze.header_metadata?.Subject;
        const payloadTitle = subject && subject.length > 0
          ? subject
          : payloadToAnalyze.synthetic_voice_anomaly
          ? 'Synthetic Audio Voicemail'
          : payloadToAnalyze.ocr_text
          ? 'Ingested Document / QR Code'
          : 'Analyzed Payload';

        const category: 'Email' | 'QR / Image' | 'Voice / Audio' | 'OAuth / Link' = payloadToAnalyze.synthetic_voice_anomaly
          ? 'Voice / Audio'
          : payloadToAnalyze.ocr_text
          ? 'QR / Image'
          : payloadToAnalyze.decoded_urls && payloadToAnalyze.decoded_urls.length > 0
          ? 'OAuth / Link'
          : 'Email';

        const newHistoryId = 'hist-' + Date.now();
        const newHistoryItem: ThreatHistoryItem = {
          id: newHistoryId,
          timestamp: 'Just Now',
          payloadName: payloadTitle,
          score: data.threat_score,
          vector: data.primary_vector,
          category,
          isInjection: data.is_prompt_injection_attempt,
        };

        setSelectedHistoryId(newHistoryId);
        setThreatHistory((prev) => [newHistoryItem, ...prev.filter((i) => i.id !== newHistoryId)].slice(0, 20));

        // Automatically log notification item to Threat Notification Log
        const newNotifItem: ThreatNotificationItem = {
          id: 'notif-' + Date.now(),
          title: data.threat_score >= 8.5 ? `CRITICAL: ${data.primary_vector}` : data.threat_score >= 5.0 ? `HIGH: ${data.primary_vector}` : `LOW: ${data.primary_vector}`,
          description: data.executive_summary || `Payload analyzed with threat score ${data.threat_score.toFixed(1)}/10.0`,
          severity: data.threat_score >= 8.5 ? 'critical' : data.threat_score >= 6.5 ? 'high' : data.threat_score >= 4.0 ? 'medium' : 'low',
          timestamp: 'Just Now',
          primaryVector: data.primary_vector,
          targetRecipient: payloadToAnalyze.header_metadata?.To || 'target-user@organization.com',
          threatScore: data.threat_score,
          iocs: data.indicators_of_compromise || [],
          isRead: false,
          status: 'active'
        };
        setNotifications((prev) => [newNotifItem, ...prev]);

        // Alert user with toast based on threat severity score
        if (data.threat_score >= 8.5 || data.is_prompt_injection_attempt) {
          addToast(
            'CRITICAL THREAT DETECTED',
            `Score ${data.threat_score.toFixed(1)}/10.0 • ${data.primary_vector}`,
            'critical',
            7000
          );
        } else if (data.threat_score >= 5.0) {
          addToast(
            'ELEVATED RISK IDENTIFIED',
            `Score ${data.threat_score.toFixed(1)}/10.0 • ${data.primary_vector}`,
            'warning',
            6000
          );
        } else {
          addToast(
            'ANALYSIS COMPLETE',
            `Score ${data.threat_score.toFixed(1)}/10.0 • Benign or low risk payload`,
            'success',
            5000
          );
        }
      }
    } catch (err) {
      console.warn('Backend API fallback:', err);
    } finally {
      setIsLoading(false);
    }
  };


  return (
    <div className="min-h-screen bg-[#020406] text-neutral-100 font-sans selection:bg-white/20 selection:text-white flex flex-col antialiased relative overflow-x-hidden">
      {/* DYNAMIC CYBER ATMOSPHERIC BACKGROUND OVERLAY */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        {/* Dark Radial Gradient (#04080B center -> #020406 edges) */}
        <div className="absolute inset-0 cyber-bg opacity-100" />

        {/* Delicate Low-Contrast Grid Mesh (Opacity 0.04) */}
        <div className="absolute inset-0 cyber-grid opacity-100" />

        {/* Ultra-Soft Ambient Emerald Radial Spotlights */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[750px] h-[750px] bg-emerald-500/5 rounded-full blur-[140px]" />
        <div className="absolute bottom-1/3 left-1/3 w-[550px] h-[550px] bg-emerald-600/3 rounded-full blur-[160px]" />

        {/* Centered Faint Low-Opacity (6% to 7%) Glowing Emerald Green SVG Spider Watermark */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-[0.065] scale-125 md:scale-150 transform transition-transform duration-1000">
          <img
            src="/spider-logo.svg"
            alt=""
            aria-hidden="true"
            className="w-[620px] h-[620px] max-w-full object-contain filter drop-shadow-[0_0_40px_rgba(16,185,129,0.8)]"
          />
        </div>

        {/* Minimalist Tech HUD Accent Corner Nodes */}
        <div className="absolute top-6 left-6 w-10 h-10 border-l border-t border-emerald-500/15" />
        <div className="absolute top-6 right-6 w-10 h-10 border-r border-t border-emerald-500/15" />
        <div className="absolute bottom-6 left-6 w-10 h-10 border-l border-b border-emerald-500/15" />
        <div className="absolute bottom-6 right-6 w-10 h-10 border-r border-b border-emerald-500/15" />
      </div>

      {/* Toast Notification Container */}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />

      {/* Sleek Minimalist Top Navigation Header */}
      <header className="sticky top-0 z-50 bg-[#04080B]/80 backdrop-blur-md border-b border-white/10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between relative z-10">
          {/* Brand Mark */}
          <div className="flex items-center gap-3">
            <SpiderLogo className="w-8 h-8" />
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold tracking-tight text-neutral-100 font-mono">
                SPIDER
              </span>
              <span className="hidden sm:inline text-[11px] text-neutral-400 font-sans border-l border-neutral-800 pl-2">
                System for Phishing Identification, Detection, and Execution Response
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-neutral-900 border border-neutral-800 text-neutral-400 font-mono">
                v2.0
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-6">
            <button
              onClick={() => setActiveNavTab('dashboard')}
              className={`text-xs font-medium transition-colors cursor-pointer ${
                activeNavTab === 'dashboard'
                  ? 'text-neutral-100 font-semibold'
                  : 'text-neutral-400 hover:text-neutral-100'
              }`}
            >
              Dashboard
            </button>

            <button
              onClick={() => setActiveNavTab('policy')}
              className={`text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                activeNavTab === 'policy'
                  ? 'text-emerald-400 font-semibold'
                  : 'text-neutral-400 hover:text-neutral-100'
              }`}
            >
              <Zap className="w-3.5 h-3.5 text-emerald-400" />
              Policy Engine
            </button>

            <button
              onClick={() => setActiveNavTab('lab')}
              className={`text-xs font-medium transition-colors cursor-pointer ${
                activeNavTab === 'lab'
                  ? 'text-neutral-100 font-semibold'
                  : 'text-neutral-400 hover:text-neutral-100'
              }`}
            >
              Scenarios
            </button>

            <button
              onClick={() => setActiveNavTab('code')}
              className={`text-xs font-medium transition-colors cursor-pointer ${
                activeNavTab === 'code'
                  ? 'text-neutral-100 font-semibold'
                  : 'text-neutral-400 hover:text-neutral-100'
              }`}
            >
              Python Code
            </button>

            <button
              onClick={() => setActiveNavTab('blueprint')}
              className={`text-xs font-medium transition-colors cursor-pointer ${
                activeNavTab === 'blueprint'
                  ? 'text-neutral-100 font-semibold'
                  : 'text-neutral-400 hover:text-neutral-100'
              }`}
            >
              Blueprint
            </button>

            {/* Payload Simulator Trigger Button */}
            <button
              onClick={() => setIsSimulatorOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-mono transition cursor-pointer shrink-0 shadow-sm"
              title="Open Payload Simulator & Stress-Tester"
            >
              <FlaskConical className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Payload Simulator</span>
            </button>

            {/* Threat Notification Log Bell Trigger Button */}
            <button
              onClick={() => setIsNotifLogOpen(true)}
              className="relative inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-300 text-xs font-mono transition cursor-pointer shrink-0 shadow-sm"
              title="Open Persistent Threat Notification Log"
            >
              <Bell className="w-3.5 h-3.5 text-red-400" />
              <span className="hidden sm:inline">Alert Log</span>
              {notifications.filter((n) => !n.isRead).length > 0 && (
                <span className="ml-0.5 px-1.5 py-0.2 rounded-full bg-red-500 text-white text-[10px] font-bold font-mono">
                  {notifications.filter((n) => !n.isRead).length}
                </span>
              )}
            </button>

            {/* Command Palette Trigger Button */}
            <button
              onClick={() => setIsCommandPaletteOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-neutral-900/90 hover:bg-neutral-800 border border-neutral-800 hover:border-emerald-500/40 text-neutral-400 hover:text-neutral-200 text-xs font-mono transition cursor-pointer shrink-0"
              title="Global Command Palette (⌘K / Ctrl+K)"
            >
              <Search className="w-3 h-3 text-emerald-400" />
              <span className="text-[11px] font-mono">⌘K</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Persistent Threat Notification Log Side-Panel */}
      <ThreatNotificationLog
        isOpen={isNotifLogOpen}
        onClose={() => setIsNotifLogOpen(false)}
        notifications={notifications}
        setNotifications={setNotifications}
        onExecuteRule={(id, ruleName) => {
          addToast(
            'SOC Rule Executed',
            `Successfully triggered response rule: ${ruleName}`,
            'success'
          );
        }}
      />

      {/* Global Command Palette Modal (⌘K) */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigate={(tab) => setActiveNavTab(tab)}
        onSelectPreset={handlePresetSelect}
        onTriggerUpload={handleTriggerUpload}
        onExportPDF={handleExportPDF}
        onTriggerAnalyze={() => triggerLateFusionAnalysis(fusedPayload)}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        activeTab={activeNavTab}
      />

      {/* Payload Simulator Modal */}
      <PayloadSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        fusedPayload={fusedPayload}
        onApplyMutation={handleApplySimulatorMutation}
      />


      {/* Main Content Container */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 flex-1 w-full space-y-6 relative z-10">
        <AnimatePresence mode="wait">
          {activeNavTab === 'dashboard' && (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="space-y-6"
            >
              {/* 1. UploadZone Component */}
              <UploadZone
                onPayloadSubmit={handlePayloadSubmit}
                onPresetSelect={handlePresetSelect}
                isLoading={isLoading}
              />

              {/* 2. ThreatVerdictCard Component */}
              <ThreatVerdictCard
                result={analysisResult}
                fusedPayload={fusedPayload}
                isLoading={isLoading}
                onAnalyzeClick={() => triggerLateFusionAnalysis(fusedPayload)}
                onDownloadPDF={handleExportPDF}
              />

              {/* 2b. Mitigation Action Plan Wizard Component */}
              <MitigationWizard
                result={analysisResult}
                fusedPayload={fusedPayload}
                onToast={addToast}
              />

              {/* 2c. Automated Policy Engine Component */}
              <AutomatedPolicyEngine
                analysisResult={analysisResult}
                fusedPayload={fusedPayload}
                addToast={addToast}
              />

              {/* 3. ThreatHistoryTimeline Component (Recharts Timeline) */}
              <ThreatHistoryTimeline
                history={threatHistory}
                activeId={selectedHistoryId}
                onSelectHistoryItem={(item) => {
                  setSelectedHistoryId(item.id);
                  addToast(
                    'History Payload Selected',
                    `${item.payloadName} • Score ${item.score.toFixed(1)}/10.0`,
                    'info'
                  );
                }}
              />

              {/* 4. ThreatHeatmap Component (Recharts Spatial & Geo Origin Analysis) */}
              <ThreatHeatmap fused={fusedPayload} />

              {/* 5. EvidenceCards Component */}
              <EvidenceCards
                indicators={analysisResult.indicators_of_compromise}
                primaryVector={analysisResult.primary_vector}
                isInjection={analysisResult.is_prompt_injection_attempt}
              />

              {/* 6. Analysis Live-Stream Component */}
              <AnalysisLiveStream
                isLoading={isLoading}
                fused={fusedPayload}
                result={analysisResult}
              />

              {/* 7. TelemetryAccordion Component */}
              <TelemetryAccordion fused={fusedPayload} result={analysisResult} />
            </motion.div>
          )}

          {activeNavTab === 'policy' && (
            <motion.div
              key="policy"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <AutomatedPolicyEngine
                analysisResult={analysisResult}
                fusedPayload={fusedPayload}
                addToast={addToast}
              />
            </motion.div>
          )}

          {activeNavTab === 'lab' && (
            <motion.div
              key="lab"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="grid grid-cols-1 md:grid-cols-2 gap-4"
            >
              {ATTACK_PRESETS.map((preset) => (
                <div
                  key={preset.id}
                  className="glass-card rounded-xl p-5 border border-white/10 flex flex-col justify-between hover:border-neutral-700 transition group"
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-neutral-900 border border-neutral-800 text-neutral-400">
                        {preset.category}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-medium ${
                          preset.riskLevel === 'CRITICAL'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}
                      >
                        {preset.riskLevel}
                      </span>
                    </div>

                    <h3 className="text-xs font-medium text-neutral-100 font-sans mb-1.5 group-hover:text-white transition">
                      {preset.name}
                    </h3>

                    <p className="text-xs text-neutral-400 leading-relaxed mb-4">
                      {preset.description}
                    </p>
                  </div>

                  <button
                    onClick={() => {
                      handlePresetSelect(preset.id);
                      setActiveNavTab('dashboard');
                    }}
                    className="w-full py-2 rounded-lg bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 text-neutral-200 text-xs font-mono transition cursor-pointer"
                  >
                    Load Test Scenario
                  </button>
                </div>
              ))}
            </motion.div>
          )}

          {activeNavTab === 'code' && (
            <motion.div
              key="code"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <CodeExplorer />
            </motion.div>
          )}

          {activeNavTab === 'blueprint' && (
            <motion.div
              key="blueprint"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
            >
              <ArchitectureView />
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Minimalist Footer */}
      <footer className="border-t border-white/5 py-4 bg-[#020406]/90 backdrop-blur-md relative z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 flex items-center justify-between text-[11px] text-neutral-500 font-mono">
          <div className="flex items-center gap-2">
            <SpiderLogo className="w-4 h-4" showGlow={false} />
            <span>SPIDER — System for Phishing Identification, Detection, and Execution Response</span>
          </div>
          <span>Next.js • Express • Tailwind CSS • Framer Motion</span>
        </div>
      </footer>
    </div>
  );
}
