import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Search,
  LayoutDashboard,
  FlaskConical,
  Code2,
  GitBranch,
  Upload,
  FileDown,
  Play,
  Zap,
  ShieldAlert,
  X,
  Command,
} from 'lucide-react';
import { ATTACK_PRESETS } from '../data/presetAttacks';

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: 'dashboard' | 'policy' | 'lab' | 'code' | 'blueprint') => void;
  onSelectPreset: (presetId: string) => void;
  onTriggerUpload: () => void;
  onExportPDF: () => void;
  onTriggerAnalyze: () => void;
  onOpenSimulator?: () => void;
  activeTab: 'dashboard' | 'policy' | 'lab' | 'code' | 'blueprint';
}

interface CommandItem {
  id: string;
  category: 'Navigation' | 'Actions' | 'Test Scenarios';
  label: string;
  sublabel?: string;
  icon: React.ReactNode;
  shortcut?: string;
  action: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate,
  onSelectPreset,
  onTriggerUpload,
  onExportPDF,
  onTriggerAnalyze,
  onOpenSimulator,
  activeTab,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Global keydown handler for direct shortcuts (⌘K, ⌘1-4, ⌘U, ⌘P, ESC)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCmdOrCtrl = e.metaKey || e.ctrlKey;

      // 1. Toggle Command Palette with ⌘K or Ctrl+K
      if (isCmdOrCtrl && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Open palette
          window.dispatchEvent(new CustomEvent('spider-open-command-palette'));
        }
        return;
      }

      // 2. Escape key closes palette
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        onClose();
        return;
      }

      // 3. Direct Shortcuts when palette is NOT open (or open)
      if (isCmdOrCtrl && !e.shiftKey && !e.altKey) {
        if (e.key === '1') {
          e.preventDefault();
          onNavigate('dashboard');
          if (isOpen) onClose();
        } else if (e.key === '2') {
          e.preventDefault();
          onNavigate('lab');
          if (isOpen) onClose();
        } else if (e.key === '3') {
          e.preventDefault();
          onNavigate('code');
          if (isOpen) onClose();
        } else if (e.key === '4') {
          e.preventDefault();
          onNavigate('blueprint');
          if (isOpen) onClose();
        } else if (e.key.toLowerCase() === 'u') {
          e.preventDefault();
          onTriggerUpload();
          if (isOpen) onClose();
        } else if (e.key.toLowerCase() === 'p') {
          e.preventDefault();
          onExportPDF();
          if (isOpen) onClose();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, onNavigate, onTriggerUpload, onExportPDF]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Command Items Registry
  const allCommands: CommandItem[] = [
    // Navigation
    {
      id: 'nav-dashboard',
      category: 'Navigation',
      label: 'Go to Dashboard',
      sublabel: 'Ingest zone, threat verdict, IoCs, and telemetry',
      icon: <LayoutDashboard className="w-4 h-4 text-emerald-400" />,
      shortcut: '⌘1',
      action: () => {
        onNavigate('dashboard');
        onClose();
      },
    },
    {
      id: 'nav-policy',
      category: 'Navigation',
      label: 'Go to Automated Policy Engine',
      sublabel: 'Custom IFTTT rules, condition logic & SOAR actions',
      icon: <Zap className="w-4 h-4 text-emerald-400" />,
      shortcut: '⌘2',
      action: () => {
        onNavigate('policy');
        onClose();
      },
    },
    {
      id: 'nav-lab',
      category: 'Navigation',
      label: 'Go to Scenarios (Lab)',
      sublabel: 'Preset attack scenarios and threat vectors',
      icon: <FlaskConical className="w-4 h-4 text-amber-400" />,
      shortcut: '⌘2',
      action: () => {
        onNavigate('lab');
        onClose();
      },
    },
    {
      id: 'nav-code',
      category: 'Navigation',
      label: 'Go to Python Backend Code',
      sublabel: 'Explore extractors.py, analyzer.py, and celery workers',
      icon: <Code2 className="w-4 h-4 text-cyan-400" />,
      shortcut: '⌘3',
      action: () => {
        onNavigate('code');
        onClose();
      },
    },
    {
      id: 'nav-blueprint',
      category: 'Navigation',
      label: 'Go to Architecture Blueprint',
      sublabel: 'Multimodal threat pipeline system design',
      icon: <GitBranch className="w-4 h-4 text-purple-400" />,
      shortcut: '⌘4',
      action: () => {
        onNavigate('blueprint');
        onClose();
      },
    },

    // Actions
    {
      id: 'action-upload',
      category: 'Actions',
      label: 'Upload Payload File / Text',
      sublabel: 'Ingest .eml, .wav, .png, or raw text string',
      icon: <Upload className="w-4 h-4 text-emerald-400" />,
      shortcut: '⌘U',
      action: () => {
        onTriggerUpload();
        onClose();
      },
    },
    {
      id: 'action-export-pdf',
      category: 'Actions',
      label: 'Download PDF Threat Intelligence Report',
      sublabel: 'Export publication-grade PDF summary with IoCs and telemetry',
      icon: <FileDown className="w-4 h-4 text-rose-400" />,
      shortcut: '⌘P',
      action: () => {
        onExportPDF();
        onClose();
      },
    },
    {
      id: 'action-reanalyze',
      category: 'Actions',
      label: 'Run Late-Fusion Threat Analysis Engine',
      sublabel: 'Execute full multimodal late-fusion evaluation',
      icon: <Play className="w-4 h-4 text-amber-400" />,
      action: () => {
        onTriggerAnalyze();
        onClose();
      },
    },
    {
      id: 'action-simulator',
      category: 'Actions',
      label: 'Open Payload Simulator & Stress-Tester',
      sublabel: 'Inject synthetic headers, deepfake signals, and adversarial mutations',
      icon: <FlaskConical className="w-4 h-4 text-emerald-400" />,
      shortcut: '⌘S',
      action: () => {
        onOpenSimulator?.();
        onClose();
      },
    },

    // Attack Scenarios
    ...ATTACK_PRESETS.map((preset) => ({
      id: `preset-${preset.id}`,
      category: 'Test Scenarios' as const,
      label: preset.name,
      sublabel: `${preset.category} • ${preset.riskLevel} Risk`,
      icon: <ShieldAlert className="w-4 h-4 text-rose-400" />,
      action: () => {
        onSelectPreset(preset.id);
        onClose();
      },
    })),
  ];

  // Filter commands by search query
  const filteredCommands = allCommands.filter((cmd) => {
    const q = query.toLowerCase().trim();
    if (!q) return true;
    return (
      cmd.label.toLowerCase().includes(q) ||
      cmd.category.toLowerCase().includes(q) ||
      (cmd.sublabel && cmd.sublabel.toLowerCase().includes(q))
    );
  });

  // Keep index within bounds
  useEffect(() => {
    if (selectedIndex >= filteredCommands.length) {
      setSelectedIndex(Math.max(0, filteredCommands.length - 1));
    }
  }, [filteredCommands.length, selectedIndex]);

  // Arrow key navigation inside open palette
  const handlePaletteKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % Math.max(1, filteredCommands.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].action();
      }
    }
  };

  // Group filtered items by category
  const groupedCategories = ['Navigation', 'Actions', 'Test Scenarios'] as const;

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-start justify-center pt-16 sm:pt-24 px-4">
          {/* Glassmorphic Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/75 backdrop-blur-md"
          />

          {/* Dialog Container */}
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -8 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="relative w-full max-w-2xl bg-[#080D12]/95 border border-white/10 rounded-2xl shadow-2xl overflow-hidden glass-panel z-10 flex flex-col max-h-[80vh]"
          >
            {/* Search Input Bar */}
            <div className="flex items-center px-4 py-3.5 border-b border-white/10 gap-3">
              <Search className="w-4 h-4 text-emerald-400 shrink-0" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setSelectedIndex(0);
                }}
                onKeyDown={handlePaletteKeyDown}
                placeholder="Type a command, navigate tabs, or switch scenarios... (⌘K)"
                className="w-full bg-transparent text-sm text-neutral-100 placeholder-neutral-500 focus:outline-none font-sans"
              />
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-400 shrink-0">
                ESC
              </span>
              <button
                onClick={onClose}
                className="text-neutral-500 hover:text-neutral-200 transition cursor-pointer shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Filtered Commands List */}
            <div className="overflow-y-auto p-2 space-y-4 flex-1">
              {filteredCommands.length === 0 ? (
                <div className="py-12 text-center text-xs font-mono text-neutral-500">
                  No matching commands or scenarios found for &quot;{query}&quot;
                </div>
              ) : (
                groupedCategories.map((cat) => {
                  const catItems = filteredCommands.filter((item) => item.category === cat);
                  if (catItems.length === 0) return null;

                  return (
                    <div key={cat} className="space-y-1">
                      <div className="px-3 py-1 text-[10px] font-mono font-semibold text-neutral-500 uppercase tracking-wider">
                        {cat}
                      </div>

                      {catItems.map((cmd) => {
                        const globalIndex = filteredCommands.findIndex((c) => c.id === cmd.id);
                        const isSelected = globalIndex === selectedIndex;

                        return (
                          <div
                            key={cmd.id}
                            onClick={cmd.action}
                            onMouseEnter={() => setSelectedIndex(globalIndex)}
                            className={`w-full text-left px-3 py-2.5 rounded-xl flex items-center justify-between gap-3 transition cursor-pointer ${
                              isSelected
                                ? 'bg-neutral-800/90 text-white border border-emerald-500/30'
                                : 'text-neutral-300 hover:bg-neutral-900/60 border border-transparent'
                            }`}
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <div
                                className={`p-1.5 rounded-lg ${
                                  isSelected ? 'bg-emerald-500/20 text-emerald-300' : 'bg-neutral-900 text-neutral-400'
                                }`}
                              >
                                {cmd.icon}
                              </div>
                              <div className="min-w-0">
                                <div className="text-xs font-medium font-sans text-neutral-100 truncate">
                                  {cmd.label}
                                </div>
                                {cmd.sublabel && (
                                  <div className="text-[11px] font-mono text-neutral-400 truncate">
                                    {cmd.sublabel}
                                  </div>
                                )}
                              </div>
                            </div>

                            {cmd.shortcut && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-400 shrink-0">
                                {cmd.shortcut}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  );
                })
              )}
            </div>

            {/* Footer Shortcut Legend */}
            <div className="px-4 py-2.5 border-t border-white/5 bg-[#04080B] flex items-center justify-between text-[11px] font-mono text-neutral-500">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1">
                  <kbd className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[10px]">↑↓</kbd> navigate
                </span>
                <span className="flex items-center gap-1">
                  <kbd className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[10px]">↵</kbd> select
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span>SPIDER Keyboard Navigation</span>
                <Command className="w-3 h-3 text-emerald-400" />
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
