import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldAlert, AlertTriangle, CheckCircle2, Info, X, FileUp } from 'lucide-react';

export interface ToastMessage {
  id: string;
  title: string;
  description?: string;
  type: 'success' | 'critical' | 'warning' | 'info';
  duration?: number;
}

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  return (
    <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none px-4 sm:px-0">
      <AnimatePresence>
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  );
};

const ToastItem: React.FC<{ toast: ToastMessage; onDismiss: (id: string) => void }> = ({
  toast,
  onDismiss,
}) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onDismiss(toast.id);
    }, toast.duration || 5000);

    return () => clearTimeout(timer);
  }, [toast, onDismiss]);

  const getStyle = () => {
    switch (toast.type) {
      case 'critical':
        return {
          card: 'bg-[#0E0709]/95 border-rose-500/40 text-rose-100 shadow-[0_0_25px_rgba(244,63,94,0.15)]',
          icon: <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />,
          badge: 'bg-rose-500/20 text-rose-400 border border-rose-500/30',
          badgeText: 'CRITICAL THREAT',
        };
      case 'warning':
        return {
          card: 'bg-[#0E0C07]/95 border-amber-500/40 text-amber-100 shadow-[0_0_25px_rgba(245,158,11,0.15)]',
          icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
          badge: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
          badgeText: 'WARNING',
        };
      case 'success':
        return {
          card: 'bg-[#070D09]/95 border-emerald-500/40 text-emerald-100 shadow-[0_0_25px_rgba(16,185,129,0.12)]',
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />,
          badge: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
          badgeText: 'INGESTED',
        };
      case 'info':
      default:
        return {
          card: 'bg-[#0A0A0A]/95 border-neutral-700/80 text-neutral-100 shadow-xl',
          icon: <FileUp className="w-4 h-4 text-neutral-300 shrink-0" />,
          badge: 'bg-neutral-800 text-neutral-300 border border-neutral-700',
          badgeText: 'SYSTEM',
        };
    }
  };

  const style = getStyle();

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 10, scale: 0.95 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      className={`pointer-events-auto rounded-xl p-3.5 border backdrop-blur-md flex items-start gap-3 shadow-2xl relative overflow-hidden font-sans ${style.card}`}
    >
      <div className="pt-0.5">{style.icon}</div>

      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <span className={`text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded ${style.badge}`}>
            {style.badgeText}
          </span>
          <span className="text-[10px] font-mono text-neutral-400">
            {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>

        <h4 className="text-xs font-semibold tracking-tight leading-snug">{toast.title}</h4>

        {toast.description && (
          <p className="text-[11px] text-neutral-300 leading-relaxed font-mono opacity-90 line-clamp-2">
            {toast.description}
          </p>
        )}
      </div>

      <button
        onClick={() => onDismiss(toast.id)}
        className="text-neutral-400 hover:text-white p-1 rounded-md hover:bg-white/10 transition cursor-pointer shrink-0"
        aria-label="Close notification"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </motion.div>
  );
};
