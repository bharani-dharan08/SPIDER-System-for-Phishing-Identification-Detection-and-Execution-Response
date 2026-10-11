import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import {
  TrendingUp,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  History,
  Activity,
  Filter,
  BarChart2,
  Sparkles,
} from 'lucide-react';

export interface ThreatHistoryItem {
  id: string;
  timestamp: string;
  payloadName: string;
  score: number;
  vector: string;
  category: 'Email' | 'QR / Image' | 'Voice / Audio' | 'OAuth / Link';
  isInjection?: boolean;
}

interface ThreatHistoryTimelineProps {
  history: ThreatHistoryItem[];
  onSelectHistoryItem?: (item: ThreatHistoryItem) => void;
  activeId?: string;
}

export const ThreatHistoryTimeline: React.FC<ThreatHistoryTimelineProps> = ({
  history,
  onSelectHistoryItem,
  activeId,
}) => {
  const [filter, setFilter] = useState<'all' | 'critical' | 'elevated' | 'low'>('all');
  const [hoveredPoint, setHoveredPoint] = useState<ThreatHistoryItem | null>(null);

  // Filter history based on selected risk category
  const filteredHistory = history.filter((item) => {
    if (filter === 'critical') return item.score >= 8.0;
    if (filter === 'elevated') return item.score >= 5.0 && item.score < 8.0;
    if (filter === 'low') return item.score < 5.0;
    return true;
  });

  // Derived statistics across the history payload set
  const totalAnalyzed = history.length;
  const avgScore =
    totalAnalyzed > 0
      ? (history.reduce((acc, curr) => acc + curr.score, 0) / totalAnalyzed).toFixed(1)
      : '0.0';
  const criticalCount = history.filter((i) => i.score >= 8.0).length;
  const injectionCount = history.filter((i) => i.isInjection).length;

  // Formatting chart data
  const chartData = filteredHistory.map((item, idx) => ({
    ...item,
    index: idx + 1,
    label: `#${idx + 1} ${item.payloadName.length > 14 ? item.payloadName.slice(0, 14) + '…' : item.payloadName}`,
  }));

  // Custom Recharts Tooltip Component
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data: ThreatHistoryItem = payload[0].payload;
      const isCritical = data.score >= 8.0;
      const isElevated = data.score >= 5.0 && data.score < 8.0;

      return (
        <div className="glass-card rounded-xl p-3.5 border border-white/15 bg-[#080d12]/95 backdrop-blur-md shadow-2xl space-y-2 min-w-[220px]">
          <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2">
            <span className="text-[10px] font-mono text-neutral-400">
              {data.timestamp}
            </span>
            <span
              className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded-full ${
                isCritical
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : isElevated
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              }`}
            >
              {isCritical ? 'CRITICAL' : isElevated ? 'ELEVATED' : 'LOW RISK'}
            </span>
          </div>

          <div>
            <p className="text-xs font-semibold text-neutral-100 font-sans leading-snug">
              {data.payloadName}
            </p>
            <p className="text-[11px] text-neutral-400 font-mono mt-0.5">
              Vector: <span className="text-neutral-200">{data.vector}</span>
            </p>
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] font-mono text-neutral-500">Threat Score</span>
            <div className="flex items-center gap-1.5">
              <span
                className={`text-sm font-mono font-bold ${
                  isCritical
                    ? 'text-rose-400'
                    : isElevated
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {data.score.toFixed(1)}
              </span>
              <span className="text-[10px] font-mono text-neutral-500">/ 10.0</span>
            </div>
          </div>

          {data.isInjection && (
            <div className="mt-1 pt-1.5 border-t border-rose-500/20 flex items-center gap-1.5 text-[10px] text-rose-400 font-mono">
              <Sparkles className="w-3 h-3 text-rose-400 shrink-0" />
              <span>Prompt Injection Vector</span>
            </div>
          )}
        </div>
      );
    }
    return null;
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="glass-card rounded-2xl p-5 border border-white/10 bg-white/[0.02] backdrop-blur-xl relative overflow-hidden space-y-5"
    >
      {/* Background Accent Subtle Glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-emerald-500/3 rounded-full blur-3xl pointer-events-none" />

      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-neutral-900/90 border border-neutral-800 flex items-center justify-center text-emerald-400 shadow-inner">
            <History className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-neutral-100 tracking-tight font-sans">
                Threat History Timeline
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Past 20 Payloads
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5 font-sans">
              Real-time threat score progression and multi-vector telemetry trends
            </p>
          </div>
        </div>

        {/* Filter Buttons */}
        <div className="flex items-center gap-1 bg-neutral-900/80 p-1 rounded-lg border border-neutral-800 text-xs font-mono">
          <button
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
              filter === 'all'
                ? 'bg-neutral-800 text-neutral-100 font-medium shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            All ({totalAnalyzed})
          </button>
          <button
            onClick={() => setFilter('critical')}
            className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
              filter === 'critical'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 font-medium'
                : 'text-neutral-400 hover:text-rose-400'
            }`}
          >
            Critical ({criticalCount})
          </button>
          <button
            onClick={() => setFilter('elevated')}
            className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
              filter === 'elevated'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 font-medium'
                : 'text-neutral-400 hover:text-amber-400'
            }`}
          >
            Elevated
          </button>
          <button
            onClick={() => setFilter('low')}
            className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
              filter === 'low'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-medium'
                : 'text-neutral-400 hover:text-emerald-400'
            }`}
          >
            Low Risk
          </button>
        </div>
      </div>

      {/* Overview Stat Cards Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Activity className="w-3 h-3 text-emerald-400" /> Average Score
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-lg font-mono font-bold text-neutral-100">
              {avgScore}
            </span>
            <span className="text-[10px] font-mono text-neutral-500">/ 10.0</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" /> Critical Incidents
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-lg font-mono font-bold text-rose-400">
              {criticalCount}
            </span>
            <span className="text-[10px] font-mono text-neutral-500">
              ({totalAnalyzed > 0 ? Math.round((criticalCount / totalAnalyzed) * 100) : 0}%)
            </span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" /> Prompt Injections
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-lg font-mono font-bold text-amber-400">
              {injectionCount}
            </span>
            <span className="text-[10px] font-mono text-neutral-500">detected</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <BarChart2 className="w-3 h-3 text-cyan-400" /> Total Payload Log
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-lg font-mono font-bold text-neutral-100">
              {totalAnalyzed}
            </span>
            <span className="text-[10px] font-mono text-neutral-500">payloads</span>
          </div>
        </div>
      </div>

      {/* Main Recharts Area Timeline */}
      <div className="h-64 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={chartData}
            margin={{ top: 12, right: 12, left: -20, bottom: 0 }}
            onMouseMove={(e: any) => {
              if (e && e.activePayload && e.activePayload[0]) {
                setHoveredPoint(e.activePayload[0].payload);
              }
            }}
            onMouseLeave={() => setHoveredPoint(null)}
          >
            <defs>
              <linearGradient id="threatScoreGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.35} />
                <stop offset="50%" stopColor="#f59e0b" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
              </linearGradient>
            </defs>

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#ffffff"
              strokeOpacity={0.05}
              vertical={false}
            />

            <XAxis
              dataKey="index"
              tickLine={false}
              axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
              tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
              tickFormatter={(val) => `P${val}`}
            />

            <YAxis
              domain={[0, 10]}
              ticks={[0, 2, 4, 6, 8, 10]}
              tickLine={false}
              axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
              tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
            />

            <Tooltip content={<CustomTooltip />} />

            {/* Critical Threshold Line (8.0) */}
            <ReferenceLine
              y={8.0}
              stroke="#f43f5e"
              strokeDasharray="4 4"
              strokeOpacity={0.5}
              label={{
                value: 'CRITICAL (8.0)',
                fill: '#f43f5e',
                fontSize: 9,
                fontFamily: 'monospace',
                position: 'insideTopRight',
              }}
            />

            {/* Elevated Risk Threshold Line (5.0) */}
            <ReferenceLine
              y={5.0}
              stroke="#f59e0b"
              strokeDasharray="4 4"
              strokeOpacity={0.3}
              label={{
                value: 'ELEVATED (5.0)',
                fill: '#f59e0b',
                fontSize: 9,
                fontFamily: 'monospace',
                position: 'insideTopRight',
              }}
            />

            <Area
              type="monotone"
              dataKey="score"
              stroke="#10b981"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#threatScoreGrad)"
              activeDot={{
                r: 6,
                fill: '#10b981',
                stroke: '#ffffff',
                strokeWidth: 2,
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Payloads List / Log Table (Past 20 Payloads) */}
      <div className="space-y-2 pt-2 border-t border-white/5">
        <div className="flex items-center justify-between text-xs text-neutral-400 font-mono px-1">
          <span>Payload Log History</span>
          <span className="text-[11px] text-neutral-500">
            Click any entry to view vector details
          </span>
        </div>

        <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin">
          {filteredHistory.map((item) => {
            const isCritical = item.score >= 8.0;
            const isElevated = item.score >= 5.0 && item.score < 8.0;
            const isSelected = activeId === item.id;

            return (
              <div
                key={item.id}
                onClick={() => onSelectHistoryItem?.(item)}
                className={`p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between gap-3 ${
                  isSelected
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-neutral-900/40 border-white/5 hover:border-white/15 hover:bg-neutral-900/80'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      isCritical
                        ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]'
                        : isElevated
                        ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]'
                        : 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]'
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-xs font-medium text-neutral-200 truncate font-sans">
                        {item.payloadName}
                      </p>
                      {item.isInjection && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/15 text-rose-300 font-mono border border-rose-500/20 shrink-0">
                          Injection
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] text-neutral-400 font-mono truncate mt-0.5">
                      {item.category} • {item.vector}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[10px] text-neutral-400 font-mono hidden sm:inline">
                    {item.timestamp}
                  </span>

                  <div className="flex items-center gap-1 min-w-[50px] justify-end">
                    <span
                      className={`text-xs font-mono font-bold ${
                        isCritical
                          ? 'text-rose-400'
                          : isElevated
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {item.score.toFixed(1)}
                    </span>
                    <span className="text-[10px] text-neutral-500 font-mono">/10</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
};
