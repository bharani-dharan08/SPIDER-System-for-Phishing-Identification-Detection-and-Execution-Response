import React, { useState } from 'react';
import { motion } from 'motion/react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  ScatterChart,
  Scatter,
  ZAxis,
  PieChart,
  Pie,
} from 'recharts';
import {
  Globe,
  MapPin,
  ShieldAlert,
  Server,
  Radio,
  ExternalLink,
  Cpu,
  Layers,
  Zap,
} from 'lucide-react';
import { FusedPayload } from '../types';

export interface GeoThreatNode {
  id: string;
  country: string;
  countryCode: string;
  region: string;
  lat: number;
  lng: number;
  ip: string;
  asn: string;
  count: number;
  avgScore: number;
  isTorOrProxy: boolean;
  primaryVector: string;
}

const GEOGRAPHIC_THREAT_DATA: GeoThreatNode[] = [
  {
    id: 'geo-1',
    country: 'Romania',
    countryCode: 'RO',
    region: 'Eastern Europe',
    lat: 44.4323,
    lng: 26.1063,
    ip: '185.220.101.42',
    asn: 'AS208046 (M247 Ltd)',
    count: 38,
    avgScore: 9.1,
    isTorOrProxy: true,
    primaryVector: 'AiTM Reverse-Proxy / BEC',
  },
  {
    id: 'geo-2',
    country: 'Russia',
    countryCode: 'RU',
    region: 'Eastern Europe',
    lat: 55.7558,
    lng: 37.6173,
    ip: '194.26.29.112',
    asn: 'AS44050 (Petersburg Internet)',
    count: 45,
    avgScore: 9.4,
    isTorOrProxy: true,
    primaryVector: 'Bulletproof Hosting / PhishKit',
  },
  {
    id: 'geo-3',
    country: 'United States',
    countryCode: 'US',
    region: 'North America',
    lat: 37.7749,
    lng: -122.4194,
    ip: '104.28.18.22',
    asn: 'AS13335 (Cloudflare Inc)',
    count: 62,
    avgScore: 6.2,
    isTorOrProxy: false,
    primaryVector: 'Cloud Service Abuse / OAuth',
  },
  {
    id: 'geo-4',
    country: 'Netherlands',
    countryCode: 'NL',
    region: 'Western Europe',
    lat: 52.3676,
    lng: 4.9041,
    ip: '185.220.102.8',
    asn: 'AS60729 (C2 Server Infrastructure)',
    count: 29,
    avgScore: 8.7,
    isTorOrProxy: true,
    primaryVector: 'Synthetic Voice / Deepfake C2',
  },
  {
    id: 'geo-5',
    country: 'China',
    countryCode: 'CN',
    region: 'East Asia',
    lat: 31.2304,
    lng: 121.4737,
    ip: '118.193.22.40',
    asn: 'AS4134 (CHINANET-BACKBONE)',
    count: 31,
    avgScore: 8.9,
    isTorOrProxy: false,
    primaryVector: 'Typosquatting & QR Barcode',
  },
  {
    id: 'geo-6',
    country: 'Nigeria',
    countryCode: 'NG',
    region: 'West Africa',
    lat: 6.5244,
    lng: 3.3792,
    ip: '102.89.23.11',
    asn: 'AS36873 (Globacom Limited)',
    count: 24,
    avgScore: 8.5,
    isTorOrProxy: false,
    primaryVector: 'Whaling / Wire Transfer BEC',
  },
  {
    id: 'geo-7',
    country: 'Brazil',
    countryCode: 'BR',
    region: 'South America',
    lat: -23.5505,
    lng: -46.6333,
    ip: '177.12.98.50',
    asn: 'AS28573 (CLARO S.A.)',
    count: 18,
    avgScore: 7.1,
    isTorOrProxy: true,
    primaryVector: 'Credential Harvesting Page',
  },
  {
    id: 'geo-8',
    country: 'Germany',
    countryCode: 'DE',
    region: 'Western Europe',
    lat: 50.1109,
    lng: 8.6821,
    ip: '159.69.45.19',
    asn: 'AS24940 (Hetzner Online)',
    count: 22,
    avgScore: 5.4,
    isTorOrProxy: false,
    primaryVector: 'Low Risk Automated Scanner',
  },
  {
    id: 'geo-9',
    country: 'Vietnam',
    countryCode: 'VN',
    region: 'Southeast Asia',
    lat: 10.8231,
    lng: 106.6297,
    ip: '113.161.4.92',
    asn: 'AS7552 (Vietel Corporation)',
    count: 15,
    avgScore: 7.8,
    isTorOrProxy: true,
    primaryVector: 'Social Engineering Consent',
  },
];

const PROXY_DISTRIBUTION_DATA = [
  { name: 'Tor Exit Nodes', value: 38, color: '#f43f5e' },
  { name: 'Bulletproof Hosting', value: 27, color: '#fb923c' },
  { name: 'Residential Proxies', value: 18, color: '#f59e0b' },
  { name: 'Commercial VPNs', value: 12, color: '#38bdf8' },
  { name: 'Direct Autonomous Systems', value: 5, color: '#10b981' },
];

interface ThreatHeatmapProps {
  fused: FusedPayload;
}

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({ fused }) => {
  const [activeTab, setActiveTab] = useState<'spatial' | 'ranking' | 'anonymity'>('spatial');
  const [selectedNode, setSelectedNode] = useState<GeoThreatNode | null>(GEOGRAPHIC_THREAT_DATA[0]);

  // Extract simulated current origin from fused metadata
  const currentIp =
    fused.header_metadata?.['Reply-To'] ||
    fused.header_metadata?.From ||
    '185.220.101.42 (Romania)';

  // Prepare Scatter dataset for Spatial Coordinate Map (X: Longitude -180..180, Y: Latitude -90..90)
  const scatterData = GEOGRAPHIC_THREAT_DATA.map((node) => ({
    x: node.lng,
    y: node.lat,
    z: node.count,
    name: `${node.country} (${node.countryCode})`,
    node,
  }));

  // Country Bar chart data sorted by count
  const countryData = [...GEOGRAPHIC_THREAT_DATA].sort((a, b) => b.count - a.count);

  // Custom Scatter Tooltip
  const ScatterTooltipContent = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data: GeoThreatNode = payload[0].payload.node;
      const isCritical = data.avgScore >= 8.5;

      return (
        <div className="glass-card rounded-xl p-3 border border-white/15 bg-[#080d12]/95 backdrop-blur-md shadow-2xl space-y-1.5 min-w-[200px]">
          <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1.5">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold text-neutral-100">{data.country}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-neutral-800 text-neutral-300">
                {data.countryCode}
              </span>
            </div>
            <span
              className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded-full ${
                isCritical
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              }`}
            >
              Score {data.avgScore.toFixed(1)}
            </span>
          </div>

          <div className="text-[11px] font-mono space-y-1 text-neutral-300">
            <p className="flex justify-between">
              <span className="text-neutral-500">IP Origin:</span>
              <span className="text-neutral-200">{data.ip}</span>
            </p>
            <p className="flex justify-between">
              <span className="text-neutral-500">ASN:</span>
              <span className="text-neutral-200 truncate max-w-[120px]">{data.asn}</span>
            </p>
            <p className="flex justify-between">
              <span className="text-neutral-500">Incidents:</span>
              <span className="text-emerald-400 font-bold">{data.count} payloads</span>
            </p>
          </div>

          <div className="pt-1 border-t border-white/5 text-[10px] font-mono text-neutral-400">
            Vector: <span className="text-neutral-200">{data.primaryVector}</span>
          </div>
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
      {/* Background Soft Glow */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-cyan-500/3 rounded-full blur-3xl pointer-events-none" />

      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-neutral-900/90 border border-neutral-800 flex items-center justify-center text-cyan-400 shadow-inner">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-neutral-100 tracking-tight font-sans">
                Geographical Threat Heatmap
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                IP Spatial Intelligence
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5 font-sans">
              Geographical node distribution, Tor exit relays, and Autonomous System (ASN) clustering
            </p>
          </div>
        </div>

        {/* View Tabs */}
        <div className="flex items-center gap-1 bg-neutral-900/80 p-1 rounded-lg border border-neutral-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('spatial')}
            className={`px-3 py-1 rounded-md transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'spatial'
                ? 'bg-neutral-800 text-neutral-100 font-medium shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <MapPin className="w-3 h-3 text-cyan-400" />
            Spatial Grid
          </button>
          <button
            onClick={() => setActiveTab('ranking')}
            className={`px-3 py-1 rounded-md transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'ranking'
                ? 'bg-neutral-800 text-neutral-100 font-medium shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <Layers className="w-3 h-3 text-emerald-400" />
            Country Ranking
          </button>
          <button
            onClick={() => setActiveTab('anonymity')}
            className={`px-3 py-1 rounded-md transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'anonymity'
                ? 'bg-neutral-800 text-neutral-100 font-medium shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <Radio className="w-3 h-3 text-rose-400" />
            Proxy / Tor Relay
          </button>
        </div>
      </div>

      {/* Top Telemetry Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Globe className="w-3 h-3 text-rose-400" /> Highest Risk Node
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-mono font-bold text-neutral-100">
              Russia (RU)
            </span>
            <span className="text-[10px] font-mono text-rose-400 font-bold">9.4/10</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Server className="w-3 h-3 text-amber-400" /> Top Flagged ASN
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-mono font-bold text-neutral-100 truncate">
              AS208046
            </span>
            <span className="text-[10px] font-mono text-neutral-500">M247 Ltd</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Radio className="w-3 h-3 text-rose-400" /> Anonymized Relays
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-mono font-bold text-rose-400">65.5%</span>
            <span className="text-[10px] font-mono text-neutral-500">Tor / Proxies</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-neutral-900/60 border border-white/5 space-y-1">
          <span className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
            <Zap className="w-3 h-3 text-cyan-400" /> Current Payload Hop
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-xs font-mono font-semibold text-emerald-400 truncate">
              185.220.101.42
            </span>
            <span className="text-[10px] font-mono text-neutral-500">RO</span>
          </div>
        </div>
      </div>

      {/* Main Visualizations Container */}
      <div className="h-72 w-full pt-2">
        {activeTab === 'spatial' && (
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: 10 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#ffffff"
                strokeOpacity={0.05}
              />
              <XAxis
                type="number"
                dataKey="x"
                name="Longitude"
                domain={[-180, 180]}
                unit="°"
                tickLine={false}
                axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
                tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
              />
              <YAxis
                type="number"
                dataKey="y"
                name="Latitude"
                domain={[-90, 90]}
                unit="°"
                tickLine={false}
                axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
                tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
              />
              <ZAxis type="number" dataKey="z" range={[100, 600]} name="Payloads" />
              <Tooltip content={<ScatterTooltipContent />} />
              <Scatter
                data={scatterData}
                onClick={(entry: any) => setSelectedNode(entry.node)}
                cursor="pointer"
              >
                {scatterData.map((entry, index) => {
                  const score = entry.node.avgScore;
                  const fill =
                    score >= 9.0
                      ? '#f43f5e'
                      : score >= 8.0
                      ? '#fb923c'
                      : score >= 6.5
                      ? '#f59e0b'
                      : '#10b981';

                  return (
                    <Cell
                      key={`cell-${index}`}
                      fill={fill}
                      stroke="#ffffff"
                      strokeWidth={1.5}
                      opacity={0.85}
                    />
                  );
                })}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        )}

        {activeTab === 'ranking' && (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={countryData}
              margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff" strokeOpacity={0.05} />
              <XAxis
                type="number"
                tickLine={false}
                axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
                tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
              />
              <YAxis
                dataKey="countryCode"
                type="category"
                tickLine={false}
                axisLine={{ stroke: '#ffffff', strokeOpacity: 0.1 }}
                tick={{ fill: '#d4d4d4', fontSize: 11, fontFamily: 'monospace' }}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data: GeoThreatNode = payload[0].payload;
                    return (
                      <div className="glass-card rounded-lg p-2.5 border border-white/15 bg-[#080d12]/95 backdrop-blur-md text-xs font-mono space-y-1">
                        <p className="font-bold text-neutral-100">{data.country}</p>
                        <p className="text-neutral-400">Total Inbound: <span className="text-emerald-400 font-bold">{data.count}</span></p>
                        <p className="text-neutral-400">Avg Threat Score: <span className="text-rose-400 font-bold">{data.avgScore}/10</span></p>
                        <p className="text-neutral-400">ASN: {data.asn}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {countryData.map((entry, index) => {
                  const fill =
                    entry.avgScore >= 8.8
                      ? '#f43f5e'
                      : entry.avgScore >= 7.5
                      ? '#f59e0b'
                      : '#10b981';
                  return <Cell key={`bar-${index}`} fill={fill} opacity={0.85} />;
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}

        {activeTab === 'anonymity' && (
          <div className="h-full flex flex-col sm:flex-row items-center justify-around gap-4">
            <div className="w-full sm:w-1/2 h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={PROXY_DISTRIBUTION_DATA}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={85}
                    paddingAngle={3}
                  >
                    {PROXY_DISTRIBUTION_DATA.map((entry, index) => (
                      <Cell key={`pie-${index}`} fill={entry.color} stroke="#020406" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="glass-card rounded-lg p-2 border border-white/15 bg-[#080d12]/95 backdrop-blur-md text-xs font-mono">
                            <span className="font-bold text-neutral-100">{data.name}: </span>
                            <span className="text-emerald-400">{data.value}%</span>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="w-full sm:w-1/2 space-y-2 font-mono text-xs">
              <span className="text-[10px] text-neutral-500 uppercase tracking-wider block">
                Relay Anonymization Vector Breakdown
              </span>
              {PROXY_DISTRIBUTION_DATA.map((item) => (
                <div
                  key={item.name}
                  className="flex items-center justify-between p-2 rounded-lg bg-neutral-900/50 border border-white/5"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-neutral-300">{item.name}</span>
                  </div>
                  <span className="text-neutral-100 font-bold">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Node Details Inspection Footer */}
      {selectedNode && (
        <div className="pt-3 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-300 font-bold">
              {selectedNode.country} ({selectedNode.countryCode})
            </div>
            <span className="text-neutral-400">
              IP: <span className="text-neutral-200">{selectedNode.ip}</span>
            </span>
            <span className="text-neutral-400 hidden md:inline">
              ASN: <span className="text-neutral-200">{selectedNode.asn}</span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-neutral-400">
              Avg Threat Score:{' '}
              <span
                className={`font-bold ${
                  selectedNode.avgScore >= 8.5
                    ? 'text-rose-400'
                    : 'text-amber-400'
                }`}
              >
                {selectedNode.avgScore.toFixed(1)}/10
              </span>
            </span>
            {selectedNode.isTorOrProxy && (
              <span className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[10px]">
                TOR / PROXY RELAY
              </span>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
};
