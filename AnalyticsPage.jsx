import {
    ScanSearch,
    AlertTriangle,
    ShieldCheck,
    Activity,
    TrendingUp,
    TrendingDown,
} from 'lucide-react';
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    LineChart,
    Line,
    Area,
    AreaChart,
    Legend,
} from 'recharts';
import { useThreatStore } from '../lib/store/threatStore';

const PIE_COLORS = ['#10b981', '#f59e0b', '#ef4444', '#f43f5e'];

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div
            style={{
                background: 'rgba(10, 15, 30, 0.95)',
                border: '1px solid rgba(148, 163, 184, 0.2)',
                borderRadius: '12px',
                padding: '12px 16px',
                backdropFilter: 'blur(12px)',
            }}
        >
            <p style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '4px' }}>{label}</p>
            {payload.map((entry, i) => (
                <p key={i} style={{ color: entry.color, fontSize: '14px', fontWeight: 600 }}>
                    {entry.name}: {entry.value}
                </p>
            ))}
        </div>
    );
};

export default function AnalyticsPage() {
    const { threatLogs, analytics } = useThreatStore();

    // Compute attack category distribution
    const categoryMap = {};
    threatLogs.forEach((log) => {
        if (log.patterns && log.patterns.length > 0) {
            log.patterns.forEach((p) => {
                categoryMap[p] = (categoryMap[p] || 0) + 1;
            });
        }
    });
    const categoryData = Object.entries(categoryMap).map(([name, count]) => ({
        name: name.length > 18 ? name.substring(0, 16) + '...' : name,
        fullName: name,
        count,
    }));

    // Risk distribution
    const riskDist = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    threatLogs.forEach((log) => {
        riskDist[log.riskLevel] = (riskDist[log.riskLevel] || 0) + 1;
    });
    const riskData = [
        { name: 'Low', value: riskDist.LOW, color: '#10b981' },
        { name: 'Medium', value: riskDist.MEDIUM, color: '#f59e0b' },
        { name: 'High', value: riskDist.HIGH, color: '#ef4444' },
        { name: 'Critical', value: riskDist.CRITICAL, color: '#f43f5e' },
    ].filter(d => d.value > 0);

    // Time-series (last 7 days)
    const timeData = [];
    for (let i = 6; i >= 0; i--) {
        const date = new Date(Date.now() - i * 86400000);
        const dayStr = date.toLocaleDateString('en-US', { weekday: 'short' });
        const dayStart = new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
        const dayEnd = dayStart + 86400000;
        const dayLogs = threatLogs.filter(l => {
            const t = new Date(l.timestamp).getTime();
            return t >= dayStart && t < dayEnd;
        });
        timeData.push({
            name: dayStr,
            scans: dayLogs.length,
            threats: dayLogs.filter(l => l.decision !== 'ALLOW').length,
            blocked: dayLogs.filter(l => l.decision === 'BLOCK').length,
        });
    }

    // Decision distribution
    const decData = [
        { name: 'Allowed', count: threatLogs.filter(l => l.decision === 'ALLOW').length },
        { name: 'Warned', count: threatLogs.filter(l => l.decision === 'WARN').length },
        { name: 'Blocked', count: threatLogs.filter(l => l.decision === 'BLOCK').length },
    ];

    const metrics = [
        {
            label: 'Total Scans',
            value: analytics.totalScans,
            icon: ScanSearch,
            colorClass: 'cyan',
            trend: '+12%',
            trendDir: 'up',
        },
        {
            label: 'Threats Detected',
            value: analytics.threatsDetected,
            icon: AlertTriangle,
            colorClass: 'amber',
            trend: '+8%',
            trendDir: 'up',
        },
        {
            label: 'Threats Blocked',
            value: analytics.threatsBlocked,
            icon: ShieldCheck,
            colorClass: 'emerald',
            trend: '100%',
            trendDir: 'down',
        },
        {
            label: 'Avg Risk Score',
            value: analytics.avgRiskScore,
            icon: Activity,
            colorClass: 'red',
            trend: '-3%',
            trendDir: 'down',
        },
    ];

    return (
        <div style={{ position: 'relative', zIndex: 1 }}>
            <div className="page-header">
                <h1>📊 Threat Analytics</h1>
                <p>Real-time security insights and threat intelligence dashboard</p>
            </div>

            {/* Metric Cards */}
            <div className="metrics-grid">
                {metrics.map((m, i) => {
                    const Icon = m.icon;
                    return (
                        <div
                            key={m.label}
                            className={`metric-card animate-fade-in-up stagger-${i + 1}`}
                        >
                            <div className={`metric-icon ${m.colorClass}`}>
                                <Icon size={22} />
                            </div>
                            <div className="metric-info">
                                <div className="metric-label">{m.label}</div>
                                <div className="metric-value">{m.value}</div>
                                <div className={`metric-trend ${m.trendDir}`}>
                                    {m.trendDir === 'up' ? (
                                        <TrendingUp size={12} />
                                    ) : (
                                        <TrendingDown size={12} />
                                    )}
                                    {m.trend}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Charts Row */}
            <div className="charts-grid">
                {/* Threat Activity Over Time */}
                <div className="chart-card">
                    <div className="chart-header">
                        <span className="chart-title">Threat Activity (Last 7 Days)</span>
                    </div>
                    <ResponsiveContainer width="100%" height={280}>
                        <AreaChart data={timeData}>
                            <defs>
                                <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                            <YAxis stroke="#64748b" fontSize={12} />
                            <Tooltip content={<CustomTooltip />} />
                            <Legend />
                            <Area
                                type="monotone"
                                dataKey="scans"
                                stroke="#06b6d4"
                                fill="url(#colorScans)"
                                strokeWidth={2}
                                name="Scans"
                            />
                            <Area
                                type="monotone"
                                dataKey="threats"
                                stroke="#ef4444"
                                fill="url(#colorThreats)"
                                strokeWidth={2}
                                name="Threats"
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* Risk Distribution */}
                <div className="chart-card">
                    <div className="chart-header">
                        <span className="chart-title">Risk Distribution</span>
                    </div>
                    <ResponsiveContainer width="100%" height={280}>
                        <PieChart>
                            <Pie
                                data={riskData}
                                cx="50%"
                                cy="50%"
                                outerRadius={100}
                                innerRadius={55}
                                dataKey="value"
                                label={({ name, value }) => `${name}: ${value}`}
                                labelLine={false}
                            >
                                {riskData.map((entry, index) => (
                                    <Cell key={index} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip content={<CustomTooltip />} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Bottom Charts */}
            <div className="charts-grid" style={{ marginTop: '24px' }}>
                {/* Attack Categories */}
                <div className="chart-card">
                    <div className="chart-header">
                        <span className="chart-title">Attack Categories</span>
                    </div>
                    <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={categoryData} layout="vertical">
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis type="number" stroke="#64748b" fontSize={12} />
                            <YAxis
                                type="category"
                                dataKey="name"
                                stroke="#64748b"
                                fontSize={11}
                                width={140}
                            />
                            <Tooltip content={<CustomTooltip />} />
                            <Bar
                                dataKey="count"
                                fill="#8b5cf6"
                                radius={[0, 6, 6, 0]}
                                name="Attacks"
                            />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Decision Distribution */}
                <div className="chart-card">
                    <div className="chart-header">
                        <span className="chart-title">Decision Distribution</span>
                    </div>
                    <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={decData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                            <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                            <YAxis stroke="#64748b" fontSize={12} />
                            <Tooltip content={<CustomTooltip />} />
                            <Bar dataKey="count" radius={[6, 6, 0, 0]} name="Decisions">
                                <Cell fill="#10b981" />
                                <Cell fill="#f59e0b" />
                                <Cell fill="#ef4444" />
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        </div>
    );
}
