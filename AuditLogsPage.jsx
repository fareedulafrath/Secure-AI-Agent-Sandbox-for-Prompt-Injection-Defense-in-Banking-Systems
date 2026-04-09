import { useState, useMemo } from 'react';
import { Search, Filter, Download, ChevronLeft, ChevronRight } from 'lucide-react';
import { useThreatStore } from '../lib/store/threatStore';
import { format } from 'date-fns';

const ITEMS_PER_PAGE = 8;

const DECISION_BADGES = {
    ALLOW: 'badge-allow',
    WARN: 'badge-warn',
    BLOCK: 'badge-block',
};

const RISK_BADGES = {
    LOW: 'badge-allow',
    MEDIUM: 'badge-warn',
    HIGH: 'badge-block',
    CRITICAL: 'badge-critical',
};

export default function AuditLogsPage() {
    const { threatLogs } = useThreatStore();
    const [search, setSearch] = useState('');
    const [filter, setFilter] = useState('ALL');
    const [page, setPage] = useState(1);

    const filteredLogs = useMemo(() => {
        let logs = [...threatLogs];

        if (filter !== 'ALL') {
            logs = logs.filter(l => l.decision === filter);
        }

        if (search.trim()) {
            const q = search.toLowerCase();
            logs = logs.filter(l =>
                l.input.toLowerCase().includes(q) ||
                l.patterns.some(p => p.toLowerCase().includes(q))
            );
        }

        return logs;
    }, [threatLogs, filter, search]);

    const totalPages = Math.max(1, Math.ceil(filteredLogs.length / ITEMS_PER_PAGE));
    const paginatedLogs = filteredLogs.slice(
        (page - 1) * ITEMS_PER_PAGE,
        page * ITEMS_PER_PAGE
    );

    const handleExport = () => {
        const csv = [
            ['Timestamp', 'Input', 'Threat Score', 'Risk Level', 'Decision', 'Patterns'].join(','),
            ...filteredLogs.map(l => [
                l.timestamp,
                `"${l.input.replace(/"/g, '""')}"`,
                l.threatScore,
                l.riskLevel,
                l.decision,
                `"${l.patterns.join(', ')}"`,
            ].join(',')),
        ].join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fintrust-audit-logs-${format(new Date(), 'yyyy-MM-dd')}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div style={{ position: 'relative', zIndex: 1 }}>
            <div className="page-header">
                <h1>📄 Audit Logs</h1>
                <p>Complete security audit trail of all scanned inputs and decisions</p>
            </div>

            {/* Summary Badges */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
                <div
                    className="glass-card"
                    style={{
                        padding: '12px 20px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                    }}
                >
                    <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Total Entries:</span>
                    <span style={{ fontWeight: 700, fontSize: '18px' }}>{threatLogs.length}</span>
                </div>
                <div
                    className="glass-card"
                    style={{
                        padding: '12px 20px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                    }}
                >
                    <span style={{ color: 'var(--accent-emerald)', fontSize: '13px' }}>Allowed:</span>
                    <span style={{ fontWeight: 700, fontSize: '18px', color: 'var(--accent-emerald)' }}>
                        {threatLogs.filter(l => l.decision === 'ALLOW').length}
                    </span>
                </div>
                <div
                    className="glass-card"
                    style={{
                        padding: '12px 20px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                    }}
                >
                    <span style={{ color: 'var(--accent-red)', fontSize: '13px' }}>Blocked:</span>
                    <span style={{ fontWeight: 700, fontSize: '18px', color: 'var(--accent-red)' }}>
                        {threatLogs.filter(l => l.decision === 'BLOCK').length}
                    </span>
                </div>
            </div>

            {/* Table */}
            <div className="table-container animate-fade-in-up">
                <div className="table-toolbar">
                    <div className="table-search">
                        <Search size={16} />
                        <input
                            type="text"
                            placeholder="Search logs by input or pattern..."
                            value={search}
                            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                        />
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div className="table-filters">
                            {['ALL', 'ALLOW', 'WARN', 'BLOCK'].map((f) => (
                                <button
                                    key={f}
                                    className={`filter-btn ${filter === f ? 'active' : ''}`}
                                    onClick={() => { setFilter(f); setPage(1); }}
                                >
                                    {f === 'ALL' ? 'All' : f.charAt(0) + f.slice(1).toLowerCase()}
                                </button>
                            ))}
                        </div>
                        <button className="btn btn-ghost btn-sm" onClick={handleExport}>
                            <Download size={14} />
                            Export
                        </button>
                    </div>
                </div>

                <div style={{ overflowX: 'auto' }}>
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Input Prompt</th>
                                <th>Score</th>
                                <th>Risk Level</th>
                                <th>Decision</th>
                                <th>Patterns Detected</th>
                            </tr>
                        </thead>
                        <tbody>
                            {paginatedLogs.length === 0 && (
                                <tr>
                                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                                        No logs found matching your criteria
                                    </td>
                                </tr>
                            )}
                            {paginatedLogs.map((log) => (
                                <tr key={log.id}>
                                    <td style={{ whiteSpace: 'nowrap', fontSize: '12px' }}>
                                        {format(new Date(log.timestamp), 'MMM dd, HH:mm:ss')}
                                    </td>
                                    <td style={{ maxWidth: '250px' }}>
                                        <div
                                            style={{
                                                overflow: 'hidden',
                                                textOverflow: 'ellipsis',
                                                whiteSpace: 'nowrap',
                                            }}
                                            title={log.input}
                                        >
                                            {log.input}
                                        </div>
                                    </td>
                                    <td>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <span style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
                                                {log.threatScore}
                                            </span>
                                            <div className="threat-score-bar" style={{ width: '60px' }}>
                                                <div
                                                    className={`threat-score-fill ${log.threatScore <= 25 ? 'low' :
                                                        log.threatScore <= 50 ? 'medium' :
                                                            log.threatScore <= 75 ? 'high' : 'critical'
                                                        }`}
                                                    style={{ width: `${log.threatScore}%` }}
                                                />
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <span className={`badge ${RISK_BADGES[log.riskLevel]}`}>
                                            {log.riskLevel}
                                        </span>
                                    </td>
                                    <td>
                                        <span className={`badge ${DECISION_BADGES[log.decision]}`}>
                                            {log.decision}
                                        </span>
                                    </td>
                                    <td>
                                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                            {log.patterns.length === 0 && (
                                                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>None</span>
                                            )}
                                            {log.patterns.map((p, i) => (
                                                <span key={i} className="badge badge-info">{p}</span>
                                            ))}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '12px 24px',
                            borderTop: '1px solid var(--border-default)',
                        }}
                    >
                        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                            Showing {(page - 1) * ITEMS_PER_PAGE + 1}–
                            {Math.min(page * ITEMS_PER_PAGE, filteredLogs.length)} of {filteredLogs.length}
                        </span>
                        <div style={{ display: 'flex', gap: '6px' }}>
                            <button
                                className="btn btn-ghost btn-sm"
                                disabled={page <= 1}
                                onClick={() => setPage(p => p - 1)}
                            >
                                <ChevronLeft size={14} />
                            </button>
                            {Array.from({ length: totalPages }, (_, i) => (
                                <button
                                    key={i}
                                    className={`btn btn-sm ${page === i + 1 ? 'btn-primary' : 'btn-ghost'}`}
                                    onClick={() => setPage(i + 1)}
                                    style={{ minWidth: '32px' }}
                                >
                                    {i + 1}
                                </button>
                            ))}
                            <button
                                className="btn btn-ghost btn-sm"
                                disabled={page >= totalPages}
                                onClick={() => setPage(p => p + 1)}
                            >
                                <ChevronRight size={14} />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
