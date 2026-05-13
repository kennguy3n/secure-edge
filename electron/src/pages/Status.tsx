import { useCallback, useEffect, useState } from 'react';
import { agent, AgentStatus, Stats } from '../api/agent';
import { StatsCard } from '../components/StatsCard';

interface Snapshot {
  status: AgentStatus | null;
  stats: Stats | null;
  reachable: boolean;
  error?: string;
}

const empty: Snapshot = { status: null, stats: null, reachable: false };

export function Status() {
  const [snap, setSnap] = useState<Snapshot>(empty);
  const [resetting, setResetting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [status, stats] = await Promise.all([
        agent.getStatus(),
        agent.getStats(),
      ]);
      setSnap({ status, stats, reachable: true });
    } catch (err) {
      setSnap((prev) => ({ ...prev, reachable: false, error: String(err) }));
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 5000);
    return () => clearInterval(id);
  }, [load]);

  const reset = useCallback(async () => {
    setResetting(true);
    try {
      await agent.resetStats();
      await load();
    } finally {
      setResetting(false);
    }
  }, [load]);

  return (
    <div className="page">
      <h2>Agent Status</h2>
      <div
        className={`status-banner status-banner-${snap.reachable ? 'ok' : 'error'}`}
        role="status"
        aria-live="polite"
      >
        {snap.reachable && snap.status
          ? `Running · v${snap.status.version} · uptime ${snap.status.uptime}`
          : `Agent unreachable${snap.error ? ` — ${snap.error}` : ''}`}
      </div>

      <h3>Anonymous Counters</h3>
      <p className="page-hint">
        Only running totals are stored. No domains, URLs, IPs, or timestamps are persisted.
      </p>
      <div className="stats-grid" role="list" aria-label="Anonymous counters">
        <StatsCard label="DNS queries" value={snap.stats?.dns_queries_total ?? '—'} />
        <StatsCard label="DNS blocks" value={snap.stats?.dns_blocks_total ?? '—'} />
        <StatsCard label="DLP scans" value={snap.stats?.dlp_scans_total ?? '—'} />
        <StatsCard label="DLP blocks" value={snap.stats?.dlp_blocks_total ?? '—'} />
      </div>
      <button
        type="button"
        className="reset-button"
        onClick={() => void reset()}
        disabled={resetting || !snap.reachable}
        aria-label="Reset all anonymous counters to zero"
      >
        {resetting ? 'Resetting…' : 'Reset Counters'}
      </button>
    </div>
  );
}
