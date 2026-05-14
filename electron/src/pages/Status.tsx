import { useCallback, useEffect, useRef, useState } from 'react';
import { agent, AgentStatus, Stats } from '../api/agent';
import { StatsCard } from '../components/StatsCard';

interface Snapshot {
  status: AgentStatus | null;
  stats: Stats | null;
  reachable: boolean;
  error?: string;
}

// NotificationEntry is the in-memory block-notification record.
// Kept ephemeral on purpose (Phase 6 Task 22): nothing persists,
// nothing reaches localStorage / SQLite, and the list is cleared the
// moment the renderer process exits.
interface NotificationEntry {
  id: number;
  at: string; // ISO timestamp, formatted for display only
  delta: number; // dlp_blocks_total increment observed in this poll
}

const empty: Snapshot = { status: null, stats: null, reachable: false };
const NOTIFICATION_CAP = 10;

export function Status() {
  const [snap, setSnap] = useState<Snapshot>(empty);
  const [resetting, setResetting] = useState(false);
  const [notifs, setNotifs] = useState<NotificationEntry[]>([]);
  const seqRef = useRef(0);
  const lastBlocksRef = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const [status, stats] = await Promise.all([
        agent.getStatus(),
        agent.getStats(),
      ]);
      // Diff the DLP block counter against the last observation so a
      // bump becomes a single in-memory notification entry. We use
      // a Ref instead of derived state so concurrent polls don't
      // accidentally double-count.
      const current = stats.dlp_blocks_total;
      const previous = lastBlocksRef.current;
      lastBlocksRef.current = current;
      if (previous !== null && current > previous) {
        const delta = current - previous;
        setNotifs((prev) => {
          const next: NotificationEntry = {
            id: ++seqRef.current,
            at: new Date().toLocaleTimeString(),
            delta,
          };
          return [next, ...prev].slice(0, NOTIFICATION_CAP);
        });
      }
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
          ? `Running · v${snap.status.version} · uptime ${snap.status.uptime} · enforcement ${snap.status.enforcement_mode ?? 'personal'}`
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

      <h3 style={{ marginTop: 24 }}>Recent blocks</h3>
      <p className="page-hint">
        Last {NOTIFICATION_CAP} DLP blocks observed in this session. The list is held
        in memory only — it disappears when this window closes and is
        never written to disk.
      </p>
      {notifs.length === 0 ? (
        <p className="page-hint">No blocks observed since the app started.</p>
      ) : (
        <ul className="category-list" aria-label="Recent DLP block events">
          {notifs.map((n) => (
            <li key={n.id} className="category-row">
              <span className="category-name">
                {n.delta} block{n.delta === 1 ? '' : 's'}
              </span>
              <span className="page-hint">{n.at}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
