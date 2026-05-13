import { useEffect, useState } from 'react';
import { agent, AgentStatus, RulesStatus } from '../api/agent';

interface State {
  status: AgentStatus | null;
  rules: RulesStatus | null;
  loading: boolean;
  error?: string;
}

const initial: State = { status: null, rules: null, loading: true };

/** Read-only rules viewer (Phase 6 Task 20).
 *
 *  Surfaces three pieces of state the agent already exposes through
 *  the /api/status and /api/rules/status endpoints:
 *  - the current downloaded rule manifest version,
 *  - the count of DLP patterns currently loaded into the live
 *    pipeline,
 *  - the rule file paths and their on-disk mtimes.
 *
 *  Patterns themselves (the regular expressions) are intentionally
 *  NOT shown. The agent does not surface them through its API and
 *  doing so would let an attacker inspect what the local agent is
 *  checking for. The page is read-only — there is no mutate-state
 *  action available — so it can be safely shown to non-admin users.
 */
export function Rules() {
  const [state, setState] = useState<State>(initial);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [status, rules] = await Promise.all([
          agent.getStatus(),
          agent.getRulesStatus(),
        ]);
        if (!cancelled) setState({ status, rules, loading: false });
      } catch (err) {
        if (!cancelled) {
          setState({ status: null, rules: null, loading: false, error: String(err) });
        }
      }
    };
    void load();
    const id = setInterval(() => void load(), 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (state.loading) {
    return (
      <div className="page">
        <h2>Rules</h2>
        <p className="page-hint">Loading…</p>
      </div>
    );
  }

  if (state.error) {
    return (
      <div className="page">
        <h2>Rules</h2>
        <p className="page-hint" role="alert">
          Could not reach the agent: {state.error}
        </p>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>Rules</h2>
      <p className="page-hint">
        Read-only view of the active rule manifest and on-disk rule files.
        Pattern bodies are not displayed.
      </p>

      <div className="stats-grid">
        <div className="stats-card">
          <div className="stats-card-value">{state.rules?.current_version ?? 'n/a'}</div>
          <div className="stats-card-label">Rule manifest version</div>
        </div>
        <div className="stats-card">
          <div className="stats-card-value">{state.status?.dlp_patterns ?? '—'}</div>
          <div className="stats-card-label">DLP patterns loaded</div>
        </div>
      </div>

      <h3>Rule files</h3>
      {(state.status?.rules ?? []).length === 0 ? (
        <p className="page-hint">No rule files reported by the agent.</p>
      ) : (
        <ul className="category-list" aria-label="Rule files on disk">
          {(state.status?.rules ?? []).map((f) => (
            <li key={f.path} className="category-row">
              <span className="category-name">{f.path}</span>
              <span className="page-hint">
                {(f.size_bytes / 1024).toFixed(1)} KiB · {new Date(f.last_modified).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
