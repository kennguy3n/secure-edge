import { useCallback, useEffect, useState } from 'react';
import {
  agent,
  AgentProfile,
  CategoryPolicy,
  DLPConfig,
  PolicyAction,
  RuleOverrideLists,
} from '../api/agent';
import { CategoryToggle } from '../components/CategoryToggle';

type FeedbackKind = 'success' | 'error';

interface Feedback {
  kind: FeedbackKind;
  message: string;
}

const DLP_KEYS: Array<{ key: keyof DLPConfig; label: string; min: number; max: number }> = [
  { key: 'threshold_critical', label: 'Critical threshold', min: 1, max: 10 },
  { key: 'threshold_high', label: 'High threshold', min: 1, max: 10 },
  { key: 'threshold_medium', label: 'Medium threshold', min: 1, max: 10 },
  { key: 'threshold_low', label: 'Low threshold', min: 1, max: 10 },
  { key: 'hotword_boost', label: 'Hotword boost', min: 0, max: 5 },
  { key: 'entropy_boost', label: 'Entropy boost', min: 0, max: 5 },
  { key: 'entropy_penalty', label: 'Entropy penalty', min: -5, max: 0 },
  { key: 'exclusion_penalty', label: 'Exclusion penalty', min: -5, max: 0 },
  { key: 'multi_match_boost', label: 'Multi-match boost', min: 0, max: 5 },
];

export function Settings() {
  const [policies, setPolicies] = useState<CategoryPolicy[] | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [profile, setProfile] = useState<AgentProfile | null>(null);
  const [dlp, setDLP] = useState<DLPConfig | null>(null);
  const [overrides, setOverrides] = useState<RuleOverrideLists | null>(null);
  const [overrideDomain, setOverrideDomain] = useState('');
  const [overrideList, setOverrideList] = useState<'allow' | 'block'>('block');

  const load = useCallback(async () => {
    try {
      const [p, prof, cfg, ov] = await Promise.all([
        agent.getPolicies(),
        agent.getProfile().catch(() => null),
        agent.getDLPConfig().catch(() => null),
        agent.listOverrides().catch(() => null),
      ]);
      setPolicies(p);
      setProfile(prof);
      setDLP(cfg);
      setOverrides(ov);
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const locked = profile?.managed ?? false;

  const update = useCallback(
    async (category: string, action: PolicyAction) => {
      setPending(category);
      try {
        const updated = await agent.updatePolicy(category, action);
        setPolicies((prev) =>
          prev ? prev.map((p) => (p.category === category ? updated : p)) : prev,
        );
        setFeedback({ kind: 'success', message: `Saved: ${category}` });
      } catch (err) {
        setFeedback({ kind: 'error', message: String(err) });
      } finally {
        setPending(null);
      }
    },
    [],
  );

  const updateDLPField = useCallback(
    async (key: keyof DLPConfig, value: number) => {
      if (!dlp) return;
      const next: DLPConfig = { ...dlp, [key]: value };
      setDLP(next);
      try {
        const saved = await agent.updateDLPConfig(next);
        setDLP(saved);
        setFeedback({ kind: 'success', message: `Saved DLP ${key}` });
      } catch (err) {
        setFeedback({ kind: 'error', message: String(err) });
      }
    },
    [dlp],
  );

  const addOverride = useCallback(async () => {
    const domain = overrideDomain.trim();
    if (!domain) return;
    try {
      const next = await agent.addOverride(domain, overrideList);
      setOverrides(next);
      setOverrideDomain('');
      setFeedback({ kind: 'success', message: `Added ${domain} to ${overrideList}` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, [overrideDomain, overrideList]);

  const removeOverride = useCallback(async (domain: string) => {
    try {
      const next = await agent.removeOverride(domain);
      setOverrides(next);
      setFeedback({ kind: 'success', message: `Removed ${domain}` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  if (policies === null) {
    return <div className="page">Loading policies…</div>;
  }

  return (
    <div className="page">
      <h2>Categories</h2>
      {locked && (
        <div className="feedback feedback-error">
          Policies are managed by enterprise profile <strong>{profile?.name}</strong>.
          Local changes are disabled.
        </div>
      )}
      <p className="page-hint">
        Choose which traffic categories are allowed or blocked at the DNS layer.
      </p>
      {feedback && (
        <div className={`feedback feedback-${feedback.kind}`}>{feedback.message}</div>
      )}
      <div className="category-list">
        {policies.map((p) => (
          <CategoryToggle
            key={p.category}
            policy={p}
            disabled={locked || pending === p.category}
            onChange={(action) => void update(p.category, action)}
          />
        ))}
      </div>

      {dlp && (
        <section className="dlp-section">
          <h2>DLP Scoring</h2>
          <p className="page-hint">
            Tune how aggressively the DLP pipeline classifies leaks. Higher
            thresholds make the agent stricter; boosts increase a match's
            score, penalties reduce it.
          </p>
          <div className="dlp-grid">
            {DLP_KEYS.map(({ key, label, min, max }) => (
              <label className="dlp-row" key={key}>
                <span>{label}</span>
                <input
                  type="range"
                  min={min}
                  max={max}
                  value={dlp[key]}
                  disabled={locked}
                  onChange={(e) => void updateDLPField(key, Number(e.target.value))}
                />
                <span className="dlp-value">{dlp[key]}</span>
              </label>
            ))}
          </div>
        </section>
      )}

      {overrides && (
        <section className="override-section">
          <h2>Admin Overrides</h2>
          <p className="page-hint">
            Allow or block individual domains regardless of category rules.
            Overrides live in <code>rules/local/</code> and survive bundled
            rule updates.
          </p>
          <div className="override-add">
            <input
              type="text"
              placeholder="example.com"
              value={overrideDomain}
              onChange={(e) => setOverrideDomain(e.target.value)}
              disabled={locked}
            />
            <select
              value={overrideList}
              disabled={locked}
              onChange={(e) => setOverrideList(e.target.value as 'allow' | 'block')}
            >
              <option value="allow">Allow</option>
              <option value="block">Block</option>
            </select>
            <button type="button" disabled={locked} onClick={() => void addOverride()}>
              Add
            </button>
          </div>

          <div className="override-lists">
            <div>
              <h3>Allow ({overrides.allow.length})</h3>
              <ul>
                {overrides.allow.map((d) => (
                  <li key={`a-${d}`}>
                    <code>{d}</code>
                    <button
                      type="button"
                      disabled={locked}
                      onClick={() => void removeOverride(d)}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Block ({overrides.block.length})</h3>
              <ul>
                {overrides.block.map((d) => (
                  <li key={`b-${d}`}>
                    <code>{d}</code>
                    <button
                      type="button"
                      disabled={locked}
                      onClick={() => void removeOverride(d)}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
