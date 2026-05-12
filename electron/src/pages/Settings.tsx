import { useCallback, useEffect, useState } from 'react';
import { agent, CategoryPolicy, PolicyAction } from '../api/agent';
import { CategoryToggle } from '../components/CategoryToggle';

type FeedbackKind = 'success' | 'error';

interface Feedback {
  kind: FeedbackKind;
  message: string;
}

export function Settings() {
  const [policies, setPolicies] = useState<CategoryPolicy[] | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setPolicies(await agent.getPolicies());
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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

  if (policies === null) {
    return <div className="page">Loading policies…</div>;
  }

  return (
    <div className="page">
      <h2>Categories</h2>
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
            disabled={pending === p.category}
            onChange={(action) => void update(p.category, action)}
          />
        ))}
      </div>
    </div>
  );
}
