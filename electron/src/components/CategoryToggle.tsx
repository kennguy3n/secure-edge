import type { CategoryPolicy, PolicyAction } from '../api/agent';

interface Props {
  policy: CategoryPolicy;
  disabled?: boolean;
  onChange: (action: PolicyAction) => void;
}

// Phase 1: two-state toggle (Allow / Block). The "allow_with_dlp" state
// is preserved when present but rendered as a non-interactive badge —
// three-state UI lands in Phase 2.
export function CategoryToggle({ policy, disabled, onChange }: Props) {
  const isAllowWithDLP = policy.action === 'allow_with_dlp';
  const isAllowed = policy.action === 'allow' || isAllowWithDLP;

  return (
    <div className="category-row">
      <div className="category-name">
        {policy.category}
        {isAllowWithDLP && <span className="dlp-badge">DLP</span>}
      </div>
      <div className="category-controls">
        <button
          type="button"
          disabled={disabled || isAllowed}
          onClick={() => onChange('allow')}
        >
          Allow
        </button>
        <button
          type="button"
          disabled={disabled || policy.action === 'deny'}
          onClick={() => onChange('deny')}
        >
          Block
        </button>
      </div>
    </div>
  );
}
