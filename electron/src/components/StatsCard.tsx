interface Props {
  label: string;
  value: number | string;
  hint?: string;
}

export function StatsCard({ label, value, hint }: Props) {
  return (
    <div className="stats-card">
      <div className="stats-card-value">{value}</div>
      <div className="stats-card-label">{label}</div>
      {hint && <div className="stats-card-hint">{hint}</div>}
    </div>
  );
}
