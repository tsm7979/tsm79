'use client';

interface MetricsCardProps {
  label: string;
  value: number;
  color: string;
}

export function MetricsCard({ label, value, color }: MetricsCardProps) {
  return (
    <div className="card" style={{ textAlign: 'center' }}>
      <div className="stat-value" style={{ color }}>{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
