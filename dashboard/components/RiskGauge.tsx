'use client';

function riskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 55) return '#f59e0b';
  if (score >= 30) return '#3b82f6';
  return '#22c55e';
}

interface RiskGaugeProps {
  score: number;
}

export function RiskGauge({ score }: RiskGaugeProps) {
  const color = riskColor(score);
  return (
    <div className="card">
      <div className="stat-value" style={{ color }}>{score}</div>
      <div className="stat-label">Avg Risk Score</div>
      <div className="risk-bar" style={{ marginTop: '12px' }}>
        <div className="risk-fill" style={{ width: `${score}%`, background: color }} />
      </div>
    </div>
  );
}
