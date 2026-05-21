'use client';

import { Sparkline } from './Sparkline';

interface MetricsCardProps {
  label: string;
  value: number;
  color: string;
  history?: number[];
  sub?: string;
}

export function MetricsCard({ label, value, color, history, sub }: MetricsCardProps) {
  return (
    <div
      className="card-gradient-border"
      style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div
            className="stat-value"
            style={{ color, fontSize: '1.6rem' }}
          >
            {value.toLocaleString()}
          </div>
          <div className="stat-label">{label}</div>
          {sub && (
            <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '4px' }}>
              {sub}
            </div>
          )}
        </div>
        {history && history.length >= 2 && (
          <div style={{ paddingTop: '4px', opacity: 0.85 }}>
            <Sparkline data={history} color={color} width={64} height={26} />
          </div>
        )}
      </div>
    </div>
  );
}
