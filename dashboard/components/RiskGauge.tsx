'use client';

function riskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 55) return '#f59e0b';
  if (score >= 30) return '#3b82f6';
  return '#10b981';
}

function riskLabel(score: number) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 55) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

interface RiskGaugeProps {
  score: number;
}

/**
 * Radial SVG gauge — draws a semi-circle arc filled to `score` (0-100).
 */
export function RiskGauge({ score }: RiskGaugeProps) {
  const color = riskColor(score);
  const label = riskLabel(score);
  const clamped = Math.max(0, Math.min(100, score));

  // Semi-circle: cx=60,cy=60,r=44, sweep from 180° to 360°
  const r = 44;
  const cx = 60;
  const cy = 60;
  const startAngle = Math.PI; // 180°
  const sweepAngle = Math.PI; // 180° total sweep

  const fraction = clamped / 100;
  const endAngle = startAngle + sweepAngle * fraction;

  const x1 = cx + r * Math.cos(startAngle);
  const y1 = cy + r * Math.sin(startAngle);
  const x2 = cx + r * Math.cos(endAngle);
  const y2 = cy + r * Math.sin(endAngle);

  const trackPath = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
  const fillLargeArc = fraction > 0.5 ? 1 : 0;
  const fillPath =
    fraction <= 0
      ? ''
      : `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${fillLargeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;

  return (
    <div className="card-gradient-border" style={{ textAlign: 'center' }}>
      <div className="section-title" style={{ marginBottom: '8px' }}>Threat Severity</div>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <svg width="120" height="70" viewBox="0 0 120 70" style={{ overflow: 'visible' }}>
          {/* Track */}
          <path
            d={trackPath}
            fill="none"
            stroke="var(--border2)"
            strokeWidth="8"
            strokeLinecap="round"
          />
          {/* Fill */}
          {fillPath && (
            <path
              d={fillPath}
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 4px ${color}66)`, transition: 'all 0.5s ease' }}
            />
          )}
          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map((pct) => {
            const angle = Math.PI + (Math.PI * pct) / 100;
            const ix = cx + (r + 6) * Math.cos(angle);
            const iy = cy + (r + 6) * Math.sin(angle);
            const ox = cx + (r + 12) * Math.cos(angle);
            const oy = cy + (r + 12) * Math.sin(angle);
            return (
              <line
                key={pct}
                x1={ix.toFixed(1)} y1={iy.toFixed(1)}
                x2={ox.toFixed(1)} y2={oy.toFixed(1)}
                stroke="var(--border2)"
                strokeWidth="1"
              />
            );
          })}
          {/* Center score */}
          <text
            x="60" y="58"
            textAnchor="middle"
            fontSize="18"
            fontWeight="800"
            fontFamily="inherit"
            fill={color}
          >
            {clamped}
          </text>
        </svg>
      </div>
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          marginTop: '4px',
          padding: '3px 10px',
          borderRadius: '4px',
          background: `${color}14`,
          border: `1px solid ${color}30`,
        }}
      >
        <span
          style={{
            width: '6px', height: '6px', borderRadius: '50%',
            background: color,
            boxShadow: `0 0 5px ${color}`,
            display: 'inline-block',
          }}
        />
        <span style={{ fontSize: '10px', fontWeight: 700, color, letterSpacing: '0.08em' }}>
          {label}
        </span>
      </div>
    </div>
  );
}
