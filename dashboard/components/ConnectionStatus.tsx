'use client';

interface ConnectionStatusProps {
  connected: boolean;
  lastUpdate: string;
}

export function ConnectionStatus({ connected, lastUpdate }: ConnectionStatusProps) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '5px 12px',
        borderRadius: '20px',
        background: connected ? 'rgba(16,185,129,0.07)' : 'rgba(239,68,68,0.07)',
        border: `1px solid ${connected ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
      }}
    >
      <span
        className={connected ? 'pulse' : ''}
        style={{
          width: '7px',
          height: '7px',
          borderRadius: '50%',
          background: connected ? 'var(--green)' : 'var(--red)',
          display: 'inline-block',
          boxShadow: connected ? '0 0 6px var(--green)' : 'none',
        }}
      />
      <span
        style={{
          color: connected ? 'var(--green)' : 'var(--red)',
          fontSize: '11px',
          fontWeight: 600,
          letterSpacing: '0.04em',
        }}
      >
        {connected ? `LIVE · ${lastUpdate}` : 'DISCONNECTED'}
      </span>
    </div>
  );
}
