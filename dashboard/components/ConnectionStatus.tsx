'use client';

interface ConnectionStatusProps {
  connected: boolean;
  lastUpdate: string;
}

export function ConnectionStatus({ connected, lastUpdate }: ConnectionStatusProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <span
        className={connected ? 'pulse' : ''}
        style={{
          width: '8px', height: '8px', borderRadius: '50%',
          background: connected ? 'var(--green)' : 'var(--red)',
          display: 'inline-block',
        }}
      />
      <span style={{ color: 'var(--muted)', fontSize: '11px' }}>
        {connected ? `Live · ${lastUpdate}` : 'Disconnected · Start proxy'}
      </span>
    </div>
  );
}
