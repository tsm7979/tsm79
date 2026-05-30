/**
 * Structured JSON logger — Datadog / Splunk / Elastic compatible.
 *
 * Every log line is a single JSON object with:
 *   ts, level, service, request_id, org_id, message, ...fields
 *
 * Set TSM_LOG_FORMAT=text for human-readable dev output (default in TTY).
 */

const SERVICE = 'tsm-proxy';
const IS_JSON = process.env.TSM_LOG_FORMAT === 'json' || !process.stdout.isTTY;

export type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_NUM: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL = LEVEL_NUM[(process.env.TSM_LOG_LEVEL as Level) ?? 'info'] ?? 20;

// ANSI for text mode
const C = { reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m', cyan: '\x1b[96m', green: '\x1b[92m', yellow: '\x1b[93m', red: '\x1b[91m' };
const LEVEL_COLOR: Record<Level, string> = { debug: C.dim, info: C.cyan, warn: C.yellow, error: C.red };

export interface LogFields {
  request_id?: string;
  org_id?:     string;
  workspace?:  string;
  model?:      string;
  action?:     string;
  risk_score?: number;
  pii_types?:  string[];
  latency_ms?: number;
  upstream?:   string;
  error?:      string;
  [key: string]: unknown;
}

function emit(level: Level, message: string, fields: LogFields = {}): void {
  if (LEVEL_NUM[level] < MIN_LEVEL) return;

  if (IS_JSON) {
    const line = JSON.stringify({
      ts:      new Date().toISOString(),
      level,
      service: SERVICE,
      message,
      ...fields,
    });
    process.stdout.write(line + '\n');
    return;
  }

  // Human-readable text mode
  const ts    = new Date().toISOString().slice(11, 23);
  const color = LEVEL_COLOR[level];
  const extra = Object.keys(fields).length
    ? '  ' + C.dim + Object.entries(fields).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ') + C.reset
    : '';
  console.log(`${C.dim}${ts}${C.reset} ${color}${C.bold}[TSM]${C.reset} ${message}${extra}`);
}

export const logger = {
  debug: (msg: string, f?: LogFields) => emit('debug', msg, f),
  info:  (msg: string, f?: LogFields) => emit('info',  msg, f),
  warn:  (msg: string, f?: LogFields) => emit('warn',  msg, f),
  error: (msg: string, f?: LogFields) => emit('error', msg, f),

  /** Log a completed request — always structured for SIEM ingestion. */
  request(fields: {
    request_id: string;
    org_id:     string;
    model:      string;
    action:     string;
    risk_score: number;
    pii_types:  string[];
    latency_ms: number;
    upstream:   string;
    status:     number;
  }): void {
    emit('info', 'request_complete', fields);
  },
};
