/**
 * TSM Proxy — TypeScript production HTTP proxy
 * ============================================
 * Handles all AI traffic. Calls the Python detector service for each request,
 * applies policy rules, then forwards clean traffic to the real AI provider.
 *
 * Architecture:
 *   Client → TSM Proxy (TS) → Detector (Python FastAPI) → Upstream AI API
 *
 * Why TypeScript here?
 *   - Non-blocking I/O: handles hundreds of concurrent streaming connections
 *   - Proper SSE/chunked-transfer support
 *   - Production HTTP server (not Python's http.server toy)
 *   - Type-safe request/response contracts
 */

import http, { IncomingMessage, ServerResponse } from 'http';
import { URL } from 'url';
import { record, snapshot } from './metrics.js';
import { resolveUpstream, forwardJSON, forwardStream, buildAuthHeaders } from './upstream.js';
import { DetectionResult, RequestStats } from './types.js';

// ── Config ────────────────────────────────────────────────────────────────────

const PORT          = parseInt(process.env.TSM_PORT          ?? '8080');
const DETECTOR_URL  = process.env.TSM_DETECTOR_URL           ?? 'http://localhost:8001';
const LOG_LEVEL     = (process.env.TSM_LOG ?? 'info') as 'debug' | 'info' | 'warn' | 'error';

// ── Logger ────────────────────────────────────────────────────────────────────

const RESET = '\x1b[0m', DIM = '\x1b[2m', BOLD = '\x1b[1m';
const CYAN = '\x1b[96m', GREEN = '\x1b[92m', YELLOW = '\x1b[93m', RED = '\x1b[91m';

function log(level: string, msg: string, color = RESET): void {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`${DIM}${ts}${RESET} ${color}${BOLD}[TSM]${RESET} ${msg}`);
}

function info(msg: string)  { log('info',  msg, CYAN);   }
function ok(msg: string)    { log('ok',    msg, GREEN);  }
function warn(msg: string)  { log('warn',  msg, YELLOW); }
function err(msg: string)   { log('err',   msg, RED);    }

// ── Detector client ───────────────────────────────────────────────────────────

async function detect(body: Record<string, unknown>): Promise<DetectionResult> {
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), 5_000);

  try {
    const res = await fetch(`${DETECTOR_URL}/detect`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  controller.signal,
    });

    if (!res.ok) throw new Error(`Detector ${res.status}`);
    return await res.json() as DetectionResult;
  } catch (e) {
    // Detector unavailable — fail open (allow with warning) so proxy never blocks due to infra
    warn(`Detector unavailable: ${e} — allowing request`);
    return {
      risk_score: 0,
      action: 'allow',
      pii_types: [],
      severity: 'none',
      redacted_body: body,
      findings: [],
      latency_ms: 0,
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ── SSE helpers ───────────────────────────────────────────────────────────────

function startSSE(res: ServerResponse, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-TSM-Proxy':  'active',
    ...extraHeaders,
  });
}

function sendSSEError(res: ServerResponse, message: string): void {
  const chunk = JSON.stringify({
    id: 'err', object: 'chat.completion.chunk', created: Date.now() / 1000 | 0,
    model: 'tsm', choices: [{ index: 0, delta: { content: message }, finish_reason: null }],
  });
  res.write(`data: ${chunk}\n\n`);
  res.write(`data: [DONE]\n\n`);
  res.end();
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

function sendJSON(res: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': payload.length,
    'X-TSM-Proxy':   'active',
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

// ── Core handler ─────────────────────────────────────────────────────────────

async function handleChatCompletion(
  req: IncomingMessage,
  res: ServerResponse,
  rawBody: string,
): Promise<void> {
  const t0 = Date.now();
  let body: Record<string, unknown>;

  try {
    body = JSON.parse(rawBody);
  } catch {
    sendJSON(res, 400, { error: { code: 400, message: 'Invalid JSON' } });
    return;
  }

  const model   = (body.model as string) ?? 'gpt-3.5-turbo';
  const isStream = Boolean(body.stream);

  // ── Detection ─────────────────────────────────────────────────────────────
  info(`→ ${model}  ${isStream ? '(stream)' : ''}`);
  const detection = await detect(body);
  const { action, pii_types, risk_score, severity, redacted_body, policy_rule } = detection;

  // ── TSM headers ───────────────────────────────────────────────────────────
  const tsmHeaders = {
    'X-TSM-Action':    action,
    'X-TSM-Risk':      String(risk_score),
    'X-TSM-PII':       pii_types.join(',') || 'none',
    'X-TSM-Severity':  severity,
    'X-TSM-Policy':    policy_rule ?? 'default',
  };

  // ── Block ─────────────────────────────────────────────────────────────────
  if (action === 'block') {
    err(`BLOCKED  risk=${risk_score}  pii=${pii_types.join(',')}`);
    sendJSON(res, 400, {
      error: {
        code:    'tsm_blocked',
        message: `[TSM] Request blocked — policy: ${policy_rule ?? 'security'}. Detected: ${pii_types.join(', ')}`,
      },
      tsm: { action, risk_score, pii_types, policy_rule },
    });
    record({ id: crypto.randomUUID(), ts: t0, model, action, pii_types, risk_score, latency_ms: Date.now() - t0, upstream: 'blocked' });
    return;
  }

  // ── Route to local (Ollama) ───────────────────────────────────────────────
  const forwardBody = (action === 'redact' || action === 'route_local')
    ? redacted_body as Record<string, unknown>
    : body;

  const upstream = action === 'route_local' ? 'ollama' : resolveUpstream(model);
  const authHeaders = buildAuthHeaders(upstream);
  const upstreamPath = upstream === 'anthropic' ? '/v1/messages' : '/v1/chat/completions';

  if (action !== 'allow') {
    warn(`${action.toUpperCase()}  risk=${risk_score}  pii=${pii_types.join(',')}  → ${upstream}`);
  } else {
    ok(`CLEAN  → ${upstream}`);
  }

  const latency = Date.now() - t0;
  record({ id: crypto.randomUUID(), ts: t0, model, action, pii_types, risk_score, latency_ms: latency, upstream });

  // ── Stream ────────────────────────────────────────────────────────────────
  if (isStream) {
    startSSE(res, tsmHeaders);

    // If no upstream key configured, emit demo stream
    if (upstream === 'ollama' && !process.env.OLLAMA_HOST) {
      const msg = `[TSM] No Ollama running. Action was ${action}. Risk score: ${risk_score}. ` +
        `Detected: ${pii_types.join(', ') || 'none'}.`;
      const words = msg.split(' ');
      for (let i = 0; i < words.length; i++) {
        const chunk = JSON.stringify({
          id: 'demo', object: 'chat.completion.chunk', created: Date.now() / 1000 | 0, model,
          choices: [{ index: 0, delta: { content: words[i] + (i < words.length - 1 ? ' ' : '') }, finish_reason: null }],
        });
        res.write(`data: ${chunk}\n\n`);
      }
      res.write(`data: ${JSON.stringify({ id: 'demo', object: 'chat.completion.chunk', created: Date.now() / 1000 | 0, model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })}\n\n`);
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    }

    forwardStream(upstream, upstreamPath, forwardBody, authHeaders, res);
    return;
  }

  // ── Non-stream ────────────────────────────────────────────────────────────
  try {
    const upstream_response = await forwardJSON(upstream, upstreamPath, forwardBody, authHeaders);
    const enriched = {
      ...upstream_response,
      tsm: { action, risk_score, pii_types, severity, policy_rule, latency_ms: Date.now() - t0, upstream },
    };
    sendJSON(res, 200, enriched);
  } catch (e) {
    // Upstream failed — return structured error with TSM context
    sendJSON(res, 502, {
      error: { code: 'upstream_error', message: String(e) },
      tsm: { action, risk_score, pii_types, upstream },
    });
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url    = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const path   = url.pathname;
  const method = req.method ?? 'GET';

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
    res.end();
    return;
  }

  // ── Routes ─────────────────────────────────────────────────────────────────

  if (method === 'GET' && path === '/health') {
    sendJSON(res, 200, { status: 'healthy', service: 'TSM Proxy', version: '2.0.0', detector: DETECTOR_URL });
    return;
  }

  if (method === 'GET' && path === '/metrics') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(snapshot()));
    return;
  }

  if (method === 'GET' && path === '/metrics/stream') {
    // Server-sent events for live dashboard
    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    const interval = setInterval(() => {
      res.write(`data: ${JSON.stringify(snapshot())}\n\n`);
    }, 1000);
    req.on('close', () => clearInterval(interval));
    return;
  }

  if (method === 'GET' && path === '/v1/models') {
    sendJSON(res, 200, { object: 'list', data: [
      { id: 'gpt-4',         object: 'model', created: 0, owned_by: 'openai'    },
      { id: 'gpt-3.5-turbo', object: 'model', created: 0, owned_by: 'openai'    },
      { id: 'claude-sonnet-4-6', object: 'model', created: 0, owned_by: 'anthropic' },
      { id: 'llama3',        object: 'model', created: 0, owned_by: 'local'     },
    ]});
    return;
  }

  if (method === 'POST' && (path === '/v1/chat/completions' || path === '/v1/completions')) {
    const rawBody = await readBody(req);
    await handleChatCompletion(req, res, rawBody);
    return;
  }

  sendJSON(res, 404, { error: { code: 404, message: `Not found: ${path}` } });
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────

function shutdown(): void {
  info('Shutting down gracefully...');
  server.close(() => {
    info('Proxy stopped.');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000); // force after 5s
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

// ── Start ─────────────────────────────────────────────────────────────────────

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log(`${CYAN}${BOLD}  TSM Proxy${RESET}  ${DIM}v2.0.0${RESET}`);
  console.log(`${DIM}  ${'─'.repeat(48)}${RESET}`);
  console.log(`  Listening   ${BOLD}http://localhost:${PORT}${RESET}`);
  console.log(`  Detector    ${DIM}${DETECTOR_URL}${RESET}`);
  console.log(`  Metrics     ${DIM}http://localhost:${PORT}/metrics${RESET}`);
  console.log(`${DIM}  ${'─'.repeat(48)}${RESET}`);
  console.log(`  ${DIM}OPENAI_API_KEY    ${process.env.OPENAI_API_KEY    ? GREEN + 'set' : DIM + 'not set'}${RESET}`);
  console.log(`  ${DIM}ANTHROPIC_API_KEY ${process.env.ANTHROPIC_API_KEY ? GREEN + 'set' : DIM + 'not set'}${RESET}`);
  console.log('');
});
