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
import { randomUUID } from 'crypto';
import { URL } from 'url';
import { record, snapshot } from './metrics.js';
import { resolveUpstream, forwardJSON, forwardStream, buildAuthHeaders } from './upstream.js';
import { DetectionResult, RequestStats } from './types.js';
import { checkRateLimit, remaining } from './ratelimit.js';
import { isAllowed, recordSuccess, recordFailure, breakerStatus } from './circuit.js';
import { logger } from './logger.js';

// ── Config ────────────────────────────────────────────────────────────────────

const PORT              = parseInt(process.env.TSM_PORT              ?? '8080');
const DETECTOR_URL      = process.env.TSM_DETECTOR_URL               ?? 'http://localhost:8001';
// allow  — pass traffic through when detector is unreachable (default, safe for dev)
// block  — return 503 until detector recovers (recommended for production)
// degrade — apply fast-path regex only, skip ML scan
const DETECTOR_FAILURE_MODE = (process.env.TSM_DETECTOR_FAILURE_MODE ?? 'allow') as 'allow' | 'block' | 'degrade';

// ── Helpers ───────────────────────────────────────────────────────────────────

function clientIp(req: IncomingMessage): string {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return (Array.isArray(fwd) ? fwd[0] : fwd).split(',')[0].trim();
  return req.socket.remoteAddress ?? 'unknown';
}

function orgId(req: IncomingMessage): string {
  return (req.headers['x-tsm-org'] as string) ?? 'default';
}

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
    logger.warn(`Detector unavailable: ${e} — mode=${DETECTOR_FAILURE_MODE}`);
    if (DETECTOR_FAILURE_MODE === 'block') {
      // Fail closed: return a block result so the proxy returns 503
      return {
        risk_score: 100,
        action: 'block',
        pii_types: ['DETECTOR_UNAVAILABLE'],
        severity: 'critical',
        redacted_body: body,
        findings: [],
        latency_ms: 0,
        policy_rule: 'detector_failure_block',
      };
    }
    // allow or degrade: pass traffic through (degrade = same as allow for now;
    // fast-path regex in Go proxy already covered the critical cases)
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
  const t0        = Date.now();
  const requestId = randomUUID();
  const ip        = clientIp(req);
  const org       = orgId(req);

  // ── Rate limiting ─────────────────────────────────────────────────────────
  if (!checkRateLimit(ip)) {
    logger.warn('rate_limited', { request_id: requestId, org_id: org });
    sendJSON(res, 429, {
      error: { code: 'rate_limited', message: 'Too many requests — slow down.' },
    });
    return;
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody);
  } catch {
    sendJSON(res, 400, { error: { code: 400, message: 'Invalid JSON' } });
    return;
  }

  const model    = (body.model as string) ?? 'gpt-3.5-turbo';
  const isStream = Boolean(body.stream);

  // ── Detection ─────────────────────────────────────────────────────────────
  logger.info(`→ ${model}`, { request_id: requestId, org_id: org });
  const detection = await detect(body);
  const { action, pii_types, risk_score, severity, redacted_body, policy_rule } = detection;

  // ── TSM headers ───────────────────────────────────────────────────────────
  const tsmHeaders = {
    'X-TSM-Action':     action,
    'X-TSM-Risk':       String(risk_score),
    'X-TSM-PII':        pii_types.join(',') || 'none',
    'X-TSM-Severity':   severity,
    'X-TSM-Policy':     policy_rule ?? 'default',
    'X-TSM-Request-ID': requestId,
  };

  // ── Block ─────────────────────────────────────────────────────────────────
  if (action === 'block') {
    logger.warn('BLOCKED', { request_id: requestId, org_id: org, risk_score, pii_types, model });
    sendJSON(res, 400, {
      error: {
        code:    'tsm_blocked',
        message: `[TSM] Request blocked — policy: ${policy_rule ?? 'security'}. Detected: ${pii_types.join(', ')}`,
      },
      tsm: { action, risk_score, pii_types, policy_rule, request_id: requestId },
    });
    record({ id: requestId, ts: t0, model, action, pii_types, risk_score, latency_ms: Date.now() - t0, upstream: 'blocked' });
    return;
  }

  // ── Route to local (Ollama) ───────────────────────────────────────────────
  const forwardBody = (action === 'redact' || action === 'route_local')
    ? redacted_body as Record<string, unknown>
    : body;

  const upstream     = action === 'route_local' ? 'ollama' : resolveUpstream(model);
  const authHeaders  = buildAuthHeaders(upstream);
  const upstreamPath = upstream === 'anthropic' ? '/v1/messages' : '/v1/chat/completions';

  logger.info(action === 'allow' ? `CLEAN → ${upstream}` : `${action.toUpperCase()} → ${upstream}`, {
    request_id: requestId, org_id: org, risk_score, pii_types, model,
  });

  // ── Circuit breaker ───────────────────────────────────────────────────────
  if (!isAllowed(upstream)) {
    logger.warn('circuit_open', { request_id: requestId, upstream });
    sendJSON(res, 503, {
      error: { code: 'upstream_unavailable', message: `Upstream ${upstream} is temporarily unavailable. Try again shortly.` },
      tsm:   { action, risk_score, pii_types, upstream },
    });
    return;
  }

  const latency = Date.now() - t0;
  record({ id: requestId, ts: t0, model, action, pii_types, risk_score, latency_ms: latency, upstream });

  // ── Stream ────────────────────────────────────────────────────────────────
  if (isStream) {
    startSSE(res, tsmHeaders);
    if (upstream === 'ollama' && !process.env.OLLAMA_HOST) {
      const msg = `[TSM] No Ollama running. Action=${action}. Risk=${risk_score}. PII=${pii_types.join(', ') || 'none'}.`;
      const words = msg.split(' ');
      for (let i = 0; i < words.length; i++) {
        const chunk = JSON.stringify({
          id: requestId, object: 'chat.completion.chunk', created: Date.now() / 1000 | 0, model,
          choices: [{ index: 0, delta: { content: words[i] + (i < words.length - 1 ? ' ' : '') }, finish_reason: null }],
        });
        res.write(`data: ${chunk}\n\n`);
      }
      res.write(`data: ${JSON.stringify({ id: requestId, object: 'chat.completion.chunk', created: Date.now() / 1000 | 0, model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })}\n\n`);
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    }
    forwardStream(upstream, upstreamPath, forwardBody, authHeaders, res);
    return;
  }

  // ── Non-stream ────────────────────────────────────────────────────────────
  try {
    const upstreamResponse = await forwardJSON(upstream, upstreamPath, forwardBody, authHeaders);
    recordSuccess(upstream);
    const enriched = {
      ...upstreamResponse,
      tsm: { action, risk_score, pii_types, severity, policy_rule, latency_ms: Date.now() - t0, upstream, request_id: requestId },
    };
    logger.request({ request_id: requestId, org_id: org, model, action, risk_score, pii_types, latency_ms: Date.now() - t0, upstream, status: 200 });
    sendJSON(res, 200, enriched);
  } catch (e) {
    recordFailure(upstream);
    logger.error('upstream_error', { request_id: requestId, upstream, error: String(e) });
    sendJSON(res, 502, {
      error: { code: 'upstream_error', message: String(e) },
      tsm:   { action, risk_score, pii_types, upstream, request_id: requestId },
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
    sendJSON(res, 200, {
      status:   'healthy',
      service:  'TSM Proxy',
      version:  '2.0.0',
      detector:  DETECTOR_URL,
      breakers:  breakerStatus(),
    });
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
  logger.info('Shutting down gracefully...');
  server.close(() => {
    logger.info('Proxy stopped.');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

// ── Start ─────────────────────────────────────────────────────────────────────

const C2 = { r: '\x1b[0m', d: '\x1b[2m', b: '\x1b[1m', c: '\x1b[96m', g: '\x1b[92m' };
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log(`${C2.c}${C2.b}  TSM Proxy${C2.r}  ${C2.d}v2.0.0${C2.r}`);
  console.log(`${C2.d}  ${'─'.repeat(48)}${C2.r}`);
  console.log(`  Listening   ${C2.b}http://localhost:${PORT}${C2.r}`);
  console.log(`  Detector    ${C2.d}${DETECTOR_URL}${C2.r}`);
  console.log(`  Metrics     ${C2.d}http://localhost:${PORT}/metrics${C2.r}`);
  console.log(`${C2.d}  ${'─'.repeat(48)}${C2.r}`);
  console.log(`  ${C2.d}OPENAI_API_KEY    ${process.env.OPENAI_API_KEY    ? C2.g + 'set' : C2.d + 'not set'}${C2.r}`);
  console.log(`  ${C2.d}ANTHROPIC_API_KEY ${process.env.ANTHROPIC_API_KEY ? C2.g + 'set' : C2.d + 'not set'}${C2.r}`);
  console.log('');
});
