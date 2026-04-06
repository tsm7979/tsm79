/**
 * Upstream forwarder — sends the (cleaned) request to the real AI provider.
 * Handles both streaming (SSE) and non-streaming responses.
 * Zero framework dependencies — raw Node.js http/https.
 */
import https from 'https';
import http from 'http';
import { IncomingMessage, ServerResponse } from 'http';

export type UpstreamTarget = 'openai' | 'anthropic' | 'ollama' | 'local';

const UPSTREAM: Record<string, { host: string; port: number; tls: boolean }> = {
  openai:    { host: 'api.openai.com',      port: 443, tls: true  },
  anthropic: { host: 'api.anthropic.com',   port: 443, tls: true  },
  ollama:    { host: 'localhost',            port: 11434, tls: false },
};

export function resolveUpstream(model: string): UpstreamTarget {
  const m = model.toLowerCase();
  if (m.startsWith('claude'))                return 'anthropic';
  if (m.startsWith('gpt') || m.startsWith('o1') || m.startsWith('o3')) return 'openai';
  if (['llama', 'mistral', 'mixtral', 'phi', 'gemma', 'qwen'].some(p => m.startsWith(p))) return 'ollama';
  if (process.env.OPENAI_API_KEY)            return 'openai';
  if (process.env.ANTHROPIC_API_KEY)         return 'anthropic';
  return 'ollama';
}

/**
 * Non-streaming forward — reads full upstream response, returns JSON.
 */
export async function forwardJSON(
  target: UpstreamTarget,
  path: string,
  body: Record<string, unknown>,
  authHeaders: Record<string, string>,
): Promise<Record<string, unknown>> {
  const up = UPSTREAM[target];
  if (!up) throw new Error(`Unknown upstream: ${target}`);

  const payload = Buffer.from(JSON.stringify(body));
  const mod = up.tls ? https : http;

  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        host:    up.host,
        port:    up.port,
        path,
        method:  'POST',
        headers: {
          'Content-Type':   'application/json',
          'Content-Length': payload.length,
          ...authHeaders,
        },
        timeout: 30_000,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8')));
          } catch (e) {
            reject(new Error(`Upstream JSON parse error: ${e}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Upstream timeout')); });
    req.write(payload);
    req.end();
  });
}

/**
 * Streaming forward — pipes SSE chunks from upstream directly to client response.
 */
export function forwardStream(
  target: UpstreamTarget,
  path: string,
  body: Record<string, unknown>,
  authHeaders: Record<string, string>,
  clientRes: ServerResponse,
): void {
  const up = UPSTREAM[target];
  if (!up) {
    clientRes.end(`data: {"error":"Unknown upstream ${target}"}\n\ndata: [DONE]\n\n`);
    return;
  }

  const payload = Buffer.from(JSON.stringify({ ...body, stream: true }));
  const mod = up.tls ? https : http;

  const req = mod.request(
    {
      host:    up.host,
      port:    up.port,
      path,
      method:  'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': payload.length,
        ...authHeaders,
      },
      timeout: 60_000,
    },
    (res: IncomingMessage) => {
      res.pipe(clientRes, { end: true });
    },
  );
  req.on('error', (err) => {
    clientRes.write(`data: {"error":"${err.message}"}\n\n`);
    clientRes.end('data: [DONE]\n\n');
  });
  req.write(payload);
  req.end();
}

export function buildAuthHeaders(target: UpstreamTarget): Record<string, string> {
  if (target === 'openai') {
    const key = process.env.OPENAI_API_KEY;
    return key ? { Authorization: `Bearer ${key}` } : {};
  }
  if (target === 'anthropic') {
    const key = process.env.ANTHROPIC_API_KEY;
    return key
      ? { 'x-api-key': key, 'anthropic-version': '2023-06-01' }
      : {};
  }
  return {};
}
