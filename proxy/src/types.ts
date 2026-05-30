export interface DetectionResult {
  risk_score: number;          // 0–100
  action: 'allow' | 'redact' | 'block' | 'route_local';
  pii_types: string[];
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  redacted_body: Record<string, unknown>;
  findings: Finding[];
  policy_rule?: string;        // which rule triggered
  latency_ms: number;
}

export interface Finding {
  type: string;
  severity: string;
  context: string;
  redacted: boolean;
}

export interface ProxyConfig {
  port: number;
  detectorUrl: string;
  policyPath: string;
  upstreamOpenAI: string;
  upstreamAnthropic: string;
  upstreamOllama: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface RequestStats {
  id: string;
  ts: number;
  model: string;
  action: string;
  pii_types: string[];
  risk_score: number;
  latency_ms: number;
  upstream: string;
}
