#!/usr/bin/env python3
"""
TSM Proxy Server - OpenAI-Compatible AI Firewall
==================================================

Drop-in replacement for OpenAI API with built-in:
- PII detection and redaction
- Smart routing (local vs cloud)
- Cost tracking
- Audit logging

Usage:
    python proxy_server.py

Then point your OpenAI client:
    export OPENAI_BASE_URL=http://localhost:8080
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('tsm.proxy')


class ModelType(str, Enum):
    """Supported model types"""
    GPT4 = "gpt-4"
    GPT4_TURBO = "gpt-4-turbo"
    GPT35_TURBO = "gpt-3.5-turbo"
    CLAUDE_3_OPUS = "claude-3-opus"
    CLAUDE_3_SONNET = "claude-3-sonnet"
    LOCAL = "local"


@dataclass
class ProxyConfig:
    """Proxy server configuration"""
    host: str = "localhost"
    port: int = 8080
    enable_pii_detection: bool = True
    enable_smart_routing: bool = True
    enable_audit_log: bool = True
    max_request_size: int = 10 * 1024 * 1024  # 10MB

    # Model costs per 1K tokens (input + output average)
    model_costs: Dict[str, float] = None

    def __post_init__(self):
        if self.model_costs is None:
            self.model_costs = {
                ModelType.GPT4: 0.045,
                ModelType.GPT4_TURBO: 0.015,
                ModelType.GPT35_TURBO: 0.001,
                ModelType.CLAUDE_3_OPUS: 0.045,
                ModelType.CLAUDE_3_SONNET: 0.009,
                ModelType.LOCAL: 0.0
            }


class PIIDetector:
    """Fast PII detection using regex patterns"""

    import re

    PATTERNS = {
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'api_key': re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']?[\w\-]{20,}["\']?', re.IGNORECASE),
        'aws_key': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
    }

    @classmethod
    def detect(cls, text: str) -> List[str]:
        """Detect PII in text, return list of detected types"""
        detected = []
        for pii_type, pattern in cls.PATTERNS.items():
            if pattern.search(text):
                detected.append(pii_type)
        return detected

    @classmethod
    def redact(cls, text: str) -> str:
        """Redact all PII from text"""
        redacted = text
        for pii_type, pattern in cls.PATTERNS.items():
            redacted = pattern.sub(f'[REDACTED_{pii_type.upper()}]', redacted)
        return redacted


class SmartRouter:
    """Route requests based on content sensitivity"""

    @staticmethod
    def route(content: str, detected_pii: List[str], requested_model: str) -> Dict[str, Any]:
        """
        Determine routing decision

        Returns:
            {
                'target_model': str,
                'reason': str,
                'is_local': bool,
                'redact_required': bool
            }
        """
        # High-risk PII → force local
        if any(pii in detected_pii for pii in ['ssn', 'credit_card', 'api_key', 'aws_key']):
            return {
                'target_model': ModelType.LOCAL,
                'reason': 'Critical PII detected - routed to local model',
                'is_local': True,
                'redact_required': True
            }

        # Low-risk PII → redact but allow cloud
        if detected_pii:
            return {
                'target_model': requested_model,
                'reason': f'PII detected ({", ".join(detected_pii)}) - redacted before cloud',
                'is_local': False,
                'redact_required': True
            }

        # No PII → pass through
        return {
            'target_model': requested_model,
            'reason': 'No sensitive data detected',
            'is_local': False,
            'redact_required': False
        }


class CostTracker:
    """Track API costs"""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.session_costs: Dict[str, float] = {}
        self.total_requests = 0

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a request"""
        if model == ModelType.LOCAL:
            return 0.0

        # Approximate: 4 chars = 1 token
        total_tokens = input_tokens + output_tokens
        cost_per_1k = self.config.model_costs.get(model, 0.01)
        return (total_tokens / 1000) * cost_per_1k

    def track(self, session_id: str, model: str, input_len: int, output_len: int) -> float:
        """Track cost for a request"""
        # Rough token estimation
        input_tokens = input_len // 4
        output_tokens = output_len // 4

        cost = self.estimate_cost(model, input_tokens, output_tokens)

        self.session_costs[session_id] = self.session_costs.get(session_id, 0) + cost
        self.total_requests += 1

        return cost


class AuditLogger:
    """Log all requests for compliance"""

    def __init__(self, log_file: str = "tsm_audit.jsonl"):
        self.log_file = log_file

    def log(self, request_data: Dict[str, Any]):
        """Append request to audit log"""
        try:
            with open(self.log_file, 'a') as f:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    **request_data
                }
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")


class TSMProxy:
    """Main proxy server logic"""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.pii_detector = PIIDetector()
        self.router = SmartRouter()
        self.cost_tracker = CostTracker(config)
        self.audit_logger = AuditLogger() if config.enable_audit_log else None

    async def handle_chat_completion(self, request_body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle /v1/chat/completions request

        OpenAI-compatible endpoint
        """
        start_time = time.time()

        # Extract messages
        messages = request_body.get('messages', [])
        requested_model = request_body.get('model', ModelType.GPT35_TURBO)

        # Concatenate all user messages for PII detection
        combined_content = '\n'.join([
            msg.get('content', '') for msg in messages
            if msg.get('role') == 'user'
        ])

        # Step 1: PII Detection
        detected_pii = []
        if self.config.enable_pii_detection:
            detected_pii = self.pii_detector.detect(combined_content)

        # Step 2: Smart Routing
        routing_decision = self.router.route(
            combined_content,
            detected_pii,
            requested_model
        )

        # Step 3: Redact if needed
        processed_messages = messages
        if routing_decision['redact_required']:
            processed_messages = [
                {
                    **msg,
                    'content': self.pii_detector.redact(msg.get('content', ''))
                    if msg.get('role') == 'user' else msg.get('content', '')
                }
                for msg in messages
            ]

        # Step 4: Generate response (simulated for demo)
        response_text = self._generate_response(
            processed_messages,
            routing_decision['target_model']
        )

        # Step 5: Track costs
        cost = self.cost_tracker.track(
            request_body.get('session_id', 'default'),
            routing_decision['target_model'],
            len(combined_content),
            len(response_text)
        )

        # Step 6: Audit log
        if self.audit_logger:
            self.audit_logger.log({
                'request_id': f"tsm_{int(time.time() * 1000)}",
                'model_requested': requested_model,
                'model_used': routing_decision['target_model'],
                'pii_detected': detected_pii,
                'routing_reason': routing_decision['reason'],
                'redacted': routing_decision['redact_required'],
                'cost': cost,
                'latency_ms': (time.time() - start_time) * 1000
            })

        # Step 7: Return OpenAI-compatible response
        return {
            'id': f"chatcmpl-{int(time.time())}",
            'object': 'chat.completion',
            'created': int(time.time()),
            'model': routing_decision['target_model'],
            'choices': [{
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': response_text
                },
                'finish_reason': 'stop'
            }],
            'usage': {
                'prompt_tokens': len(combined_content) // 4,
                'completion_tokens': len(response_text) // 4,
                'total_tokens': (len(combined_content) + len(response_text)) // 4
            },
            'tsm_metadata': {
                'pii_detected': detected_pii,
                'routing_decision': routing_decision['reason'],
                'cost_estimate': round(cost, 6),
                'firewall_active': True
            }
        }

    def _generate_response(self, messages: List[Dict], model: str) -> str:
        """
        Generate AI response (simulated for demo)

        In production, this would call actual LLM APIs
        """
        if model == ModelType.LOCAL:
            return "[Demo Response] Processed locally for privacy. In production, this would call a local LLM."
        else:
            return f"[Demo Response] Processed via {model}. In production, this would call the actual API."


class TSMRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for proxy server"""

    proxy: TSMProxy = None  # Set by server

    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path

        # OpenAI-compatible endpoints
        if path == '/v1/chat/completions':
            self._handle_chat_completion()
        else:
            self._send_error(404, f"Endpoint not found: {path}")

    def do_GET(self):
        """Handle GET requests"""
        path = urlparse(self.path).path

        if path == '/health':
            self._send_json({'status': 'healthy', 'service': 'TSM Proxy'})
        elif path == '/stats':
            self._send_json({
                'total_requests': self.proxy.cost_tracker.total_requests,
                'session_costs': self.proxy.cost_tracker.session_costs,
                'firewall_enabled': self.proxy.config.enable_pii_detection
            })
        else:
            self._send_error(404, f"Endpoint not found: {path}")

    def _handle_chat_completion(self):
        """Handle chat completion request"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > self.proxy.config.max_request_size:
                self._send_error(413, "Request too large")
                return

            body = self.rfile.read(content_length)
            request_data = json.loads(body.decode('utf-8'))

            # Process request
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            response = loop.run_until_complete(
                self.proxy.handle_chat_completion(request_data)
            )
            loop.close()

            # Send response
            self._send_json(response)

        except json.JSONDecodeError:
            self._send_error(400, "Invalid JSON")
        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            self._send_error(500, str(e))

    def _send_json(self, data: Dict):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_error(self, code: int, message: str):
        """Send error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        error_data = {'error': {'message': message, 'code': code}}
        self.wfile.write(json.dumps(error_data).encode('utf-8'))

    def log_message(self, format, *args):
        """Override to use proper logging"""
        logger.info(f"{self.address_string()} - {format % args}")


def start_server(config: ProxyConfig = None):
    """Start the TSM proxy server"""
    if config is None:
        config = ProxyConfig()

    # Create proxy instance
    proxy = TSMProxy(config)

    # Set proxy on handler class
    TSMRequestHandler.proxy = proxy

    # Create server
    server = HTTPServer((config.host, config.port), TSMRequestHandler)

    logger.info("="*70)
    logger.info("🛡️  TSM Proxy Server - AI Firewall Active")
    logger.info("="*70)
    logger.info(f"Listening on: http://{config.host}:{config.port}")
    logger.info(f"PII Detection: {'✓ Enabled' if config.enable_pii_detection else '✗ Disabled'}")
    logger.info(f"Smart Routing: {'✓ Enabled' if config.enable_smart_routing else '✗ Disabled'}")
    logger.info(f"Audit Logging: {'✓ Enabled' if config.enable_audit_log else '✗ Disabled'}")
    logger.info("="*70)
    logger.info("")
    logger.info("📡 OpenAI-Compatible Endpoints:")
    logger.info(f"  POST http://{config.host}:{config.port}/v1/chat/completions")
    logger.info("")
    logger.info("📊 Management Endpoints:")
    logger.info(f"  GET  http://{config.host}:{config.port}/health")
    logger.info(f"  GET  http://{config.host}:{config.port}/stats")
    logger.info("")
    logger.info("💡 Usage:")
    logger.info("  export OPENAI_BASE_URL=http://localhost:8080")
    logger.info("  # Now your OpenAI SDK calls go through TSM firewall!")
    logger.info("="*70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\n\n🛑 Shutting down TSM Proxy Server...")
        server.shutdown()


if __name__ == '__main__':
    start_server()
