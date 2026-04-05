"""
TSM Layer - Webhooks
Event-driven webhooks for external integrations.
"""

import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import time


class WebhookEvent(Enum):
    """Webhook event types."""
    REQUEST_STARTED = "request.started"
    REQUEST_COMPLETED = "request.completed"
    REQUEST_FAILED = "request.failed"
    PII_DETECTED = "pii.detected"
    POLICY_VIOLATED = "policy.violated"
    RATE_LIMIT_EXCEEDED = "ratelimit.exceeded"
    COST_THRESHOLD_EXCEEDED = "cost.threshold_exceeded"


@dataclass
class Webhook:
    """Webhook configuration."""
    id: str
    url: str
    events: List[WebhookEvent]
    secret: str
    is_active: bool = True
    retry_count: int = 3


class WebhookManager:
    """Manages webhook subscriptions and delivery."""

    def __init__(self):
        self.webhooks: Dict[str, Webhook] = {}
        self.event_handlers: Dict[WebhookEvent, List[str]] = {}  # event -> webhook_ids

    def register_webhook(self, webhook_id: str, url: str, events: List[WebhookEvent],
                        secret: str) -> bool:
        """Register a new webhook."""
        webhook = Webhook(
            id=webhook_id,
            url=url,
            events=events,
            secret=secret
        )
        self.webhooks[webhook_id] = webhook

        # Register for events
        for event in events:
            if event not in self.event_handlers:
                self.event_handlers[event] = []
            self.event_handlers[event].append(webhook_id)

        return True

    def unregister_webhook(self, webhook_id: str) -> bool:
        """Unregister a webhook."""
        if webhook_id in self.webhooks:
            webhook = self.webhooks[webhook_id]
            for event in webhook.events:
                if event in self.event_handlers:
                    self.event_handlers[event].remove(webhook_id)
            del self.webhooks[webhook_id]
            return True
        return False

    async def trigger_event(self, event: WebhookEvent, payload: Dict):
        """Trigger webhook event."""
        webhook_ids = self.event_handlers.get(event, [])
        tasks = []

        for webhook_id in webhook_ids:
            webhook = self.webhooks.get(webhook_id)
            if webhook and webhook.is_active:
                tasks.append(self._deliver_webhook(webhook, event, payload))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _deliver_webhook(self, webhook: Webhook, event: WebhookEvent, payload: Dict):
        """Deliver webhook with retry logic."""
        event_payload = {
            'event': event.value,
            'timestamp': time.time(),
            'data': payload
        }

        for attempt in range(webhook.retry_count):
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {
                        'Content-Type': 'application/json',
                        'X-TSM-Signature': webhook.secret,
                        'X-TSM-Event': event.value
                    }

                    async with session.post(
                        webhook.url,
                        json=event_payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            return  # Success

            except Exception:
                if attempt < webhook.retry_count - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    # Final failure, log it
                    pass


# Global webhook manager
_global_webhooks: Optional[WebhookManager] = None


def get_webhook_manager() -> WebhookManager:
    """Get the global webhook manager."""
    global _global_webhooks
    if _global_webhooks is None:
        _global_webhooks = WebhookManager()
    return _global_webhooks
