"""
TSM Layer - Messaging
Internal pub/sub messaging system for event distribution.
"""

import asyncio
from typing import Callable, Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class MessageTopic(Enum):
    """Message topics."""
    REQUEST_STARTED = "request.started"
    REQUEST_COMPLETED = "request.completed"
    REQUEST_FAILED = "request.failed"
    PII_DETECTED = "pii.detected"
    POLICY_VIOLATED = "policy.violated"
    CACHE_HIT = "cache.hit"
    CACHE_MISS = "cache.miss"
    RATE_LIMIT_HIT = "ratelimit.hit"
    COST_ALERT = "cost.alert"
    SYSTEM_HEALTH = "system.health"


@dataclass
class Message:
    """Message in the bus."""
    topic: MessageTopic
    payload: Dict[str, Any]
    timestamp: float


class MessageBus:
    """Simple in-memory pub/sub message bus."""

    def __init__(self):
        self.subscribers: Dict[MessageTopic, List[Callable]] = {}
        self.message_history: List[Message] = []

    def subscribe(self, topic: MessageTopic, handler: Callable):
        """Subscribe to a topic."""
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(handler)

    def unsubscribe(self, topic: MessageTopic, handler: Callable):
        """Unsubscribe from a topic."""
        if topic in self.subscribers:
            self.subscribers[topic].remove(handler)

    async def publish(self, topic: MessageTopic, payload: Dict):
        """Publish a message to a topic."""
        import time
        message = Message(
            topic=topic,
            payload=payload,
            timestamp=time.time()
        )

        # Store in history
        self.message_history.append(message)
        if len(self.message_history) > 1000:
            self.message_history = self.message_history[-1000:]

        # Notify subscribers
        handlers = self.subscribers.get(topic, [])
        tasks = []

        for handler in handlers:
            if asyncio.iscoroutinefunction(handler):
                tasks.append(handler(message))
            else:
                # Run sync handler in executor
                tasks.append(asyncio.to_thread(handler, message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def get_history(self, topic: MessageTopic = None, limit: int = 100) -> List[Message]:
        """Get message history."""
        messages = self.message_history
        if topic:
            messages = [m for m in messages if m.topic == topic]
        return messages[-limit:]


# Global message bus
_global_bus: MessageBus = None


def get_message_bus() -> MessageBus:
    """Get the global message bus."""
    global _global_bus
    if _global_bus is None:
        _global_bus = MessageBus()
    return _global_bus
