"""
TSM Layer - Queue Module
Asynchronous task queue for long-running operations.
"""

import asyncio
import json
import time
import uuid
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Queued task representation."""
    id: str
    name: str
    payload: Dict[str, Any]
    status: TaskStatus
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    priority: int = 0  # Higher = more important

    def to_dict(self) -> Dict:
        data = asdict(self)
        data['status'] = self.status.value
        return data


class TaskQueue:
    """
    In-memory task queue with priority support.
    Suitable for single-node deployments.
    For production, use Redis/RabbitMQ.
    """

    def __init__(self):
        self._queue: List[Task] = []
        self._tasks: Dict[str, Task] = {}
        self._handlers: Dict[str, Callable] = {}
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    def register_handler(self, task_name: str, handler: Callable):
        """Register a handler function for a task type."""
        self._handlers[task_name] = handler

    def enqueue(self, task_name: str, payload: Dict[str, Any], priority: int = 0) -> str:
        """Add a task to the queue."""
        task = Task(
            id=str(uuid.uuid4()),
            name=task_name,
            payload=payload,
            status=TaskStatus.PENDING,
            created_at=time.time(),
            priority=priority
        )

        self._queue.append(task)
        self._tasks[task.id] = task

        # Sort by priority (descending)
        self._queue.sort(key=lambda t: t.priority, reverse=True)

        return task.id

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID."""
        return self._tasks.get(task_id)

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        task = self._tasks.get(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            self._queue.remove(task)
            return True
        return False

    async def _process_task(self, task: Task):
        """Process a single task."""
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()

        handler = self._handlers.get(task.name)
        if not handler:
            task.status = TaskStatus.FAILED
            task.error = f"No handler registered for task '{task.name}'"
            task.completed_at = time.time()
            return

        try:
            # Execute handler
            if asyncio.iscoroutinefunction(handler):
                result = await handler(task.payload)
            else:
                result = handler(task.payload)

            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()

        except Exception as e:
            task.retries += 1
            if task.retries < task.max_retries:
                # Retry
                task.status = TaskStatus.PENDING
                self._queue.append(task)
            else:
                # Failed permanently
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.completed_at = time.time()

    async def _worker(self):
        """Background worker that processes tasks."""
        while self._running:
            if self._queue:
                task = self._queue.pop(0)
                await self._process_task(task)
            else:
                await asyncio.sleep(0.1)  # Wait for tasks

    def start(self):
        """Start the queue worker."""
        if not self._running:
            self._running = True
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self):
        """Stop the queue worker."""
        self._running = False
        if self._worker_task:
            await self._worker_task

    def get_stats(self) -> Dict:
        """Get queue statistics."""
        pending = sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)
        running = sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)
        completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)

        return {
            'total_tasks': len(self._tasks),
            'pending': pending,
            'running': running,
            'completed': completed,
            'failed': failed,
            'queue_depth': len(self._queue)
        }


class PersistentQueue(TaskQueue):
    """Task queue with disk persistence."""

    def __init__(self, queue_file: str = "~/.tsm/queue.jsonl"):
        super().__init__()
        self.queue_file = Path(queue_file).expanduser()
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        self._load_queue()

    def _load_queue(self):
        """Load queue from disk."""
        if self.queue_file.exists():
            with open(self.queue_file, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    task = Task(
                        id=data['id'],
                        name=data['name'],
                        payload=data['payload'],
                        status=TaskStatus(data['status']),
                        created_at=data['created_at'],
                        started_at=data.get('started_at'),
                        completed_at=data.get('completed_at'),
                        result=data.get('result'),
                        error=data.get('error'),
                        retries=data.get('retries', 0),
                        priority=data.get('priority', 0)
                    )
                    self._tasks[task.id] = task
                    if task.status == TaskStatus.PENDING:
                        self._queue.append(task)

    def _save_queue(self):
        """Save queue to disk."""
        with open(self.queue_file, 'w') as f:
            for task in self._tasks.values():
                f.write(json.dumps(task.to_dict()) + '\n')

    def enqueue(self, task_name: str, payload: Dict[str, Any], priority: int = 0) -> str:
        task_id = super().enqueue(task_name, payload, priority)
        self._save_queue()
        return task_id

    async def _process_task(self, task: Task):
        await super()._process_task(task)
        self._save_queue()


# Global queue instance
_global_queue = PersistentQueue()


def get_queue() -> PersistentQueue:
    """Get the global task queue."""
    return _global_queue


async def enqueue_task(task_name: str, payload: Dict[str, Any], priority: int = 0) -> str:
    """Enqueue a task for async processing."""
    queue = get_queue()
    return queue.enqueue(task_name, payload, priority)


async def get_task_status(task_id: str) -> Optional[Dict]:
    """Get the status of a task."""
    queue = get_queue()
    task = queue.get_task(task_id)
    if task:
        return task.to_dict()
    return None
