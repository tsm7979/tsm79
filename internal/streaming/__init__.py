"""
TSM Layer - Streaming
Real-time streaming responses for LLM completions.
"""

import asyncio
from typing import AsyncIterator, Callable, Dict, Optional
from dataclasses import dataclass


@dataclass
class StreamChunk:
    """Streaming response chunk."""
    content: str
    is_final: bool = False
    metadata: Dict = None


class StreamManager:
    """Manages streaming LLM responses."""

    def __init__(self):
        self.active_streams: Dict[str, asyncio.Queue] = {}

    async def create_stream(self, stream_id: str) -> asyncio.Queue:
        """Create a new stream queue."""
        queue = asyncio.Queue()
        self.active_streams[stream_id] = queue
        return queue

    async def write_chunk(self, stream_id: str, chunk: StreamChunk):
        """Write a chunk to the stream."""
        if stream_id in self.active_streams:
            await self.active_streams[stream_id].put(chunk)

    async def close_stream(self, stream_id: str):
        """Close a stream."""
        if stream_id in self.active_streams:
            # Send final chunk
            await self.write_chunk(stream_id, StreamChunk(content="", is_final=True))
            del self.active_streams[stream_id]

    async def read_stream(self, stream_id: str) -> AsyncIterator[StreamChunk]:
        """Read chunks from a stream."""
        if stream_id not in self.active_streams:
            return

        queue = self.active_streams[stream_id]

        while True:
            chunk = await queue.get()
            yield chunk

            if chunk.is_final:
                break


# Global stream manager
_global_streaming: Optional[StreamManager] = None


def get_stream_manager() -> StreamManager:
    """Get the global stream manager."""
    global _global_streaming
    if _global_streaming is None:
        _global_streaming = StreamManager()
    return _global_streaming
