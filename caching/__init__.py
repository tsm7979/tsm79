"""
TSM Layer - Caching Module
Provides multi-level caching for LLM responses, embeddings, and metadata.
"""

import json
import hashlib
import time
from typing import Any, Optional, Dict
from pathlib import Path
import pickle


class CacheBackend:
    """Base cache backend interface."""

    def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        raise NotImplementedError

    def clear(self) -> bool:
        raise NotImplementedError


class InMemoryCache(CacheBackend):
    """Fast in-memory cache with TTL support."""

    def __init__(self):
        self._cache: Dict[str, tuple] = {}  # key -> (value, expiry_time)

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry > time.time():
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        expiry = time.time() + ttl
        self._cache[key] = (value, expiry)
        return True

    def delete(self, key: str) -> bool:
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self) -> bool:
        self._cache.clear()
        return True

    def cleanup_expired(self):
        """Remove expired entries."""
        now = time.time()
        expired_keys = [k for k, (_, expiry) in self._cache.items() if expiry <= now]
        for key in expired_keys:
            del self._cache[key]


class FileCache(CacheBackend):
    """Persistent file-based cache."""

    def __init__(self, cache_dir: str = "~/.tsm/cache"):
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, key: str) -> Path:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"

    def get(self, key: str) -> Optional[Any]:
        path = self._get_path(key)
        if path.exists():
            try:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                    expiry = data.get('expiry', 0)
                    if expiry > time.time():
                        return data.get('value')
                    else:
                        path.unlink()  # Delete expired
            except Exception:
                pass
        return None

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        path = self._get_path(key)
        try:
            data = {
                'value': value,
                'expiry': time.time() + ttl,
                'created': time.time()
            }
            with open(path, 'wb') as f:
                pickle.dump(data, f)
            return True
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        path = self._get_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def clear(self) -> bool:
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
        return True


class MultiLevelCache:
    """
    Multi-level caching with L1 (memory) and L2 (disk).
    Optimized for LLM response caching.
    """

    def __init__(self):
        self.l1 = InMemoryCache()
        self.l2 = FileCache()
        self._stats = {
            'l1_hits': 0,
            'l2_hits': 0,
            'misses': 0,
            'sets': 0
        }

    def get(self, key: str) -> Optional[Any]:
        # Try L1 (memory) first
        value = self.l1.get(key)
        if value is not None:
            self._stats['l1_hits'] += 1
            return value

        # Try L2 (disk)
        value = self.l2.get(key)
        if value is not None:
            self._stats['l2_hits'] += 1
            # Promote to L1
            self.l1.set(key, value, ttl=3600)
            return value

        self._stats['misses'] += 1
        return None

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        self._stats['sets'] += 1
        # Set in both levels
        self.l1.set(key, value, ttl)
        self.l2.set(key, value, ttl)
        return True

    def delete(self, key: str) -> bool:
        self.l1.delete(key)
        self.l2.delete(key)
        return True

    def clear(self) -> bool:
        self.l1.clear()
        self.l2.clear()
        return True

    def get_stats(self) -> Dict:
        """Get cache performance statistics."""
        total_reads = self._stats['l1_hits'] + self._stats['l2_hits'] + self._stats['misses']
        hit_rate = 0.0
        if total_reads > 0:
            hit_rate = (self._stats['l1_hits'] + self._stats['l2_hits']) / total_reads

        return {
            **self._stats,
            'total_reads': total_reads,
            'hit_rate': hit_rate
        }


class LLMResponseCache:
    """Specialized cache for LLM responses with prompt hashing."""

    def __init__(self):
        self.cache = MultiLevelCache()

    def _make_key(self, model: str, prompt: str, **kwargs) -> str:
        """Create cache key from model, prompt, and parameters."""
        key_parts = [model, prompt]
        for k in sorted(kwargs.keys()):
            key_parts.append(f"{k}={kwargs[k]}")
        key_str = "|".join(key_parts)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get_response(self, model: str, prompt: str, **kwargs) -> Optional[str]:
        """Get cached LLM response."""
        key = self._make_key(model, prompt, **kwargs)
        return self.cache.get(key)

    def set_response(self, model: str, prompt: str, response: str, ttl: int = 3600, **kwargs) -> bool:
        """Cache LLM response."""
        key = self._make_key(model, prompt, **kwargs)
        return self.cache.set(key, response, ttl)

    def get_stats(self) -> Dict:
        """Get cache statistics."""
        return self.cache.get_stats()


# Global cache instance
_global_cache = LLMResponseCache()


def get_cache() -> LLMResponseCache:
    """Get the global LLM response cache."""
    return _global_cache
