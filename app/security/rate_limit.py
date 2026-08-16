from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(RuntimeError):
    pass


class LoginRateLimiter:
    """In-memory limiter suitable for a single-process educational deployment."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        attempts = self._attempts[key]
        threshold = now - self.window_seconds
        while attempts and attempts[0] < threshold:
            attempts.popleft()
        return attempts

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._prune(key, now)
            if len(attempts) >= self.max_attempts:
                retry_after = max(1, int(self.window_seconds - (now - attempts[0])))
                raise RateLimitExceeded(str(retry_after))

    def register_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._prune(key, now)
            attempts.append(now)

    def register_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
