from __future__ import annotations

import time
from collections import deque


class RateLimitError(PermissionError):
    pass


class SlidingWindowRateLimiter:
    def __init__(self, max_calls_per_minute: int) -> None:
        self.max_calls_per_minute = max_calls_per_minute
        self.calls: dict[str, deque[float]] = {}

    def check(self, key: str) -> None:
        now = time.time()
        q = self.calls.setdefault(key, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.max_calls_per_minute:
            raise RateLimitError("RATE_LIMIT_EXCEEDED")
        q.append(now)
