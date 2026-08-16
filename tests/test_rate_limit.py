import pytest

from app.security.rate_limit import LoginRateLimiter, RateLimitExceeded


def test_rate_limit_blocks_after_threshold() -> None:
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
    key = "127.0.0.1:alice"
    for _ in range(3):
        limiter.check(key)
        limiter.register_failure(key)
    with pytest.raises(RateLimitExceeded):
        limiter.check(key)
    limiter.register_success(key)
    limiter.check(key)
