from security.rate_limiter import RateLimiter
def test_rate_limit():
    r=RateLimiter(1);assert r.allow('x');assert not r.allow('x')
