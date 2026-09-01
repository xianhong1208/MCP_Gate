"""Rate limiter tests

Coverage:
1. Sliding-window rate limiting
2. IP whitelist
3. Path-specific limits
"""

import pytest


class TestSlidingWindowCounter:
    """Sliding-window counter tests"""

    def test_counter_initialization(self):
        """Test counter initialization."""
        from src.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_size=60)
        assert counter.window_size == 60

    def test_add_request(self):
        """Test recording requests."""
        from src.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_size=60)

        count = counter.add_request("test_ip")
        assert count == 1

        count = counter.add_request("test_ip")
        assert count == 2

    def test_different_keys_independent(self):
        """Test that different keys are counted independently."""
        from src.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_size=60)

        counter.add_request("ip1")
        counter.add_request("ip1")
        counter.add_request("ip2")

        assert counter.get_count("ip1") == 2
        assert counter.get_count("ip2") == 1

    def test_cleanup(self):
        """Test cleanup."""
        from src.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_size=60)
        counter.add_request("test_ip")

        # cleanup should not raise
        counter.cleanup()

    def test_hour_window_counter_accumulates(self):
        """Test that the hourly window counter accumulates (REQ-RATE-LIMITER-13).

        Simulates the hourly counter with a 3600-second window and verifies that consecutive requests
        accumulate and exceed a small limit.
        """
        from src.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_size=3600)
        hour_limit = 3

        # The first hour_limit requests should not exceed the limit
        for expected in range(1, hour_limit + 1):
            assert counter.add_request("hour_ip") == expected

        # One more request exceeds the hourly limit
        assert counter.add_request("hour_ip") == hour_limit + 1
        assert counter.get_count("hour_ip") > hour_limit


class TestRateLimitConfig:
    """Rate limit configuration tests"""

    def test_config_defaults(self):
        """Test configuration defaults."""
        from src.middleware.rate_limiter import RateLimitConfig

        config = RateLimitConfig()

        assert config.requests_per_minute == 60
        assert config.requests_per_hour == 1000
        assert config.enabled is True
        assert "127.0.0.1" in config.whitelist

    def test_config_custom_values(self):
        """Test custom configuration values."""
        from src.middleware.rate_limiter import RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=30,
            requests_per_hour=500,
            whitelist=["192.168.1.1"]
        )

        assert config.requests_per_minute == 30
        assert config.requests_per_hour == 500
        assert "192.168.1.1" in config.whitelist

    def test_config_path_limits(self):
        """Test path-specific limits."""
        from src.middleware.rate_limiter import RateLimitConfig

        config = RateLimitConfig(
            path_limits={
                "/admin/login": 10,
                "/auth/token": 30
            }
        )

        assert config.path_limits["/admin/login"] == 10
        assert config.path_limits["/auth/token"] == 30


class TestIPWhitelist:
    """IP whitelist tests"""

    def test_ip_in_whitelist_direct_match(self):
        """Test direct IP matching."""
        from src.middleware.rate_limiter import is_ip_in_whitelist

        whitelist = ["127.0.0.1", "192.168.1.1"]

        assert is_ip_in_whitelist("127.0.0.1", whitelist) is True
        assert is_ip_in_whitelist("192.168.1.1", whitelist) is True
        assert is_ip_in_whitelist("10.0.0.1", whitelist) is False

    def test_ip_in_whitelist_cidr(self):
        """Test CIDR matching."""
        from src.middleware.rate_limiter import is_ip_in_whitelist

        whitelist = ["192.168.1.0/24"]

        assert is_ip_in_whitelist("192.168.1.1", whitelist) is True
        assert is_ip_in_whitelist("192.168.1.100", whitelist) is True
        assert is_ip_in_whitelist("192.168.2.1", whitelist) is False

    def test_ip_in_whitelist_localhost(self):
        """Test localhost handling."""
        from src.middleware.rate_limiter import is_ip_in_whitelist

        whitelist = ["localhost", "127.0.0.1"]

        assert is_ip_in_whitelist("localhost", whitelist) is True
        assert is_ip_in_whitelist("127.0.0.1", whitelist) is True


class TestRateLimiter:
    """Rate limiter tests"""

    def test_limiter_initialization(self):
        """Test limiter initialization."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(requests_per_minute=60)
        limiter = RateLimiter(config)

        assert limiter.config.requests_per_minute == 60

    @pytest.mark.asyncio
    async def test_limiter_allows_whitelisted_ip(self):
        """Test that whitelisted IPs are allowed."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=1,
            whitelist=["127.0.0.1"]
        )
        limiter = RateLimiter(config)

        # Whitelisted IPs should always be allowed
        allowed, reason, retry_after = await limiter.is_allowed("127.0.0.1")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_limiter_blocks_after_limit(self):
        """Test blocking after the limit is exceeded."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=2,
            whitelist=[]  # Clear the whitelist
        )
        limiter = RateLimiter(config)

        # The first two should pass
        allowed1, _, _ = await limiter.is_allowed("10.0.0.1")
        allowed2, _, _ = await limiter.is_allowed("10.0.0.1")
        assert allowed1 is True
        assert allowed2 is True

        # The third should be blocked
        allowed3, reason, _ = await limiter.is_allowed("10.0.0.1")
        assert allowed3 is False
        assert "rate_limit" in reason

    @pytest.mark.asyncio
    async def test_limiter_blocks_after_hour_limit(self):
        """Test blocking after the hourly limit is exceeded (REQ-RATE-LIMITER-13).

        The per-minute limit is set very generously and the hourly limit very small, so requests trip
        the hourly limit before the per-minute one; verifies that exceeding the hourly limit returns
        rate_limit_hour.
        """
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=100,  # Generous minute limit so it is not hit first
            requests_per_hour=3,       # Only 3 requests allowed per hour
            whitelist=[]               # Clear the whitelist
        )
        limiter = RateLimiter(config)

        # The first 3 should pass (hourly limit not exceeded)
        for _ in range(3):
            allowed, _, _ = await limiter.is_allowed("10.0.0.9")
            assert allowed is True

        # The 4th exceeds the hourly limit and should be blocked with rate_limit_hour
        allowed, reason, retry_after = await limiter.is_allowed("10.0.0.9")
        assert allowed is False
        assert reason == "rate_limit_hour"
        assert retry_after > 0

    @pytest.mark.asyncio
    async def test_limiter_disabled(self):
        """Test a disabled limiter."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            enabled=False,
            requests_per_minute=1
        )
        limiter = RateLimiter(config)

        # Should be allowed even beyond the limit
        for _ in range(10):
            allowed, _, _ = await limiter.is_allowed("10.0.0.1")
            assert allowed is True

    @pytest.mark.asyncio
    async def test_limiter_path_specific_limit(self):
        """Test path-specific limits."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=100,
            path_limits={"/admin/login": 2},
            whitelist=[]
        )
        limiter = RateLimiter(config)

        # The /admin/login path has a limit of 2
        await limiter.is_allowed("10.0.0.2", "/admin/login")
        await limiter.is_allowed("10.0.0.2", "/admin/login")
        allowed, _, _ = await limiter.is_allowed("10.0.0.2", "/admin/login")
        assert allowed is False


class TestRateLimiterSingleton:
    """Rate limiter singleton tests"""

    def test_get_instance(self):
        """Test getting the singleton instance."""
        from src.middleware.rate_limiter import RateLimiter, RateLimitConfig

        # Reset first
        RateLimiter.reset_instance()

        config = RateLimitConfig(requests_per_minute=100)
        instance1 = RateLimiter.get_instance(config)
        instance2 = RateLimiter.get_instance()

        assert instance1 is instance2

        # Clean up
        RateLimiter.reset_instance()


class TestRateLimitIntegration:
    """Rate limiting integration tests"""

    def test_api_rate_limit(self, client, db_session):
        """Test API rate limiting."""
        # The health check endpoint should be accessible
        response = client.get("/health")
        assert response.status_code == 200
