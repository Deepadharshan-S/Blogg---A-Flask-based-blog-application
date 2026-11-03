"""Tests for distributed rate limiting and configuration validation (BLOGG-SEC-017).

Verifies:
- Safe sanitization of Redis URIs (no password exposure in logs).
- Production configuration validation for rate limit backends.
- Rejection of invalid storage schemes.
- Support for Redis and Rediss storage backends in Flask-Limiter.
- Fail-safe operation: graceful in-memory degradation on Redis disconnection.
- Fail-closed configurable behavior when swallow_errors is disabled.
"""

import os
from unittest.mock import patch

from app import create_app, db
from config import sanitize_redis_uri
from tests.iam_base import IAMTestCase


class DistributedRateLimitingTestCase(IAMTestCase):
    def test_sanitize_redis_uri(self):
        """Ensure Redis URI passwords are sanitized for logging."""
        self.assertEqual(
            sanitize_redis_uri("redis://:secret123@10.0.0.1:6379/0"),
            "redis://:***@10.0.0.1:6379/0",
        )
        self.assertEqual(
            sanitize_redis_uri("rediss://admin:p@ssword@cluster.redis.cache:6380/1"),
            "rediss://admin:***@cluster.redis.cache:6380/1",
        )
        self.assertEqual(
            sanitize_redis_uri("redis://localhost:6379/0"),
            "redis://localhost:6379/0",
        )
        self.assertEqual(sanitize_redis_uri("memory://"), "memory://")

    def test_production_config_rate_limit_validation(self):
        """Ensure ProductionConfig validates RATELIMIT_STORAGE_URI schemes appropriately."""
        prod_env = {
            "SECRET_KEY": "super-secret-prod-key",
            "BLOGG_MFA_ENCRYPTION_KEY": "YmxvZ2ctdGVzdC1tZmEtZW5jcnlwdGlvbi1rZXktMzI=",
        }

        # 1. Valid Redis URI is accepted
        with patch.dict(
            os.environ, {**prod_env, "RATELIMIT_STORAGE_URI": "redis://:secret@localhost:6379/0"}
        ):
            app = create_app("production")
            self.assertEqual(
                app.config["RATELIMIT_STORAGE_URI"], "redis://:secret@localhost:6379/0"
            )

        # 2. In-memory storage in production logs warning about multi-worker isolation
        with patch.dict(os.environ, {**prod_env, "RATELIMIT_STORAGE_URI": "memory://"}):
            with patch("logging.Logger.warning") as mock_warn:
                create_app("production")
                warnings = [c[0][0] for c in mock_warn.call_args_list if c[0]]
                self.assertTrue(
                    any("memory://" in w and "multi-worker" in w.lower() for w in warnings)
                )

        # 3. Unsupported scheme raises ValueError
        with patch.dict(os.environ, {**prod_env, "RATELIMIT_STORAGE_URI": "ftp://bad-storage"}):
            with self.assertRaises(ValueError) as ctx:
                create_app("production")
            self.assertIn("Unsupported RATELIMIT_STORAGE_URI scheme", str(ctx.exception))

    def test_redis_limiter_initialization(self):
        """Ensure Limiter initializes with RedisStorage when RATELIMIT_STORAGE_URI is configured."""
        from limits.storage.redis import RedisStorage

        with patch.dict(os.environ, {"RATELIMIT_STORAGE_URI": "redis://127.0.0.1:6379/0"}):
            app = create_app("testing")
            self.assertIsNotNone(app)
            from app import limiter

            self.assertIsInstance(limiter._storage, RedisStorage)

    def test_redis_connection_failure_failsafe_degraded_operation(self):
        """Ensure unreachable Redis degrades to local in-memory fallback without 500 error."""
        with patch.dict(
            os.environ,
            {
                "RATELIMIT_STORAGE_URI": "redis://127.0.0.1:59998",
                "BLOGG_REDIS_CONNECT_TIMEOUT": "0.1",
                "BLOGG_REDIS_SOCKET_TIMEOUT": "0.1",
                "RATELIMIT_SWALLOW_ERRORS": "true",
                "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED": "true",
            },
        ):
            app = create_app("testing")
            with app.app_context():
                db.create_all()

            client = app.test_client()

            # Requests succeed without 500 Internal Server Error
            res1 = client.get("/auth/login")
            self.assertEqual(res1.status_code, 200)

    def test_redis_connection_failure_fail_closed_configurable(self):
        """Ensure when RATELIMIT_SWALLOW_ERRORS is false, storage errors raise."""
        with patch.dict(
            os.environ,
            {
                "RATELIMIT_STORAGE_URI": "redis://127.0.0.1:59997",
                "BLOGG_REDIS_CONNECT_TIMEOUT": "0.1",
                "BLOGG_REDIS_SOCKET_TIMEOUT": "0.1",
                "RATELIMIT_SWALLOW_ERRORS": "false",
                "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED": "false",
            },
        ):
            app = create_app("testing")
            app.config["TESTING"] = False
            with app.app_context():
                db.create_all()

            client = app.test_client()
            # Under fail-closed mode, unreachable Redis causes route evaluation to fail with 500
            res = client.get("/auth/login")
            self.assertEqual(res.status_code, 500)
