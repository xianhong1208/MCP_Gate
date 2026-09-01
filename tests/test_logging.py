"""Logging module tests

Coverage:
1. Logging middleware
2. Request logging
"""



class TestLoggingMiddleware:
    """Logging middleware tests"""

    def test_request_logging(self, client):
        """Test that requests are logged"""
        # The health-check request should be logged
        response = client.get("/health")
        assert response.status_code == 200


class TestMiddlewareConfig:
    """Middleware configuration tests"""

    def test_middleware_class_exists(self):
        """Test that the middleware class exists"""
        from src.logging.middleware import RequestLoggingMiddleware

        assert RequestLoggingMiddleware is not None


class TestRequestIdInjection:
    """REQ-LOGGING-03: request-id injection

    generate_request_id() produces an id that can be passed through the request context
    (after set, the same request_id is read back from the context).
    """

    def teardown_method(self):
        from src.logging.logger import clear_request_context

        clear_request_context()

    def test_generate_request_id_produces_id(self):
        """generate_request_id() produces a non-empty string id that differs on every call"""
        from src.logging.logger import generate_request_id

        rid1 = generate_request_id()
        rid2 = generate_request_id()

        assert isinstance(rid1, str)
        assert len(rid1) > 0
        assert rid1 != rid2  # UUID-based, collision probability is negligible

    def test_request_id_carried_by_context(self):
        """After set_request_context sets request_id, the context returns the same value"""
        from src.logging.logger import (
            generate_request_id,
            set_request_context,
            get_request_context,
        )

        rid = generate_request_id()
        set_request_context(request_id=rid)

        ctx = get_request_context()
        assert ctx["request_id"] == rid


class TestRequestContextTracking:
    """REQ-LOGGING-04: request-context tracking via contextvars

    set/get/clear request context work correctly, and the request_context() context
    manager sets on entry and restores on exit.
    """

    def teardown_method(self):
        from src.logging.logger import clear_request_context

        clear_request_context()

    def test_set_and_get_context(self):
        """After set_request_context the values are readable via get_request_context and accumulate"""
        from src.logging.logger import (
            set_request_context,
            get_request_context,
        )

        set_request_context(request_id="abc123", method="GET")
        set_request_context(path="/health")  # should accumulate, not overwrite

        ctx = get_request_context()
        assert ctx["request_id"] == "abc123"
        assert ctx["method"] == "GET"
        assert ctx["path"] == "/health"

    def test_get_context_returns_copy(self):
        """get_request_context returns a copy; external modification does not affect internal state"""
        from src.logging.logger import (
            set_request_context,
            get_request_context,
        )

        set_request_context(request_id="orig")
        ctx = get_request_context()
        ctx["request_id"] = "mutated"

        assert get_request_context()["request_id"] == "orig"

    def test_clear_context(self):
        """clear_request_context empties the context"""
        from src.logging.logger import (
            set_request_context,
            get_request_context,
            clear_request_context,
        )

        set_request_context(request_id="xyz")
        clear_request_context()

        assert get_request_context() == {}

    def test_request_context_manager_sets_and_restores(self):
        """request_context() context manager sets on entry and restores on exit"""
        from src.logging.logger import (
            request_context,
            get_request_context,
        )

        assert get_request_context() == {}

        with request_context(request_id="ctx-1", user="admin"):
            ctx = get_request_context()
            assert ctx["request_id"] == "ctx-1"
            assert ctx["user"] == "admin"

        # Should be restored to empty after exit
        assert get_request_context() == {}


class TestSetupLogging:
    """REQ-LOGGING-05: setup_logging() configures loguru sinks without errors"""

    def test_setup_logging_runs_and_logger_usable(self, tmp_path):
        """Calling setup_logging() does not raise, and the returned logger is usable"""
        from src.logging.logger import setup_logging, get_logger

        # Use a temp directory to avoid polluting the repo's logs/
        setup_logging(level="INFO", format_type="colorized", log_dir=str(tmp_path))

        log = get_logger("test-module")
        # Actually write one log line -- a misconfigured sink would raise here
        log.info("setup_logging colorized smoke test")

        # An app_*.log file should be produced
        assert any(tmp_path.glob("app_*.log"))

    def test_setup_logging_json_sink(self, tmp_path):
        """json format -- goes through the json_sink path; setup and writing do not raise"""
        from src.logging.logger import setup_logging, get_logger

        setup_logging(level="DEBUG", format_type="json", log_dir=str(tmp_path))

        log = get_logger("db")
        log.info("setup_logging json smoke test")

        assert any(tmp_path.glob("app_*.log"))

    def test_json_sink_serializes_record(self, capsys):
        """Feeding a loguru message straight into json_sink outputs valid JSON"""
        import json
        from src.logging.logger import json_sink, logger, clear_request_context

        clear_request_context()
        # Capture the message object with a temporary sink, then hand it to json_sink
        captured = {}

        def _intercept(message):
            captured["msg"] = message

        sink_id = logger.add(_intercept, level="INFO")
        try:
            logger.bind(module="unit").info("json sink direct test")
        finally:
            logger.remove(sink_id)

        assert "msg" in captured
        json_sink(captured["msg"])

        out = capsys.readouterr().err
        payload = json.loads(out.strip().splitlines()[-1])
        assert payload["message"] == "json sink direct test"
        assert payload["level"] == "INFO"


class TestGetLogger:
    """REQ-LOGGING-06: get_logger() returns a bound logger"""

    def test_get_logger_returns_bound_logger(self):
        """With a name, returns a logger bound to that module whose log methods work"""
        from src.logging.logger import get_logger

        log = get_logger("my-module")

        assert log is not None
        # A loguru bound logger has the standard log methods
        assert callable(getattr(log, "info", None))
        assert callable(getattr(log, "error", None))
        # The bound module is stored in the logger's options extra (last element)
        assert log._options[-1].get("module") == "my-module"

    def test_get_logger_without_name_returns_base_logger(self):
        """Without a name, returns the base logger object"""
        from src.logging.logger import get_logger, logger

        log = get_logger()
        assert log is logger
