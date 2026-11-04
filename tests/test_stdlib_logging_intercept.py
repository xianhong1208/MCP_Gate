"""Stdlib logging reaches loguru (#35): uvicorn, APScheduler, SQLAlchemy and our own logging.getLogger users
land in the same sinks (and therefore the log files) as loguru records."""

import logging
import sys

import pytest
from loguru import logger

from src.logging.logger import _ROUTED_LOGGERS, intercept_stdlib_logging


@pytest.fixture
def stdlib_state():
    """Restore the stdlib logging configuration touched by the intercept."""
    names = ["", *_ROUTED_LOGGERS]
    saved = {n: (list(logging.getLogger(n).handlers), logging.getLogger(n).level, logging.getLogger(n).propagate)
             for n in names}
    yield
    for n, (handlers, level, propagate) in saved.items():
        lg = logging.getLogger(n)
        lg.handlers, lg.propagate = handlers, propagate
        lg.setLevel(level)


@pytest.fixture
def captured(stdlib_state):
    """Install the intercept and capture loguru records."""
    records = []
    sink_id = logger.add(lambda m: records.append(m.record), level="DEBUG")
    intercept_stdlib_logging("INFO")
    yield records
    logger.remove(sink_id)


def test_uvicorn_error_record_reaches_loguru(captured):
    logging.getLogger("uvicorn.error").error("Exception in ASGI application")
    rec = next(r for r in captured if r["message"] == "Exception in ASGI application")
    assert rec["level"].name == "ERROR"
    assert rec["extra"]["module"] == "uvicorn.error"
    # Caller frame is the real call site, not logging internals
    assert rec["function"] == "test_uvicorn_error_record_reaches_loguru"


def test_own_stdlib_modules_get_short_module_name(captured):
    logging.getLogger("src.discovery.scanner").warning("scan failed")
    rec = next(r for r in captured if r["message"] == "scan failed")
    assert rec["extra"]["module"] == "discovery.scanner"


def test_apscheduler_warnings_routed_but_info_quiet(captured):
    logging.getLogger("apscheduler.executors.default").info("Running job x")
    logging.getLogger("apscheduler.scheduler").warning("Run time of job was missed")
    messages = [r["message"] for r in captured]
    assert "Running job x" not in messages
    assert "Run time of job was missed" in messages


def test_uvicorn_access_does_not_duplicate_request_logging(captured):
    logging.getLogger("uvicorn.access").info('127.0.0.1 - "GET / HTTP/1.1" 200')
    assert not any("HTTP/1.1" in r["message"] for r in captured)


def test_sqlalchemy_does_not_echo_sql(captured):
    assert not logging.getLogger("sqlalchemy.engine.Engine").isEnabledFor(logging.INFO)
    logging.getLogger("sqlalchemy.pool").warning("pool overflow")
    rec = next(r for r in captured if r["message"] == "pool overflow")
    assert rec["extra"]["module"].startswith("db.")


def test_exception_info_is_forwarded(captured):
    try:
        raise ValueError("bad")
    except ValueError:
        logging.getLogger("uvicorn.error").exception("boom")
    rec = next(r for r in captured if r["message"] == "boom")
    assert rec["exception"] is not None and rec["exception"].type is ValueError


def test_setup_logging_writes_stdlib_records_to_files(tmp_path, stdlib_state):
    from src.logging.logger import setup_logging

    try:
        setup_logging(level="INFO", format_type="json", log_dir=str(tmp_path), compression=None)
        logging.getLogger("uvicorn.error").warning("stdlib line for the file")
        logger.complete()
    finally:
        # setup_logging replaced every loguru sink; put back loguru's default one
        logger.remove()
        logger.add(sys.stderr)
    app_logs = list(tmp_path.glob("app_*.log"))
    assert app_logs and "stdlib line for the file" in app_logs[0].read_text()
