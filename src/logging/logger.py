"""Structured Logger Configuration

Provides JSON-formatted logging for production and colorized output for development.
Includes request context tracking via context variables.
"""

import sys
import json
import logging
import uuid
from typing import Optional
from contextvars import ContextVar

from loguru import logger

# Context variable for request tracking
_request_context: ContextVar[dict] = ContextVar("request_context", default={})


class LogContext:
    """Context manager for adding context to log messages"""

    def __init__(self, **kwargs):
        self.context = kwargs
        self.token = None

    def __enter__(self):
        current = _request_context.get().copy()
        current.update(self.context)
        self.token = _request_context.set(current)
        return self

    def __exit__(self, *args):
        if self.token:
            _request_context.reset(self.token)


def request_context(**kwargs) -> LogContext:
    """Create a log context with request information

    Usage:
        with request_context(request_id="abc", user="admin"):
            logger.info("Processing request")
    """
    return LogContext(**kwargs)


def set_request_context(**kwargs):
    """Set request context without context manager"""
    current = _request_context.get().copy()
    current.update(kwargs)
    _request_context.set(current)


def get_request_context() -> dict:
    """Get current request context"""
    return _request_context.get().copy()


def clear_request_context():
    """Clear request context"""
    _request_context.set({})


def generate_request_id() -> str:
    """Generate a unique request ID"""
    return str(uuid.uuid4())[:8]


def json_sink(message):
    """Sink function for JSON output"""
    record = message.record
    context = _request_context.get()

    log_entry = {
        "timestamp": record["time"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "level": record["level"].name,
        "message": record["message"],
        "module": record["module"],
        "function": record["function"],
        "line": record["line"],
    }

    # Add request context
    if context:
        log_entry["context"] = context

    # Add extra fields from record
    if record.get("extra"):
        for key, value in record["extra"].items():
            if key not in ("request_id",):  # Skip internal keys
                log_entry[key] = value

    # Add exception info if present
    if record["exception"]:
        log_entry["exception"] = {
            "type": record["exception"].type.__name__ if record["exception"].type else None,
            "value": str(record["exception"].value) if record["exception"].value else None,
        }

    sys.stderr.write(json.dumps(log_entry, default=str, ensure_ascii=False) + "\n")


def colorized_format(record: dict) -> str:
    """Format string for colorized output"""
    context = _request_context.get()

    # Build context string
    ctx_str = ""
    if context:
        ctx_parts = [f"{k}={v}" for k, v in context.items()]
        ctx_str = f" <yellow>[{', '.join(ctx_parts)}]</yellow>"

    # Format template
    fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan>"
        + ctx_str +
        " - <level>{message}</level>\n"
    )

    if record["exception"]:
        fmt += "{exception}\n"

    return fmt


# Category rules: which files a module name (from get_logger(name)) maps to.
# Ordered from narrow to wide (more specific rules first), but in practice every record passes through every sink
# (each sink decides for itself whether to write), so one log line may land in app.log + http.log + error.log at once
LOG_CATEGORIES = {
    # category_name → (filter_fn, level_override or None)
    "http":  (lambda m: m == "http", None),
    "auth":  (lambda m: m.startswith("auth") or m == "security", None),
    "db":    (lambda m: m.startswith("db"), None),
}

_FILE_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
    "{extra[module]}:{function}:{line} - {message}"
)


def _make_module_filter(predicate):
    """Build a loguru filter that matches by extra['module']"""
    def filter_fn(record):
        module = record["extra"].get("module", "")
        return predicate(module)
    return filter_fn


class InterceptHandler(logging.Handler):
    """Stdlib ``logging`` handler that forwards every record to loguru.

    Installed on the root logger, so uvicorn, APScheduler, SQLAlchemy and the modules here that still use
    ``logging.getLogger(__name__)`` end up in the same console + category files as everything else.
    The stdlib logger name becomes ``extra['module']`` (``src.`` prefix dropped; SQLAlchemy is filed
    under ``db.`` so it lands in the db category).
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Walk back to the frame that called the stdlib logger, so {function}/{line} point at real code
        frame, depth = sys._getframe(0), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1

        logger.bind(module=_stdlib_module_name(record.name)).opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def _stdlib_module_name(name: str) -> str:
    if name.startswith("src."):
        return name[len("src."):]
    if name == "sqlalchemy" or name.startswith("sqlalchemy."):
        return "db." + name
    return name


# Third-party loggers routed into loguru, with a floor level for the chatty ones.
#   uvicorn.access: RequestLoggingMiddleware already writes one line per request (with request id and timing),
#                   so uvicorn's own access line would only duplicate it.
#   sqlalchemy:     INFO on sqlalchemy.engine means "echo every SQL statement" -- never implicitly.
#   apscheduler:    INFO is a line per job run (health checks run every few seconds).
#   httpx/httpcore: INFO is a line per outgoing request (health probes, scans).
_ROUTED_LOGGERS = {
    "uvicorn": None,
    "uvicorn.error": None,
    "uvicorn.asgi": None,
    "uvicorn.access": logging.WARNING,
    "apscheduler": logging.WARNING,
    "sqlalchemy": logging.WARNING,
    "alembic": None,
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
}


def intercept_stdlib_logging(level: str = "INFO") -> None:
    """Route stdlib ``logging`` (root logger and the known third-party loggers) into loguru."""
    root = logging.getLogger()
    root.handlers = [InterceptHandler()]
    root.setLevel(level.upper() if isinstance(level, str) else level)

    for name, floor in _ROUTED_LOGGERS.items():
        lib_logger = logging.getLogger(name)
        lib_logger.handlers = []
        lib_logger.propagate = True
        lib_logger.setLevel(floor if floor is not None else logging.NOTSET)


def setup_logging(
    level: str = "INFO",
    format_type: str = "colorized",
    log_dir: str = "logs",
    rotation: str = "00:00",
    rotation_max_size: str = "50 MB",
    retention: str = "60 days",
    compression: str = "zip",
):
    """Setup logging configuration with category-based file splits.

    Files produced (assuming log_dir="logs"):
        logs/app_YYYY-MM-DD.log     everything INFO+
        logs/http_YYYY-MM-DD.log    HTTP requests
        logs/auth_YYYY-MM-DD.log    authentication / authorization / security
        logs/db_YYYY-MM-DD.log      database operations
        logs/error_YYYY-MM-DD.log   all ERROR+ (cross-module safety net)

    Rotation: daily at 00:00; kept for `retention`; old files are compressed automatically.

    Args:
        level: default level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
        format_type: console format -- "json" or "colorized"
        log_dir: directory for the category log files
        rotation: loguru rotation condition, e.g. "00:00" / "1 day" / "100 MB"
        rotation_max_size: reserved (combined time+size rotation, currently unused)
        retention: retention period, e.g. "60 days"
        compression: compression for old files -- "zip" / "gz" / "bz2" / None
    """
    # Remove default handler
    logger.remove()

    # Global extra defaults -- so that someone using `from loguru import logger` directly without binding a module
    # does not hit a KeyError on `{extra[module]}`
    logger.configure(extra={"module": "unknown"})

    # ---- Console sink ----
    if format_type == "json":
        logger.add(json_sink, level=level, colorize=False)
    else:
        logger.add(sys.stderr, format=colorized_format, level=level, colorize=True)

    # ---- File sinks ----
    from pathlib import Path
    dir_path = Path(log_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    # Rotation policy: switch files daily at 00:00 (rotation_max_size is reserved; loguru's public API does not
    # support a "time OR size" combined condition, and combining them needs a callable + private API, which is too
    # fragile, so plain time-based rotation is enough for now. A single-day blow-up is extremely rare; if it must be
    # guarded against, drop to "12:00" for half-day rotation)
    del rotation_max_size  # explicitly mark as unused to keep lint quiet

    # The "everything" aggregate file
    logger.add(
        str(dir_path / "app_{time:YYYY-MM-DD}.log"),
        format=_FILE_FORMAT,
        level=level,
        rotation=rotation,
        retention=retention,
        compression=compression,
        enqueue=True,  # non-blocking -- required with multiple sinks so IO does not stall the main thread
    )

    # Category files
    for cat_name, (filter_pred, level_override) in LOG_CATEGORIES.items():
        logger.add(
            str(dir_path / f"{cat_name}_{{time:YYYY-MM-DD}}.log"),
            format=_FILE_FORMAT,
            level=level_override or level,
            filter=_make_module_filter(filter_pred),
            rotation=rotation,
            retention=retention,
            compression=compression,
            enqueue=True,
        )

    # Cross-module ERROR safety net -- an ERROR from any module lands here
    logger.add(
        str(dir_path / "error_{time:YYYY-MM-DD}.log"),
        format=_FILE_FORMAT,
        level="ERROR",
        rotation=rotation,
        retention=retention,
        compression=compression,
        enqueue=True,
        backtrace=True,
        diagnose=True,  # ERRORs include variable values, which makes debugging much faster
    )

    # ---- Stdlib logging (uvicorn, APScheduler, SQLAlchemy, ...) -> loguru ----
    intercept_stdlib_logging(level)

    logger.bind(module="logger").info(
        f"Logging configured: level={level}, format={format_type}, "
        f"log_dir={log_dir}, rotation={rotation}, retention={retention}"
    )


def get_logger(name: Optional[str] = None):
    """Get a logger instance

    Args:
        name: Optional module name for the logger

    Returns:
        Logger instance bound with the module name
    """
    if name:
        return logger.bind(module=name)
    return logger


# Convenience exports
log = logger
