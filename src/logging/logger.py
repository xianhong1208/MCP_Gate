"""Structured Logger Configuration

Provides JSON-formatted logging for production and colorized output for development.
Includes request context tracking via context variables.
"""

import sys
import json
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
