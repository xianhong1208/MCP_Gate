"""Exception Handlers for FastAPI"""

from fastapi import Request
from fastapi.responses import JSONResponse

from src.exceptions.base import MCPCenterError
from src.logging import get_logger

logger = get_logger("exceptions")


async def mcp_center_exception_handler(
    request: Request,
    exc: MCPCenterError
) -> JSONResponse:
    """Handle MCPCenterError exceptions

    Converts our custom exceptions to proper JSON responses.
    """
    logger.warning(
        f"MCPCenterError: {exc.code}",
        error_code=exc.code,
        error_message=exc.message,
        path=request.url.path,
        method=request.method,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


def register_exception_handlers(app):
    """Register all exception handlers with the FastAPI app

    Usage:
        app = FastAPI()
        register_exception_handlers(app)
    """
    app.add_exception_handler(MCPCenterError, mcp_center_exception_handler)
