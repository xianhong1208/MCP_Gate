"""Exception handling tests

Coverage:
1. Auth exceptions
2. Database exceptions
3. Service exceptions
4. Base exceptions
"""



class TestAuthExceptions:
    """Auth exception tests"""

    def test_authentication_error(self):
        """Test the authentication error exception"""
        from src.exceptions.auth import AuthenticationError

        exc = AuthenticationError("Authentication failed")
        assert exc.status_code == 401
        assert exc.code == "AUTHENTICATION_ERROR"

    def test_invalid_credentials_error(self):
        """Test the invalid credentials exception"""
        from src.exceptions.auth import InvalidCredentialsError

        exc = InvalidCredentialsError()
        assert exc.status_code == 401

    def test_token_expired_error(self):
        """Test the token expired exception"""
        from src.exceptions.auth import TokenExpiredError

        exc = TokenExpiredError(expired_at="2024-01-01T00:00:00")
        assert exc.status_code == 401
        assert exc.code == "TOKEN_EXPIRED"

    def test_token_not_found_error(self):
        """Test the token not found exception"""
        from src.exceptions.auth import TokenNotFoundError

        exc = TokenNotFoundError(token_preview="abc123...")
        assert exc.status_code == 404
        assert exc.code == "TOKEN_NOT_FOUND"

    def test_invalid_token_error(self):
        """Test the invalid token exception"""
        from src.exceptions.auth import InvalidTokenError

        exc = InvalidTokenError(reason="Malformed JWT")
        assert exc.status_code == 401
        assert exc.code == "INVALID_TOKEN"

    def test_token_revoked_error(self):
        """Test the token revoked exception"""
        from src.exceptions.auth import TokenRevokedError

        exc = TokenRevokedError()
        assert exc.status_code == 401
        assert exc.code == "TOKEN_REVOKED"

    def test_insufficient_scope_error(self):
        """Test the insufficient scope exception"""
        from src.exceptions.auth import InsufficientScopeError

        exc = InsufficientScopeError(required_scopes=["admin"], token_scopes=["read"])
        assert exc.status_code == 403
        assert exc.code == "INSUFFICIENT_SCOPE"

    def test_service_mismatch_error(self):
        """Test the service mismatch exception"""
        from src.exceptions.auth import ServiceMismatchError

        exc = ServiceMismatchError()
        assert exc.status_code == 403


class TestDatabaseExceptions:
    """Database exception tests"""

    def test_database_error(self):
        """Test the database error exception"""
        from src.exceptions.database import DatabaseError

        exc = DatabaseError("Connection failed")
        assert exc.status_code == 500

    def test_record_not_found_error(self):
        """Test the record not found exception"""
        from src.exceptions.database import RecordNotFoundError

        exc = RecordNotFoundError(model="user", identifier="123")
        assert exc.status_code == 404
        assert exc.code == "RECORD_NOT_FOUND"

    def test_duplicate_record_error(self):
        """Test the duplicate record exception"""
        from src.exceptions.database import DuplicateRecordError

        exc = DuplicateRecordError(field="username", value="admin")
        assert exc.status_code == 409
        assert exc.code == "DUPLICATE_RECORD"


class TestServiceExceptions:
    """Service exception tests"""

    def test_service_error(self):
        """Test the service error exception"""
        from src.exceptions.service import ServiceError

        exc = ServiceError()
        assert exc.status_code == 400
        assert exc.code == "SERVICE_ERROR"

    def test_service_not_found_error(self):
        """Test the service not found exception"""
        from src.exceptions.service import ServiceNotFoundError

        exc = ServiceNotFoundError(service_name="my-service")
        assert exc.status_code == 404
        assert exc.code == "SERVICE_NOT_FOUND"

    def test_service_already_exists_error(self):
        """Test the service already exists exception"""
        from src.exceptions.service import ServiceAlreadyExistsError

        exc = ServiceAlreadyExistsError(service_name="my-service")
        assert exc.status_code == 409


class TestBaseExceptions:
    """Base exception tests"""

    def test_token_server_error(self):
        """Test the base error exception"""
        from src.exceptions.base import MCPCenterError

        exc = MCPCenterError(message="Test error", code="TEST_ERROR")
        assert exc.message == "Test error"
        assert exc.code == "TEST_ERROR"
        assert exc.status_code == 500

    def test_token_server_http_exception(self):
        """Test the HTTP exception"""
        from src.exceptions.base import MCPCenterHTTPException

        exc = MCPCenterHTTPException(
            message="Custom error",
            status_code=400,
            code="CUSTOM_ERROR"
        )
        assert exc.message == "Custom error"
        assert exc.status_code == 400
        assert exc.code == "CUSTOM_ERROR"

    def test_exception_to_dict(self):
        """Test converting an exception to a dict"""
        from src.exceptions.base import MCPCenterError

        exc = MCPCenterError(
            message="Test error",
            code="TEST_CODE",
            details={"key": "value"}
        )

        result = exc.to_dict()
        assert result["error"] == "TEST_CODE"
        assert result["message"] == "Test error"
        assert result["details"]["key"] == "value"

    def test_exception_to_http_exception(self):
        """Test converting an exception to HTTPException"""
        from src.exceptions.base import MCPCenterHTTPException
        from fastapi import HTTPException

        exc = MCPCenterHTTPException(
            message="HTTP error",
            status_code=404
        )

        http_exc = exc.to_http_exception()
        assert isinstance(http_exc, HTTPException)
        assert http_exc.status_code == 404


class TestExceptionHandlerMiddleware:
    """Exception handler middleware tests (REQ-EXCEPTIONS-10)"""

    def test_custom_exception_converted_to_json_error_response(self):
        """A custom exception is converted by the handler into the correct JSON error response and status code"""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from src.exceptions.base import MCPCenterError
        from src.exceptions.handlers import register_exception_handlers

        class TeapotError(MCPCenterError):
            code = "IM_A_TEAPOT"
            message = "short and stout"
            status_code = 418

        # Build a minimal app, register the handlers, and add a route that raises a custom exception
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/boom")
        def boom():
            raise TeapotError(details={"pot": "tea"})

        client = TestClient(app)
        response = client.get("/boom")

        # Status code comes from the exception
        assert response.status_code == 418

        # Error body shape matches the to_dict() contract
        body = response.json()
        assert body["error"] == "IM_A_TEAPOT"
        assert body["message"] == "short and stout"
        assert body["details"]["pot"] == "tea"


class TestExceptionInAPI:
    """Exception handling tests within the API"""

    def test_invalid_session_returns_401(self, client):
        response = client.get("/api/session/me", headers={"Authorization": "Bearer invalid-token"})
        assert response.status_code == 401

    def test_missing_auth_returns_401(self, client):
        assert client.get("/api/services").status_code == 401

    def test_not_found_service_returns_404(self, owner_client):
        response = owner_client.get("/api/services/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404
        assert response.json()["detail"]["error"] == "service.not_found"
