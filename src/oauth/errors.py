"""OAuth errors (RFC 6749 section 5.2 error codes)."""


class OAuthError(Exception):
    """error:invalid_request / invalid_client / invalid_grant / unauthorized_client /
    unsupported_grant_type / invalid_scope / invalid_target / access_denied / server_error …
    redirectable=True means redirect_uri has been validated and the error can safely be redirected back to the client.
    """

    def __init__(self, error: str, description: str = "", status_code: int = 400, *, redirectable: bool = False):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status_code = status_code
        self.redirectable = redirectable

    def to_dict(self) -> dict:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body
